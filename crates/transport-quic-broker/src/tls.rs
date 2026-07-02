//! Broker TLS plumbing: QUIC transport/server config builders, PEM loaders, the
//! ALPN-pinned client endpoint, and the loopback-only insecure verifier.

use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls_platform_verifier::BuilderVerifierExt;

use crate::client::BrokerServerTrust;
use crate::config::{QuicBrokerConfig, QuicBrokerTlsConfig};
use crate::error::QuicBrokerError;
use crate::protocol::QUIC_BROKER_ALPN_V1;

pub(crate) fn broker_transport_config(
    config: &QuicBrokerConfig,
) -> Result<TransportConfig, QuicBrokerError> {
    let mut transport = TransportConfig::default();
    let streams = VarInt::try_from(config.max_streams_per_connection as u64)?;
    transport
        .max_concurrent_bidi_streams(streams)
        .max_concurrent_uni_streams(streams)
        .max_idle_timeout(Some(config.max_idle_timeout.try_into()?))
        .keep_alive_interval(Some(config.keep_alive_interval));
    Ok(transport)
}

pub(crate) fn configure_server(
    tls: &QuicBrokerTlsConfig,
) -> Result<(ServerConfig, Vec<u8>), QuicBrokerError> {
    match tls {
        QuicBrokerTlsConfig::GenerateSelfSigned { subject_alt_names } => {
            let subject_alt_names = if subject_alt_names.is_empty() {
                vec!["localhost".to_owned()]
            } else {
                subject_alt_names.clone()
            };
            let certified_key = rcgen::generate_simple_self_signed(subject_alt_names)
                .map_err(|err| QuicBrokerError::Certificate(err.to_string()))?;
            let cert_der = CertificateDer::from(certified_key.cert);
            let key_der = PrivatePkcs8KeyDer::from(certified_key.signing_key.serialize_der());
            let server_config = broker_server_config(vec![cert_der.clone()], key_der.into())?;
            Ok((server_config, cert_der.as_ref().to_vec()))
        }
        QuicBrokerTlsConfig::PemFiles {
            cert_path,
            key_path,
        } => {
            let certs = load_certificate_chain(cert_path)?;
            let leaf_cert_der = certs
                .first()
                .ok_or(QuicBrokerError::EmptyCertificateChain)?
                .as_ref()
                .to_vec();
            let key = load_private_key(key_path)?;
            let server_config = broker_server_config(certs, key)?;
            Ok((server_config, leaf_cert_der))
        }
    }
}

/// Build the broker QUIC server config with the spec-mandated ALPN
/// `marmot.quic_broker.v1` so broker connections negotiate the broker control
/// protocol during the TLS handshake.
fn broker_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, QuicBrokerError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| QuicBrokerError::Certificate(err.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| QuicBrokerError::Certificate(err.to_string()))?;
    crypto.alpn_protocols = vec![QUIC_BROKER_ALPN_V1.to_vec()];
    crypto.max_early_data_size = u32::MAX;
    Ok(ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto)
            .map_err(|err| QuicBrokerError::Certificate(err.to_string()))?,
    )))
}

fn load_certificate_chain(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>, QuicBrokerError> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(QuicBrokerError::Io)?;
    if certs.is_empty() {
        return Err(QuicBrokerError::EmptyCertificateChain);
    }
    Ok(certs)
}

fn load_private_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>, QuicBrokerError> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)
        .map_err(QuicBrokerError::Io)?
        .ok_or(QuicBrokerError::MissingPrivateKey)
}

pub(crate) fn client_endpoint(
    trust: BrokerServerTrust,
    broker_addr: SocketAddr,
) -> Result<Endpoint, QuicBrokerError> {
    // Every broker-path client config negotiates the spec-mandated ALPN
    // `marmot.quic_broker.v1`, so the rustls config is built here instead of
    // through the quinn convenience constructors (which set no ALPN).
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| QuicBrokerError::ClientConfig(err.to_string()))?;
    let mut crypto = match trust {
        BrokerServerTrust::Platform => builder
            .with_platform_verifier()
            .map_err(|err| QuicBrokerError::ClientConfig(err.to_string()))?
            .with_no_client_auth(),
        BrokerServerTrust::CertificateDer(cert_der) => {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(CertificateDer::from(cert_der))?;
            builder
                .with_root_certificates(Arc::new(roots))
                .with_no_client_auth()
        }
        BrokerServerTrust::InsecureLocal => {
            if !broker_addr.ip().is_loopback() {
                return Err(QuicBrokerError::InsecureLocalRequiresLoopback(broker_addr));
            }
            builder
                .dangerous()
                .with_custom_certificate_verifier(SkipServerVerification::new(provider))
                .with_no_client_auth()
        }
    };
    crypto.alpn_protocols = vec![QUIC_BROKER_ALPN_V1.to_vec()];
    crypto.enable_early_data = true;
    let client_config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| QuicBrokerError::ClientConfig(err.to_string()))?,
    ));
    let mut endpoint = Endpoint::client(client_bind_addr_for_broker(broker_addr))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

pub(crate) fn client_bind_addr_for_broker(broker_addr: SocketAddr) -> SocketAddr {
    match broker_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

#[derive(Debug)]
pub(crate) struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    pub(crate) fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
