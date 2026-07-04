//! TLS 1.3 setup for both peers: the self-signed server config, the ALPN-pinned
//! client endpoint per trust mode, and the loopback-only insecure verifier.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls_platform_verifier::BuilderVerifierExt;

use crate::error::QuicTextStreamError;
use crate::hardening::QuicPreviewTransportProfile;
use crate::protocol::{LOCAL_BIND, QUIC_STREAM_ALPN_V1};
use crate::receive::ServerTrust;

pub(crate) fn configure_server() -> Result<(ServerConfig, Vec<u8>), QuicTextStreamError> {
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .map_err(|err| QuicTextStreamError::Certificate(err.to_string()))?;
    let cert_der = CertificateDer::from(certified_key.cert);
    let key_der = PrivatePkcs8KeyDer::from(certified_key.signing_key.serialize_der());
    let crypto = direct_rustls_server_config(cert_der.clone(), key_der)?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto)
            .map_err(|err| QuicTextStreamError::Certificate(err.to_string()))?,
    ));
    server_config.transport_config(Arc::new(direct_transport_config()?));
    Ok((server_config, cert_der.as_ref().to_vec()))
}

/// Build the direct-path rustls server config with the spec-mandated ALPN
/// `marmot.quic_stream.v1` (per spec/transports/quic.md), built directly
/// rather than via the quinn convenience constructor (which sets no ALPN).
///
/// TLS 0-RTT stays disabled (`max_early_data_size` keeps its default of 0),
/// per the shared preview hardening profile in [`crate::hardening`].
pub(crate) fn direct_rustls_server_config(
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
) -> Result<rustls::ServerConfig, QuicTextStreamError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| QuicTextStreamError::Certificate(err.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .map_err(|err| QuicTextStreamError::Certificate(err.to_string()))?;
    crypto.alpn_protocols = vec![QUIC_STREAM_ALPN_V1.to_vec()];
    Ok(crypto)
}

pub(crate) fn direct_transport_config() -> Result<TransportConfig, QuicTextStreamError> {
    Ok(QuicPreviewTransportProfile::direct_server().transport_config()?)
}

/// Build the direct-path rustls client config for a trust mode with the
/// spec-mandated ALPN `marmot.quic_stream.v1`, built directly rather than via
/// the quinn convenience constructors (which set no ALPN).
///
/// TLS 0-RTT stays disabled (`enable_early_data` keeps its default of false),
/// per the shared preview hardening profile in [`crate::hardening`].
pub(crate) fn direct_rustls_client_config(
    trust: ServerTrust,
    server_addr: SocketAddr,
) -> Result<rustls::ClientConfig, QuicTextStreamError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| QuicTextStreamError::ClientConfig(err.to_string()))?;
    let mut crypto = match trust {
        ServerTrust::Platform => builder
            .with_platform_verifier()
            .map_err(|err| QuicTextStreamError::ClientConfig(err.to_string()))?
            .with_no_client_auth(),
        ServerTrust::CertificateDer(cert_der) => {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(CertificateDer::from(cert_der))?;
            builder
                .with_root_certificates(Arc::new(roots))
                .with_no_client_auth()
        }
        ServerTrust::InsecureLocal => {
            if !server_addr.ip().is_loopback() {
                return Err(QuicTextStreamError::InsecureLocalRequiresLoopback(
                    server_addr,
                ));
            }
            builder
                .dangerous()
                .with_custom_certificate_verifier(SkipServerVerification::new(provider))
                .with_no_client_auth()
        }
    };
    crypto.alpn_protocols = vec![QUIC_STREAM_ALPN_V1.to_vec()];
    Ok(crypto)
}

pub(crate) fn client_endpoint(
    trust: ServerTrust,
    server_addr: SocketAddr,
) -> Result<Endpoint, QuicTextStreamError> {
    let crypto = direct_rustls_client_config(trust, server_addr)?;
    let mut client_config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| QuicTextStreamError::ClientConfig(err.to_string()))?,
    ));
    client_config.transport_config(Arc::new(
        QuicPreviewTransportProfile::client().transport_config()?,
    ));
    let mut endpoint = Endpoint::client(LOCAL_BIND)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
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
