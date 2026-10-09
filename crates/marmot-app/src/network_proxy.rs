//! Explicit process-wide SOCKS5 routing. HTTP keeps its validated DNS pins;
//! relay hostnames are resolved by the proxy through the SDK's SOCKS5 transport.

use std::net::SocketAddr;

use nostr_sdk::prelude::ClientBuilder;

#[path = "../../network_proxy.rs"]
mod process_proxy;

pub(crate) fn socks5_proxy() -> Result<Option<SocketAddr>, &'static str> {
    process_proxy::socks5_proxy().map(|config| config.map(|config| config.addr))
}

pub(crate) fn config_error(detail: &'static str) -> crate::AppError {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, detail).into()
}

pub(crate) fn nostr_builder() -> ClientBuilder {
    process_proxy::nostr_builder(process_proxy::socks5_proxy())
}

pub(crate) fn http_builder(
    builder: reqwest::ClientBuilder,
) -> Result<reqwest::ClientBuilder, &'static str> {
    // Remove explicit and environment proxies first: NO_PROXY must not bypass
    // the chosen proxy, and ALL_PROXY must not replace it.
    let builder = builder.no_proxy();
    match process_proxy::socks5_proxy()? {
        Some(config) => {
            // socks5h would ignore resolve_to_addrs and allow proxy-side DNS
            // rebinding into private services. socks5 sends the vetted IP while
            // reqwest retains the original URL for TLS/SNI and the Host header.
            let mut proxy = reqwest::Proxy::all(format!("socks5://{}", config.addr))
                .map_err(|_| process_proxy::CONFIG_ERROR)?;
            if let Some(credentials) = config.credentials {
                proxy = proxy.basic_auth(&credentials.username, &credentials.password);
            }
            Ok(builder.proxy(proxy))
        }
        None => Ok(builder),
    }
}

pub(crate) fn require_direct_transport() -> Result<(), crate::AppError> {
    if socks5_proxy().map_err(config_error)?.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "QUIC agent previews are unavailable while WN_SOCKS5_PROXY is enabled; SOCKS5 TCP routing cannot carry QUIC",
        )
        .into());
    }
    Ok(())
}
