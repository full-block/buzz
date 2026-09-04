//! rustls client connector that trusts Mozilla roots plus extra local CAs.
//!
//! Extra PEMs (missing files are skipped):
//! - `SSL_CERT_FILE` if set
//! - `/Users/farmer/.mpzl/certs/caddy-local-authority.pem`
//! - `$HOME/.mpzl/certs/caddy-local-authority.pem`
//! - platform/keychain certs via rustls-native-certs

use tokio_tungstenite::{
    connect_async, connect_async_tls_with_config,
    tungstenite::{handshake::client::Response, Error as WsError},
    Connector, MaybeTlsStream, WebSocketStream,
};

pub(crate) async fn connect_async_with_extra_cas(
    url: &str,
) -> Result<(WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>, Response), WsError> {
    if let Some(rest) = url.strip_prefix("wss://") {
        let _ = rest;
        let connector = rustls_connector_with_extra_cas();
        connect_async_tls_with_config(url, None, false, Some(connector)).await
    } else {
        connect_async(url).await
    }
}

fn rustls_connector_with_extra_cas() -> Connector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut extra = Vec::new();
    if let Ok(path) = std::env::var("SSL_CERT_FILE") {
        extra.push(std::path::PathBuf::from(path));
    }
    extra.push(std::path::PathBuf::from(
        "/Users/farmer/.mpzl/certs/caddy-local-authority.pem",
    ));
    if let Some(home) = std::env::var_os("HOME") {
        extra.push(std::path::PathBuf::from(home).join(".mpzl/certs/caddy-local-authority.pem"));
    }
    extra.sort();
    extra.dedup();

    for path in extra {
        add_pem_file_to_roots(&mut roots, &path);
    }

    let native = rustls_native_certs::load_native_certs();
    for err in &native.errors {
        tracing::debug!("native cert load: {err}");
    }
    for cert in native.certs {
        let _ = roots.add(cert);
    }

    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .expect("rustls default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();

    Connector::Rustls(std::sync::Arc::new(config))
}

fn add_pem_file_to_roots(roots: &mut rustls::RootCertStore, path: &std::path::Path) {
    if !path.is_file() {
        return;
    }
    let Ok(file) = std::fs::File::open(path) else {
        return;
    };
    let mut reader = std::io::BufReader::new(file);
    let mut added = 0usize;
    for cert in rustls_pemfile::certs(&mut reader) {
        if let Ok(cert) = cert {
            if roots.add(cert).is_ok() {
                added += 1;
            }
        }
    }
    if added > 0 {
        tracing::info!("loaded {added} extra CA cert(s) from {}", path.display());
    }
}
