//! One-shot wss probe using the same extra-CA rustls pattern as rustls_extra_ca.rs
use std::process::ExitCode;

fn rustls_connector_with_extra_cas() -> tokio_tungstenite::Connector {
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
        if !path.is_file() {
            continue;
        }
        let Ok(file) = std::fs::File::open(&path) else {
            continue;
        };
        let mut reader = std::io::BufReader::new(file);
        for cert in rustls_pemfile::certs(&mut reader).flatten() {
            let _ = roots.add(cert);
        }
    }

    let native = rustls_native_certs::load_native_certs();
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

    tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(config))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "wss://buzz.mpzl".to_string());
    let result = if url.starts_with("wss://") {
        let connector = rustls_connector_with_extra_cas();
        tokio_tungstenite::connect_async_tls_with_config(url.as_str(), None, false, Some(connector))
            .await
    } else {
        tokio_tungstenite::connect_async(url.as_str()).await
    };
    match result {
        Ok((_ws, response)) => {
            println!("status={} headers={:?}", response.status(), response.headers());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error={err}");
            ExitCode::FAILURE
        }
    }
}
