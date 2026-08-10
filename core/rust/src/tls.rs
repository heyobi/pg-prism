//! TLS termination support.

use native_tls::Identity;
use std::error::Error;
use tokio_native_tls::TlsAcceptor;

fn ensure_ssl_certificates() -> Result<(), Box<dyn Error + Send + Sync>> {
    use std::path::Path;
    use std::process::Command;

    let cert_path = "server.crt";
    let key_path = "server.key";
    let p12_path = "identity.p12";

    if !Path::new(p12_path).exists() {
        log::info!("SSL PKCS12 archive not found. Generating self-signed cert and p12...");

        // 1. Generate key and crt
        let status = Command::new("openssl")
            .args([
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-days",
                "365",
                "-nodes",
                "-x509",
                "-keyout",
                key_path,
                "-out",
                cert_path,
                "-subj",
                "/CN=localhost",
            ])
            .status()?;
        if !status.success() {
            return Err("Failed to generate private key and certificate using openssl".into());
        }

        // 2. Export to pkcs12 format
        let status = Command::new("openssl")
            .args([
                "pkcs12",
                "-export",
                "-out",
                p12_path,
                "-inkey",
                key_path,
                "-in",
                cert_path,
                "-passout",
                "pass:mypassword",
            ])
            .status()?;
        if !status.success() {
            return Err("Failed to export pkcs12 archive".into());
        }
        log::info!("SSL PKCS12 archive generated successfully.");
    }
    Ok(())
}

pub fn load_tls_acceptor() -> Result<TlsAcceptor, Box<dyn Error + Send + Sync>> {
    ensure_ssl_certificates()?;
    let p12_bytes = std::fs::read("identity.p12")?;
    let identity = Identity::from_pkcs12(&p12_bytes, "mypassword")?;
    let native_acceptor = native_tls::TlsAcceptor::builder(identity).build()?;
    Ok(TlsAcceptor::from(native_acceptor))
}
