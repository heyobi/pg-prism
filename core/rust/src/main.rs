use std::env;
use std::error::Error;
use std::sync::Arc;
use tokio::net::TcpListener;

use pg_prism_rust::guardian::Guardian;
use pg_prism_rust::proxy::handle_client;
use pg_prism_rust::tls::load_tls_acceptor;
use pg_prism_rust::trust::TrustedProxies;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Who may send us a PROXY header. Refuse to start on a malformed list
    // rather than falling back to a default that trusts more than the operator
    // asked for.
    let trusted = Arc::new(TrustedProxies::from_env().map_err(|e| {
        log::error!("{}", e);
        e
    })?);
    log::info!("Accepting PROXY headers only from: {}", trusted.spec());

    // Initialize Guardian
    let guardian = Arc::new(Guardian::new("guardian.yaml").unwrap_or_else(|| {
        log::warn!("Guardian failed to load, proceeding with empty rules (Allow All)");
        Guardian { rules: vec![] }
    }));

    let ssl_enabled = env::var("SSL_ENABLED").unwrap_or_else(|_| "true".to_string()).to_lowercase() == "true";
    let tls_acceptor = if ssl_enabled {
        match load_tls_acceptor() {
            Ok(acc) => {
                log::info!("SSL/TLS termination support is active.");
                Some(Arc::new(acc))
            }
            Err(e) => {
                log::error!("Failed to initialize SSL. Disabling SSL support: {}", e);
                None
            }
        }
    } else {
        log::info!("SSL termination is disabled.");
        None
    };

    let listen_host = env::var("LISTEN_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let listen_port = env::var("LISTEN_PORT").unwrap_or_else(|_| "5433".to_string());
    let addr = format!("{}:{}", listen_host, listen_port);

    let listener = TcpListener::bind(&addr).await?;
    log::info!("PG-Prism running on {}", addr);

    let pg_host = env::var("PG_HOST").unwrap_or_else(|_| "localhost".to_string());
    let pg_port = env::var("PG_PORT").unwrap_or_else(|_| "5432".to_string());
    let pg_addr = format!("{}:{}", pg_host, pg_port);
    log::info!("Redirecting traffic to {}", pg_addr);

    loop {
        let (client_socket, _) = listener.accept().await?;
        if let Err(e) = client_socket.set_nodelay(true) {
            log::warn!("Failed to set TCP_NODELAY on client socket: {}", e);
        }
        let pg_addr = pg_addr.clone();
        let guardian = guardian.clone();
        let tls_acceptor = tls_acceptor.clone();
        let trusted = trusted.clone();

        tokio::spawn(async move {
            if let Err(e) =
                handle_client(client_socket, pg_addr, guardian, tls_acceptor, trusted).await
            {
                log::error!("Connection dropped: {}", e);
            }
        });
    }
}
