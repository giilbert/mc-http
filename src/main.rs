mod config;
mod parser;

use std::{net::SocketAddr, path::PathBuf};

use anyhow::Context;
use clap::Parser;
use tokio::net::TcpStream;
use tracing::instrument;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{config::Config, parser::UnifiedHandshakeFormat};

#[instrument(skip(config, connection))]
async fn handle_connection(
    config: Config,
    address: SocketAddr,
    connection: TcpStream,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 512];

    let (mut rx, tx) = connection.into_split();
    let n_bytes = rx.peek(&mut buf).await.context("failed to peek")?;

    let handshake =
        UnifiedHandshakeFormat::from_bytes(&buf[..n_bytes]).context("failed to parse handshake")?;

    tracing::debug!("parsed handshake: {:?}", handshake);

    let target_server = match handshake {
        Some(handshake) => config
            .data()
            .servers
            .get(&handshake.hostname)
            .cloned()
            .unwrap_or_else(|| config.data().default.clone()),
        None => config.data().default.clone(),
    };

    tracing::info!("forwarding {address:?} to server {target_server}");

    let mut server_connection = TcpStream::connect(&*target_server)
        .await
        .context("failed to connect to target server")?;
    let mut client_connection = rx.reunite(tx).context("failed to reunite connection")?;

    /// A 128 KiB buffer size for each direction.
    const BUF_SIZE: usize = 128 * 1024;
    tokio::io::copy_bidirectional_with_sizes(
        &mut client_connection,
        &mut server_connection,
        BUF_SIZE,
        BUF_SIZE,
    )
    .await
    .context("failed to proxy data")?;

    Ok(())
}

#[derive(clap::Parser)]
pub struct Cli {
    /// Path to the configuration file.
    ///
    /// If not provided, defaults to "/etc/mc_http.toml".
    #[arg(short, long)]
    pub config: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    const DEFAULT_LOG_SETTINGS: &str = "mc_http=debug";
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .parse(std::env::var("RUST_LOG").unwrap_or(DEFAULT_LOG_SETTINGS.to_string()))?,
        )
        .init();

    let cli = Cli::parse();

    let config = Config::load(
        cli.config
            .as_ref()
            .unwrap_or(&PathBuf::from("/etc/mc_http.toml")),
    )
    .context("failed to load configuration")?;

    tracing::info!("starting mc http proxy!");
    tracing::info!("config:");
    tracing::info!("  port: {}", config.data().port);
    tracing::info!("  default server: {}", config.data().default);
    tracing::info!("  mapped servers:");
    for (hostname, server) in &config.data().servers {
        tracing::info!("    {} -> {}", hostname, server);
    }

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.data().port))
        .await
        .context(format!("failed to bind to port {}", config.data().port))?;

    while let Some((connection, address)) = listener.accept().await.ok() {
        tracing::info!("accepted connection from {}", address);

        let config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(config, address, connection).await {
                tracing::error!("error handling connection from {}: {:?}", address, e);
            }
        });
    }

    anyhow::bail!("listener has exited unexpectedly");
}
