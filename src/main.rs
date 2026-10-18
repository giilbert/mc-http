mod config;
mod parser;

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::Context;
use clap::Parser;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::instrument;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    config::Config,
    parser::{ParseResult, UnifiedHandshakeFormat},
};

/// Upper bound on how many bytes are read while waiting for a full handshake.
const MAX_HANDSHAKE_SIZE: usize = 2048;
/// How long to wait for a client to send its handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Reads from `connection` into `buf` until a handshake can be parsed (or ruled out).
///
/// Returns `None` if the data is not a recognizable handshake.
async fn read_handshake(
    connection: &mut TcpStream,
    buf: &mut Vec<u8>,
) -> anyhow::Result<Option<UnifiedHandshakeFormat>> {
    loop {
        let n_bytes = connection
            .read_buf(buf)
            .await
            .context("failed to read handshake")?;

        match UnifiedHandshakeFormat::from_bytes(buf) {
            ParseResult::Handshake(handshake) => return Ok(Some(handshake)),
            ParseResult::Unrecognized => return Ok(None),
            ParseResult::Incomplete if n_bytes == 0 => {
                anyhow::bail!("client closed connection before sending a full handshake")
            }
            ParseResult::Incomplete if buf.len() >= MAX_HANDSHAKE_SIZE => return Ok(None),
            ParseResult::Incomplete => {}
        }
    }
}

#[instrument(skip(config, client_connection))]
async fn handle_connection(
    config: Config,
    address: SocketAddr,
    mut client_connection: TcpStream,
) -> anyhow::Result<()> {
    // bytes read from the client while parsing the handshake, which are replayed to the server
    let mut buf = Vec::with_capacity(512);

    let handshake = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        read_handshake(&mut client_connection, &mut buf),
    )
    .await
    {
        Ok(handshake) => handshake?,
        Err(_) => {
            tracing::debug!("timed out waiting for handshake");
            None
        }
    };

    tracing::debug!("parsed handshake: {:?}", handshake);

    let target_server = match handshake {
        Some(handshake) => {
            // '\0FORGE' is sometimes appended to the hostname by Forge, which breaks our server
            // mapping. We strip it out here to ensure that the hostname is matched correctly.
            let handshake_before_null = handshake
                .hostname
                .split('\0')
                .next()
                .unwrap_or(&handshake.hostname)
                .to_string();

            config
                .data()
                .servers
                .get(&handshake_before_null)
                .cloned()
                .unwrap_or_else(|| config.data().default.clone())
        }
        None => config.data().default.clone(),
    };

    tracing::info!("forwarding {address:?} to server {target_server}");

    let mut server_connection = TcpStream::connect(&*target_server)
        .await
        .context("failed to connect to target server")?;

    server_connection
        .set_nodelay(true)
        .context("failed to set nodelay")?;
    client_connection
        .set_nodelay(true)
        .context("failed to set nodelay")?;

    server_connection
        .write_all(&buf)
        .await
        .context("failed to forward handshake to target server")?;

    let io_sl2sr = tokio_splice2::context::SpliceIoCtx::prepare()?.into_io();
    let io_sr2sl = tokio_splice2::context::SpliceIoCtx::prepare()?.into_io();

    let traffic = tokio_splice2::SpliceBidiIo { io_sl2sr, io_sr2sl }
        .execute(&mut server_connection, &mut client_connection)
        .await;

    tracing::info!("connection from {address:?} to server {target_server} closed: {traffic:?}");

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
