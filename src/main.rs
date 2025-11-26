mod config;
mod gen_vec;
mod parser;
mod socket;
mod token;
mod utils;

use std::{mem::MaybeUninit, net::TcpListener, os::fd::AsRawFd, path::PathBuf, pin::Pin};

use anyhow::Context;
use clap::Parser;
use io_uring::{IoUring, types::Fd};
use tracing::instrument;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    config::Config,
    socket::{Socket, SocketUninit},
    token::Token,
};

/// A simple runtime for executing futures interacting with io_uring.
struct Rt {
    ring: IoUring,
    inner: RtInner,
}

struct RtInner {
    config: Config,
    listener: TcpListener,

    pending_socket: Pin<Box<SocketUninit>>,
    sockets: Vec<Socket>,
}

impl Rt {
    fn new(config: Config) -> anyhow::Result<Self> {
        let mut ring = IoUring::new(256)?;

        let addr = format!("0.0.0.0:{}", config.data().port);
        let listener = TcpListener::bind(&addr).context(format!("failed to bind to {addr}"))?;

        // Add the initial accept operation to the ring.
        let pending_socket = Box::pin(SocketUninit {
            addr: MaybeUninit::uninit(),
            sock_addr_len: std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        });
        let accept = pending_socket.sqe(Fd(listener.as_raw_fd()));

        unsafe {
            // SAFETY: The listener's file descriptor is kept alive by Rt and the operation is
            // created with the correct arguments for address storage.
            ring.submission()
                .push(
                    &accept
                        .build()
                        .user_data(Token::Accept { socket_id: 0 }.into()),
                )
                .context("failed to add initial accept operation to io_uring")?;
        }

        Ok(Rt {
            ring,
            inner: RtInner {
                config,
                listener,
                pending_socket,
                sockets: vec![],
            },
        })
    }

    #[instrument(skip(self))]
    fn run_once(&mut self) -> anyhow::Result<()> {
        let Rt { ring, inner } = self;

        let mut did_socket_accept = false;

        ring.submit_and_wait(1)
            .context("failed to submit io_uring operations")?;

        for cqe in ring.completion() {
            let token = Token::from(cqe.user_data());
            tracing::debug!("io_uring operation token {:?} completed: {:?}", token, cqe);

            match token {
                Token::Accept { socket_id } => {
                    inner.on_accept(socket_id, cqe.result())?;
                    did_socket_accept = true;
                }
            }
        }

        if did_socket_accept {
            // Re-add the accept operation for the next incoming connection.
            let accept_sqe = inner.pending_socket.sqe(Fd(inner.listener.as_raw_fd()));
            tracing::debug!("re-adding accept operation for next connection");
            unsafe {
                // SAFETY: The listener's file descriptor is kept alive by Rt and the operation is
                // created with the correct arguments for address storage.
                ring.submission()
                    .push(
                        &accept_sqe
                            .build()
                            .user_data(Token::Accept { socket_id: 0 }.into()),
                    )
                    .context("failed to re-add accept operation to io_uring")?;
            }
        }

        Ok(())
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        loop {
            self.run_once()?;
        }
    }
}

#[derive(clap::Parser)]
pub struct Cli {
    /// Path to the configuration file.
    ///
    /// If not provided, defaults to "/etc/mc_http.toml".
    #[arg(short, long)]
    pub config: Option<std::path::PathBuf>,
}

fn main() -> anyhow::Result<()> {
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

    let mut rt = Rt::new(config)?;
    rt.run()
}
