mod config;
mod parser;
mod token;

use std::{
    mem::MaybeUninit,
    net::{SocketAddr, TcpListener},
    os::fd::AsRawFd,
    path::PathBuf,
    pin::Pin,
};

use anyhow::Context;
use clap::Parser;
use io_uring::{
    IoUring, opcode,
    types::{self, Fd},
};
use tracing::instrument;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{config::Config, token::Token};

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
        let mut pending_socket = Box::pin(SocketUninit {
            addr: MaybeUninit::uninit(),
            sock_addr_len: std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        });
        let accept = opcode::Accept::new(
            Fd(listener.as_raw_fd()),
            pending_socket.addr.as_mut_ptr() as *mut _,
            &mut pending_socket.sock_addr_len,
        );

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

impl RtInner {
    /// Called when a new connection has been accepted.
    ///
    /// This method reads the address information from the pending socket, sets up the new
    /// connection, and then resets the accept operation for the next incoming connection.
    #[instrument(skip(self))]
    fn on_accept(&mut self, socket_id: u32, result: i32) -> anyhow::Result<()> {
        tracing::debug!("accepted connection on socket id {}", socket_id);

        // Errors in io uring are indicated by negative result codes.
        if result < 0 {
            let code = -result;
            let io_error = std::io::Error::from_raw_os_error(code);
            anyhow::bail!("accept operation failed: {}", io_error);
        }

        // Check that the number of bytes written matches the expected size of a libc::sockaddr_in.
        let written_bytes = self.pending_socket.sock_addr_len as usize;
        if written_bytes as usize != std::mem::size_of::<libc::sockaddr_in>() {
            anyhow::bail!(
                "accept operation returned unexpected address size: {} (expected {})",
                written_bytes,
                std::mem::size_of::<libc::sockaddr_in>()
            );
        }

        // SAFETY: The address storage is valid and was initialized by the accept operation.
        let data = unsafe { self.pending_socket.addr.assume_init_read() };

        if data.sin_family as i32 != libc::AF_INET {
            anyhow::bail!(
                "accepted connection with unsupported address family: {} (expected AF_INET {})",
                data.sin_family,
                libc::AF_INET
            );
        }

        let socket_fd = Fd(result);
        let port = data.sin_port.to_be();
        let ip = std::net::Ipv4Addr::from(u32::from_be(data.sin_addr.s_addr));
        let addr = SocketAddr::V4(std::net::SocketAddrV4::new(ip, port));

        tracing::info!("new connection from {}", addr);

        // Add to the list of connected sockets.
        let socket = Socket {
            fd: types::Fd(socket_fd.0),
            addr,
        };
        self.sockets.push(socket);

        // Reset the pending socket for the next accept operation.
        *self.pending_socket = SocketUninit::new();

        Ok(())
    }
}

/// A connected socket.
struct Socket {
    fd: types::Fd,
    addr: SocketAddr,
}

/// A socket that is pending an accept operation.
///
/// It is important to keep the address storage alive and in the same memory location until the
/// accept operation completes.
struct SocketUninit {
    addr: MaybeUninit<libc::sockaddr_in>,
    sock_addr_len: libc::socklen_t,
}

impl SocketUninit {
    /// Creates a new uninitialized socket storage.
    fn new() -> Self {
        Self {
            addr: MaybeUninit::uninit(),
            sock_addr_len: std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        }
    }

    /// Creates an accept opcode for this socket.
    fn sqe(&self, fd: Fd) -> opcode::Accept {
        opcode::Accept::new(
            fd,
            self.addr.as_ptr() as *mut _,
            &self.sock_addr_len as *const _ as *mut _,
        )
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
