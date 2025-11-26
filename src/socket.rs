use std::{
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddr},
};

use io_uring::{opcode, types::Fd};
use tracing::instrument;

use crate::RtInner;

impl RtInner {
    /// Called when a new connection has been accepted.
    ///
    /// This method reads the address information from the pending socket, sets up the new
    /// connection, and then resets the accept operation for the next incoming connection.
    #[instrument(skip(self))]
    pub(crate) fn on_accept(&mut self, socket_id: u32, result: i32) -> anyhow::Result<()> {
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
        let ip = Ipv4Addr::from(u32::from_be(data.sin_addr.s_addr));
        let addr = SocketAddr::V4(std::net::SocketAddrV4::new(ip, port));

        tracing::info!("new connection from {}", addr);

        // Add to the list of connected sockets.
        let socket = Socket {
            fd: Fd(socket_fd.0),
            addr,
            state: SocketState::ReadingHeader,
        };
        self.sockets.push(socket);

        // Reset the pending socket for the next accept operation.
        *self.pending_socket = SocketUninit::new();

        Ok(())
    }
}

/// The state of a connected socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    ReadingHeader,
    ConnectingToOrigin,
    Forwarding,
}

/// A connected socket.
#[derive(Debug)]
pub struct Socket {
    pub fd: Fd,
    pub addr: SocketAddr,
    pub state: SocketState,
}

/// A socket that is pending an accept operation.
///
/// It is important to keep the address storage alive and in the same memory location until the
/// accept operation completes.
#[derive(Debug)]
pub struct SocketUninit {
    pub addr: MaybeUninit<libc::sockaddr_in>,
    pub sock_addr_len: libc::socklen_t,
}

impl SocketUninit {
    /// Creates a new uninitialized socket storage.
    pub fn new() -> Self {
        Self {
            addr: MaybeUninit::uninit(),
            sock_addr_len: std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        }
    }

    /// Creates an accept opcode for this socket.
    pub fn sqe(&self, fd: Fd) -> opcode::Accept {
        opcode::Accept::new(
            fd,
            self.addr.as_ptr() as *mut _,
            &self.sock_addr_len as *const _ as *mut _,
        )
    }
}
