use crate::noise::NoiseConfig;
use crate::transport::{boxed, tcp, BoundInfo, ConnectionOrigin, TransportExt};
use crypto::x25519::{PrivateKey, PublicKey};
use futures::io::{AsyncRead, AsyncWrite};
use parity_multiaddr::Multiaddr;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

pub const TCP_TRANSPORT: tcp::TcpTransport = tcp::TcpTransport {
    // Use default options.
    recv_buffer_size: None,
    send_buffer_size: None,
    ttl: None,
    keepalive: None,
    // Use TCP_NODELAY for libra tcp connections.
    nodelay: Some(true),
};

pub trait TSocket: AsyncRead + AsyncWrite + Send + Debug + Unpin + 'static + BoundInfo {}
impl<T> TSocket for T where T: AsyncRead + AsyncWrite + Send + Debug + Unpin + 'static + BoundInfo {}

/// Metadata associated with an established connection.
#[derive(Clone, Debug)]
pub struct ConnectionMetadata {
    c_addr: Multiaddr,
    s_addr: Multiaddr,
    origin: ConnectionOrigin,
}

unsafe impl Send for ConnectionMetadata {}
impl ConnectionMetadata {
    pub fn new(
        c_addr: Multiaddr,
        s_addr: Multiaddr,
        origin: ConnectionOrigin,
    ) -> ConnectionMetadata {
        ConnectionMetadata {
            c_addr,
            s_addr,
            origin,
        }
    }

    pub fn c_addr(&self) -> &Multiaddr {
        &self.c_addr
    }

    #[allow(dead_code)]
    pub fn s_addr(&self) -> &Multiaddr {
        &self.s_addr
    }

    #[allow(dead_code)]
    pub fn origin(&self) -> ConnectionOrigin {
        self.origin
    }
}

/// The `Connection` struct consists of connection metadata and the actual socket for
/// communication.
#[derive(Debug)]
pub struct Connection<TSocket> {
    pub socket: Option<TSocket>,
    pub metadata: ConnectionMetadata,
}

unsafe impl<T: TSocket> Send for Connection<T> {}
/// A timeout for the connection to open and complete all of the upgrade steps.
const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(30);

pub fn build_tcp_noise_transport(
    local_private_key: PrivateKey,
    peer_public_key: PublicKey,
) -> boxed::BoxedTransport<Connection<impl TSocket>, impl ::std::error::Error> {
    let noise_config = Arc::new(Box::new(NoiseConfig::new(
        local_private_key,
        peer_public_key,
    )));

    TCP_TRANSPORT
        .and_then(|socket, _addr, origin| async move {
            let (_remote_static_key, socket) =
                noise_config.upgrade_connection(socket, origin).await?;
            let (c_addr, s_addr) = match origin {
                ConnectionOrigin::Inbound => (socket.peer_addr(), socket.local_addr()),
                ConnectionOrigin::Outbound => (socket.local_addr(), socket.peer_addr()),
            };
            Ok(Connection {
                socket: Some(socket),
                metadata: ConnectionMetadata::new(c_addr, s_addr, origin),
            })
        })
        .with_timeout(TRANSPORT_TIMEOUT)
        .boxed()
}

pub fn build_tcp_transport(
) -> boxed::BoxedTransport<Connection<impl TSocket>, impl ::std::error::Error> {
    TCP_TRANSPORT
        .and_then(|socket, _addr, origin| async move {
            let (c_addr, s_addr) = match origin {
                ConnectionOrigin::Inbound => (socket.peer_addr(), socket.local_addr()),
                ConnectionOrigin::Outbound => (socket.local_addr(), socket.peer_addr()),
            };
            Ok(Connection {
                socket: Some(socket),
                metadata: ConnectionMetadata::new(c_addr, s_addr, origin),
            })
        })
        .with_timeout(TRANSPORT_TIMEOUT)
        .boxed()
}
