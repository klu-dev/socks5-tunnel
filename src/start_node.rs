use crate::build_transport::{build_tcp_noise_transport, build_tcp_transport, Connection, TSocket};
use crate::server::{server_stream_handler, transfer};
use crate::transport::{tcp::multiaddr_to_socketaddr, Transport};
use ::log::{info, log, warn};
use crypto::x25519::{PrivateKey, PublicKey};
use futures::{future, AsyncReadExt};
use parity_multiaddr::Multiaddr;
use std::sync::Arc;
use tokio::io;

#[derive(Debug, Clone)]
struct StartNode {
    peer_addr: Multiaddr,
    local_private_key: PrivateKey,
    peer_public_key: PublicKey,
}

impl StartNode {
    fn new(
        peer_addr: Multiaddr,
        local_private_key: PrivateKey,
        peer_public_key: PublicKey,
    ) -> StartNode {
        StartNode {
            peer_addr,
            local_private_key,
            peer_public_key,
        }
    }

    async fn serve(
        &self,
        conn: impl TSocket,
    ) -> Result<(u64, u64, Box<String>), Box<dyn std::error::Error>> {
        let noise_transport =
            build_tcp_noise_transport(self.local_private_key.clone(), self.peer_public_key);

        let mut c2 = noise_transport.dial(self.peer_addr.clone())?.await?;

        let c1_addr = (conn.local_addr(), conn.peer_addr());
        let c2_addr = (c2.metadata.c_addr().clone(), c2.metadata.s_addr().clone());
        let dest_addr = Box::new(multiaddr_to_socketaddr(&c2_addr.1).unwrap().to_string());
        let (c1_read, c1_write) = conn.split();
        let (c2_read, c2_write) = c2.socket.take().unwrap().split();

        let half1 = transfer(c1_read, c1_addr.clone(), c2_write, c2_addr.clone());
        let half2 = transfer(c2_read, c2_addr, c1_write, c1_addr);
        let (res1, res2) = future::try_join(half1, half2).await?;
        Ok((res1, res2, dest_addr))
    }
}

fn concate_conn<S>(mut con: Connection<S>, node: Arc<StartNode>) -> ()
where
    S: TSocket,
{
    tokio::spawn(async move {
        match node
            .serve(con.socket.take().unwrap())
            .await
            .map_err(|e| Box::new(e))
        {
            Ok((a, b, addr)) => info!(
                "proxied {} -----> {}: {}/{} bytes",
                multiaddr_to_socketaddr(con.metadata.c_addr()).unwrap(),
                addr,
                a,
                b,
            ),
            Err(e) => warn!("Error for {}: {}", con.metadata.c_addr(), e),
        }
        io::Result::Ok(())
    });
}

pub async fn start_client_mode(
    listen_addr: Multiaddr,
    peer_addr: Multiaddr,
    local_private_key: PrivateKey,
    peer_public_key: PublicKey,
) -> Result<(), Box<dyn ::std::error::Error + Send + Sync + 'static>> {
    let start_node = Arc::new(StartNode::new(
        peer_addr,
        local_private_key,
        peer_public_key,
    ));
    let transport = build_tcp_transport();
    let (listener, _server_addr) = transport.listen_on(listen_addr)?;
    server_stream_handler(listener, concate_conn, start_node).await?;
    Ok(())
}
