use crate::build_transport::Connection;
use crate::transport::{tcp::multiaddr_to_socketaddr, BoundInfo};
use ::log::{debug, warn};
use futures::{
    future::Future,
    io::{ReadHalf, WriteHalf},
    stream::{Stream, StreamExt},
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};
use parity_multiaddr::Multiaddr;

/// Server side handler for send throughput benchmark when the messages are sent
/// over a simple stream (tcp or in-memory).
pub async fn server_stream_handler<L, I, S, E, N>(
    mut server_listener: L,
    f: fn(Connection<S>, N) -> (),
    node: N,
) -> Result<(), E>
where
    L: Stream<Item = Result<(I, Multiaddr), E>> + Unpin,
    I: Future<Output = Result<Connection<S>, E>>,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static + BoundInfo,
    E: ::std::error::Error,
    N: Clone,
{
    // Wait for next inbound connection
    loop {
        let (f_stream, client_addr) = match server_listener.next().await {
            None => continue,
            Some(res) => res?,
        };
        let con = match f_stream.await {
            Err(e) => {
                warn!("Error for {}: {}", client_addr, e);
                continue;
            }
            Ok(con) => con,
        };
        f(con, node.clone());
    }
}

/// A transfer representing reading all data from one side of a proxy connection
/// and writing it to another. Use async transfer instead of Transfer Future to
/// avoid complicated polling process.
///
pub async fn transfer(
    mut reader: ReadHalf<impl AsyncRead>,
    reader_addr: (Multiaddr, Multiaddr),
    mut writer: WriteHalf<impl AsyncWrite>,
    writer_addr: (Multiaddr, Multiaddr),
) -> std::io::Result<u64> {
    let mut buf = vec![0u8; 8 * 1024];
    let mut amt = 0_u64;
    loop {
        let read_size = match reader.read(&mut buf).await {
            Ok(n) => {
                if n == 0 {
                    if let Err(e) = writer.close().await {
                        debug!(
                            "Close {} error: {}",
                            multiaddr_to_socketaddr(&writer_addr.1)?,
                            e
                        );
                    }
                    return Ok(amt);
                } else {
                    n
                }
            }
            Err(e) => {
                debug!(
                    "Read from {} error: {}",
                    multiaddr_to_socketaddr(&reader_addr.1)?,
                    e
                );
                if let Err(e) = writer.close().await {
                    debug!(
                        "Close {} error: {}",
                        multiaddr_to_socketaddr(&writer_addr.1)?,
                        e
                    );
                }
                return Ok(amt);
            }
        };

        const MAX_LEN: usize = 1024 * 1024 * 2;

        if read_size >= buf.len() && buf.len() <= MAX_LEN {
            buf.resize_with(buf.len() * 2, Default::default);
            debug!(
                "Expand the read buffer size to {} for {}",
                buf.len(),
                multiaddr_to_socketaddr(&reader_addr.1)?
            );
        }
        if let Err(e) = writer.write_all(&buf[..read_size]).await {
            debug!(
                "Write to {} error: {}",
                multiaddr_to_socketaddr(&writer_addr.1)?,
                e
            );
            if let Err(e) = writer.close().await {
                debug!(
                    "Close {} error: {}",
                    multiaddr_to_socketaddr(&writer_addr.1)?,
                    e
                );
            }
            return Ok(amt);
        }

        if read_size < buf.len() {
            writer.flush().await?;
        }

        amt += read_size as u64;
    }
}
