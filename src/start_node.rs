use crate::build_transport::{
    build_tcp_noise_transport, build_tcp_transport, Connection, TSocket, TCP_TRANSPORT,
};
use crate::command::NetAddrIpv4List;
use crate::other;
use crate::server::{server_stream_handler, transfer};
use crate::socks::{http_hostname_to_ip, socks_name_port, v4, v5};
use crate::transport::tcp::socketaddr_to_multiaddr;
use crate::transport::BoundInfo;
use crate::transport::{tcp::multiaddr_to_socketaddr, Transport};
use ::log::{info, warn};
use crypto::x25519::{PrivateKey, PublicKey};
use futures::{future, AsyncReadExt, AsyncWriteExt, FutureExt, TryFutureExt};
use log::{debug, error, trace};
use parity_multiaddr::Multiaddr;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io;
use tokio::time::sleep;

#[derive(Debug, Clone, Copy)]
pub enum ProtoType {
    Socks,
    Http,
}

impl FromStr for ProtoType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "socks" => Ok(ProtoType::Socks),
            "http" => Ok(ProtoType::Http),
            _ => Err("Unknow mode. Option should be socks or http"),
        }
    }
}

#[derive(Debug)]
struct StartNode {
    proto: ProtoType,
    listen_addr: Multiaddr,
    peer_addr: Multiaddr,
    local_private_key: PrivateKey,
    peer_public_key: PublicKey,
    bypass_list: Option<NetAddrIpv4List>,
    peer_ready: AtomicBool,
}

impl StartNode {
    fn new(
        proto: ProtoType,
        listen_addr: Multiaddr,
        peer_addr: Multiaddr,
        local_private_key: PrivateKey,
        peer_public_key: PublicKey,
        bypass_list: Option<NetAddrIpv4List>,
    ) -> StartNode {
        StartNode {
            proto,
            listen_addr,
            peer_addr,
            local_private_key,
            peer_public_key,
            bypass_list,
            peer_ready: AtomicBool::new(false),
        }
    }

    fn is_bypass_addr(&self, addr: &Ipv4Addr) -> bool {
        if !self.peer_ready.load(Ordering::Relaxed) {
            return true;
        }

        if self.bypass_list.is_none() {
            return false;
        }

        if addr.is_private() || addr.is_loopback() || addr.is_broadcast() {
            return true;
        }
        let ip = u32::from(*addr);
        let mut mask = 0xffffff00_u32;
        let mut mask_bits = 24_u16;
        let mut net = ip & mask;
        while mask_bits >= 8_u16 {
            trace!(
                "addr: {} net: {} mask_bits: {} mask: {}",
                *addr,
                Ipv4Addr::from(net),
                mask_bits,
                Ipv4Addr::from(mask)
            );
            if let Some(val) = self.bypass_list.as_ref().unwrap().get(&net) {
                if mask_bits == *val {
                    return true;
                }
            }
            mask <<= 1;
            mask_bits -= 1;
            net = ip & mask;
        }
        false
    }

    async fn serve(&self, conn: impl TSocket) -> io::Result<(u64, u64, Box<String>)> {
        match self.proto {
            ProtoType::Socks => self.serve_socks(conn).await,
            ProtoType::Http => self.serve_http(conn).await,
        }
    }

    async fn serve_socks(&self, mut conn: impl TSocket) -> io::Result<(u64, u64, Box<String>)> {
        let mut buf = [0_u8; 1];

        conn.read_exact(&mut buf).await?;
        let res = match buf[0] {
            v5::VERSION => self.serve_v5(conn).await,
            v4::VERSION => self.serve_v4(conn),

            // If we hit an unknown version, we return a "terminal future"
            // which represents that this future has immediately failed. In
            // this case the type of the future is `io::Error`, so we use a
            // helper function, `other`, to create an error quickly.
            n => Err(other(&format!("unknown version {}", n))),
        };
        res
    }

    fn serve_v4(&self, mut _conn: impl TSocket) -> io::Result<(u64, u64, Box<String>)> {
        Err(other("Socks version 4 not implemented"))
    }

    async fn serve_v5(&self, mut conn: impl TSocket) -> io::Result<(u64, u64, Box<String>)> {
        // First part of the SOCKSv5 protocol is to negotiate a number of
        // "methods". These methods can typically be used for various kinds of
        // proxy authentication and such, but for this server we only implement
        // the `METH_NO_AUTH` method, indicating that we only implement
        // connections that work with no authentication.
        //
        // First here we do the same thing as reading the version byte, we read
        // a byte indicating how many methods. Afterwards we then read all the
        // methods into a temporary buffer.
        //
        // Note that we use `and_then` here to chain computations after one
        // another, but it also serves to simply have fallible computations,
        // such as checking whether the list of methods contains `METH_NO_AUTH`.
        let num_methods = async move {
            let mut buf = [0u8; 1];
            conn.read_exact(&mut buf).await?;
            io::Result::Ok((buf, conn))
        }
        .boxed();

        let authenticated = num_methods
            .and_then(|(buf, mut conn)| async move {
                let mut buf = vec![0u8; buf[0] as usize];
                let _ = conn.read_exact(&mut buf).await?;
                if buf.contains(&v5::METH_NO_AUTH) {
                    io::Result::Ok(conn)
                } else {
                    io::Result::Err(other("no supported method given"))
                }
            })
            .boxed();

        // After we've concluded that one of the client's supported methods is
        // `METH_NO_AUTH`, we "ack" this to the client by sending back that
        // information. Here we make use of the `write_all` combinator which
        // works very similarly to the `read_exact` combinator.
        let part1 = authenticated
            .and_then(|mut conn| async move {
                conn.write_all(&[v5::VERSION, v5::METH_NO_AUTH]).await?;
                conn.flush().await?;
                io::Result::Ok(conn)
            })
            .boxed();

        // Next up, we get a selected protocol version back from the client, as
        // well as a command indicating what they'd like to do. We just verify
        // that the version is still v5, and then we only implement the
        // "connect" command so we ensure the proxy sends that.
        //
        // As above, we're using `and_then` not only for chaining "blocking
        // computations", but also to perform fallible computations.
        let ack = part1
            .and_then(|mut conn| async move {
                let mut buf = [0u8; 1];
                let _ = conn.read_exact(&mut buf).await?;
                if buf[0] == v5::VERSION {
                    io::Result::Ok(conn)
                } else {
                    io::Result::Err(other("didn't confirm with v5 version"))
                }
            })
            .boxed();

        let command = ack
            .and_then(|mut conn| async move {
                let mut buf = [0u8; 1];
                let _ = conn.read_exact(&mut buf).await?;
                if buf[0] == v5::CMD_CONNECT {
                    io::Result::Ok(conn)
                } else {
                    io::Result::Err(other("unsupported command"))
                }
            })
            .boxed();

        // After we've negotiated a command, there's one byte which is reserved
        // for future use, so we read it and discard it. The next part of the
        // protocol is to read off the address that we're going to proxy to.
        // This address can come in a number of forms, so we read off a byte
        // which indicates the address type (ATYP).
        //
        // Depending on the address type, we then delegate to different futures
        // to implement that particular address format.
        let atyp = command
            .and_then(|mut conn| async move {
                let mut buf = [0u8; 1];
                // read pass reserved byte
                conn.read_exact(&mut buf).await?;
                conn.read_exact(&mut buf).await?;
                io::Result::Ok((buf, conn))
            })
            .boxed();

        let addr = atyp
            .and_then(|(buf, mut conn)| {
                async move {
                    match buf[0] {
                        // For IPv4 addresses, we read the 4 bytes for the address as
                        // well as 2 bytes for the port.
                        v5::ATYP_IPV4 => {
                            let mut buf = [0u8; 6];
                            conn.read_exact(&mut buf).await?;
                            let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                            let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                            let addr = SocketAddrV4::new(addr, port);
                            Ok((
                                SocketAddr::V4(addr),
                                conn,
                                Box::new(addr.to_string()),
                                v5::ATYP_IPV4,
                            ))
                        }

                        v5::ATYP_IPV6 => {
                            let mut buf = [0u8; 18];
                            conn.read_exact(&mut buf).await?;
                            let v6_a = ((buf[0] as u16) << 8) | (buf[1] as u16);
                            let v6_b = ((buf[2] as u16) << 8) | (buf[3] as u16);
                            let v6_c = ((buf[4] as u16) << 8) | (buf[5] as u16);
                            let v6_d = ((buf[6] as u16) << 8) | (buf[7] as u16);
                            let v6_e = ((buf[8] as u16) << 8) | (buf[9] as u16);
                            let v6_f = ((buf[10] as u16) << 8) | (buf[11] as u16);
                            let v6_g = ((buf[12] as u16) << 8) | (buf[13] as u16);
                            let v6_h = ((buf[14] as u16) << 8) | (buf[15] as u16);
                            let addr =
                                Ipv6Addr::new(v6_a, v6_b, v6_c, v6_d, v6_e, v6_f, v6_g, v6_h);
                            let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
                            let addr = SocketAddrV6::new(addr, port, 0, 0);
                            Ok((
                                SocketAddr::V6(addr),
                                conn,
                                Box::new(addr.to_string()),
                                v5::ATYP_IPV6,
                            ))
                        }
                        // The SOCKSv5 protocol not only supports proxying to specific
                        // IP addresses, but also arbitrary hostnames. This allows
                        // clients to perform hostname lookups within the context of the
                        // proxy server rather than the client itself.
                        //
                        // Since the first publication of this code, several
                        // futures-based DNS libraries appeared, and as a demonstration
                        // of integrating third-party asynchronous code into our chain,
                        // we will use one of them, TRust-DNS.
                        //
                        // The protocol here is to have the next byte indicate how many
                        // bytes the hostname contains, followed by the hostname and two
                        // bytes for the port. To read this data, we execute two
                        // respective `read_exact` operations to fill up a buffer for
                        // the hostname.
                        //
                        // Finally, to perform the "interesting" part, we process the
                        // buffer and pass the retrieved hostname to a query future if
                        // it wasn't already recognized as an IP address. The query is
                        // very basic: it asks for an IPv4 address with a timeout of
                        // five seconds. We're using TRust-DNS at the protocol level,
                        // so we don't have the functionality normally expected from a
                        // stub resolver, such as sorting of answers according to RFC
                        // 6724, more robust timeout handling, or resolving CNAME
                        // lookups.
                        v5::ATYP_DOMAIN => {
                            let mut buf = [0u8; 1];
                            conn.read_exact(&mut buf).await?;
                            let mut buf = vec![0u8; (buf[0] as usize) + 2];
                            conn.read_exact(&mut buf).await?;
                            let (socket_addr, addr) = socks_name_port(&buf).await?;
                            Ok((socket_addr, conn, addr, v5::ATYP_DOMAIN))
                        }

                        n => {
                            let msg = format!("unknown ATYP received: {}", n);
                            io::Result::Err(other(&msg))
                        }
                    }
                }
            })
            .boxed();

        // Now that we've got a socket address to connect to, let's actually
        // create a connection to that socket!
        //
        // To do this, we use our `handle` field, a handle to the event loop, to
        // issue a connection to the address we've figured out we're going to
        // connect to. Note that this `tcp_connect` method itself returns a
        // future resolving to a `TcpStream`, representing how long it takes to
        // initiate a TCP connection to the remote.
        //
        // We wait for the TCP connect to get fully resolved before progressing
        // to the next stage of the SOCKSv5 handshake, but we keep a hold of any
        // possible error in the connection phase to handle it in a moment.
        let connected = addr
            .and_then(|(socket_addr, conn, dest_addr, atyp)| async move {
                debug!("proxying to {}", socket_addr);
                let mut pass = false;
                if atyp != v5::ATYP_IPV6 {
                    if let SocketAddr::V4(addr_v4) = socket_addr {
                        pass = self.is_bypass_addr(addr_v4.ip());
                        trace!("address: {} bypass: {}", addr_v4, pass)
                    }
                }
                if !pass {
                    Ok((
                        conn,
                        None,
                        Some(self.build_tunnel(dest_addr.to_string(), atyp).await),
                        dest_addr,
                    ))
                } else {
                    Ok((
                        conn,
                        Some(
                            TCP_TRANSPORT
                                .dial(socketaddr_to_multiaddr(&socket_addr))?
                                .await,
                        ),
                        None,
                        dest_addr,
                    ))
                }
            })
            .boxed();

        let (conn, bypass_c2, tun_c2, dest_addr) = connected.await?;
        if bypass_c2.is_some() {
            self.run_bypass_proc(conn, bypass_c2.unwrap(), dest_addr)
                .await
        } else {
            self.run_tun_proc(conn, tun_c2.unwrap(), dest_addr).await
        }
    }

    async fn build_tunnel(
        &self,
        addres: String,
        atyp: u8,
    ) -> io::Result<(Connection<impl TSocket>, SocketAddr)> {
        let noise_transport =
            build_tcp_noise_transport(self.local_private_key.clone(), self.peer_public_key);
        let mut c2 = noise_transport
            .dial(self.peer_addr.clone())
            .map_err(|e| other(e.to_string().as_str()))?
            .await
            .map_err(|e| other(e.to_string().as_str()))?;

        // request method negotiation header
        // |VER | NMETHODS | METHODS  |
        // +----+----------+----------+
        // | 1  |    1     | 1 to 255 |
        let auth_request = async move {
            let mut buf = [0u8; 3];
            // version v5
            buf[0] = v5::VERSION;
            // num_auth_methods 1
            buf[1] = 1;
            // only one auth_method
            buf[2] = v5::METH_NO_AUTH;
            c2.socket.as_mut().unwrap().write_all(&buf).await?;
            c2.socket.as_mut().unwrap().flush().await?;
            trace!("build_tun: Send auth_request");
            Ok(c2)
        }
        .boxed();

        // reply the method selection
        // |VER | METHOD |
        // +----+--------+
        // | 1  |   1    |
        let auth_response = auth_request
            .and_then(|mut c2| async move {
                let mut buf = [0u8; 2];
                c2.socket.as_mut().unwrap().read_exact(&mut buf).await?;
                if buf[1] != v5::METH_NO_AUTH {
                    io::Result::Err(other("METH_NO_AUTH not supported"))
                } else {
                    trace!("build_tun: Receive auth_response");
                    Ok(c2)
                }
            })
            .boxed();

        // request command
        // +----+-----+-------+------+----------+----------+
        // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+
        let connect_request = auth_response
            .and_then(|mut c2| async move {
                trace!("build_tun: addr_port: {}", &addres);
                let addr_port = addres.split(':').collect::<Vec<_>>();

                let port = if addr_port.len() >= 2 {
                    addr_port[1]
                        .parse::<u16>()
                        .map_err(|_| other("parse port fail"))?
                } else {
                    80
                };
                let mut buf = [0u8; 4];
                // version v5
                buf[0] = v5::VERSION;
                // num_auth_methods 1
                buf[1] = v5::CMD_CONNECT;
                // only one auth_method
                buf[2] = 0x0;
                buf[3] = atyp;
                c2.socket.as_mut().unwrap().write_all(&buf).await?;
                // Send addr
                match atyp {
                    v5::ATYP_IPV4 => {
                        let ipv4 = addr_port[0]
                            .parse::<Ipv4Addr>()
                            .map_err(|_| other("parse address fail"))?;
                        c2.socket
                            .as_mut()
                            .unwrap()
                            .write_all(&ipv4.octets())
                            .await?;
                    }
                    v5::ATYP_IPV6 => {
                        let ipv6 = addr_port[0]
                            .parse::<Ipv6Addr>()
                            .map_err(|_| other("parse address fail"))?;
                        c2.socket
                            .as_mut()
                            .unwrap()
                            .write_all(&ipv6.octets())
                            .await?;
                    }
                    v5::ATYP_DOMAIN => {
                        let mut buf = [0u8; 1];
                        let len = addr_port[0].len() as u8;
                        buf[0] = len;
                        c2.socket.as_mut().unwrap().write_all(&buf).await?;
                        c2.socket
                            .as_mut()
                            .unwrap()
                            .write_all(addr_port[0].as_bytes())
                            .await?;
                    }
                    n => {
                        let msg = format!("connect_request: unknown ATYP received: {}", n);
                        return io::Result::Err(other(&msg));
                    }
                }

                // Send port
                let mut buf = [0u8; 2];
                buf[1] = port as u8;
                buf[0] = (port >> 8) as u8;
                c2.socket.as_mut().unwrap().write_all(&buf).await?;
                c2.socket.as_mut().unwrap().flush().await?;
                trace!("build_tun: Send connect_request");
                Ok(c2)
            })
            .boxed();

        // reply the connection request
        // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        let connect_response = connect_request
            .and_then(|mut c2| async move {
                let mut buf = [0u8; 4];
                c2.socket.as_mut().unwrap().read_exact(&mut buf).await?;
                trace!("build_tun: connect response {}", buf[1]);

                if buf[1] != 0 {
                    return io::Result::Err(other(&format!("connect command reply {}", buf[1])));
                }
                let remote_c2_local_addr = match buf[3] {
                    v5::ATYP_IPV4 => {
                        let mut buf = [0u8; 4 + 2];
                        c2.socket.as_mut().unwrap().read_exact(&mut buf).await?;
                        trace!("build_tun: read ipv4 success");
                        let ip: [u8; 4] = buf[..4].try_into().unwrap();
                        let sock_addr =
                            SocketAddrV4::new(ip.into(), ((buf[4] as u16) << 8) + (buf[5] as u16));
                        Some(SocketAddr::V4(sock_addr))
                    }
                    v5::ATYP_IPV6 => {
                        let mut buf = [0u8; 16 + 2];
                        c2.socket.as_mut().unwrap().read_exact(&mut buf).await?;
                        trace!("build_tun: read ipv6 success");
                        let ip: [u8; 16] = buf[..16].try_into().unwrap();
                        let sock_addr = SocketAddrV6::new(
                            ip.into(),
                            ((buf[16] as u16) << 8) + (buf[17] as u16),
                            0,
                            0,
                        );
                        Some(SocketAddr::V6(sock_addr))
                    }
                    // v5::ATYP_DOMAIN => {
                    //     let mut buf = [0u8; 1];
                    //     c2.socket.as_mut().unwrap().read_exact(&mut buf).await?;
                    //     let mut buf = vec![0u8; (buf[0] as usize) + 2];
                    //     c2.socket.as_mut().unwrap().read_exact(&mut buf).await?;
                    //     trace!("build_tun: read domain success");
                    // }
                    n => {
                        let msg = format!("connect_response: unknown ATYP received: {}", n);
                        return io::Result::Err(other(&msg));
                    }
                };

                Ok((c2, remote_c2_local_addr.unwrap()))
            })
            .boxed();

        Ok(connect_response.await?)
    }

    async fn run_bypass_proc(
        &self,
        mut conn: impl TSocket,
        c2: io::Result<impl TSocket>,
        dest_addr: Box<String>,
    ) -> io::Result<(u64, u64, Box<String>)> {
        trace!("bypass_proc: dest_addr: {}", *dest_addr);
        // Once we've gotten to this point, we're ready for the final part of
        // the SOCKSv5 handshake. We've got in our hands (c2) the client we're
        // going to proxy data to, so we write out relevant information to the
        // original client (c1) the "response packet" which is the final part of
        // this handshake.
        let handshake_finish = async move {
            let mut resp = [0u8; 32];

            // VER - protocol version
            resp[0] = 5;

            // REP - "reply field" -- what happened with the actual connect.
            //
            // In theory this should reply back with a bunch more kinds of
            // errors if possible, but for now we just recognize a few concrete
            // errors.
            resp[1] = match c2 {
                Ok(..) => 0,
                Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => 5,
                Err(..) => 1,
            };

            // RSV - reserved
            resp[2] = 0;

            if resp[1] != 0 {
                resp[3] = 1;
                resp[4..10].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
                conn.write_all(&resp[..10]).await?;
                conn.flush().await?;
                return Err(other("c2 connect fail"));
            }

            let c2 = c2.unwrap();
            // ATYP, BND.ADDR, and BND.PORT
            //
            // These three fields, when used with a "connect" command
            // (determined above), indicate the address that our proxy
            // connection was bound to remotely. There's a variable length
            // encoding of what's actually written depending on whether we're
            // using an IPv4 or IPv6 address, but otherwise it's pretty
            // standard.
            let addr = multiaddr_to_socketaddr(&c2.local_addr())?;

            let pos = match addr {
                SocketAddr::V4(ref a) => {
                    resp[3] = 1;
                    resp[4..8].copy_from_slice(&a.ip().octets()[..]);
                    8
                }
                SocketAddr::V6(ref a) => {
                    resp[3] = 4;
                    let mut pos = 4;
                    for &segment in a.ip().segments().iter() {
                        resp[pos] = (segment >> 8) as u8;
                        resp[pos + 1] = segment as u8;
                        pos += 2;
                    }
                    pos
                }
            };

            resp[pos] = (addr.port() >> 8) as u8;
            resp[pos + 1] = addr.port() as u8;

            // Slice our 32-byte `resp` buffer to the actual size, as it's
            // variable depending on what address we just encoding. Once that's
            // done, write out the whole buffer to our client.
            //
            // The returned type of the future here will be `(TcpStream,
            // TcpStream)` representing the client half and the proxy half of
            // the connection.
            conn.write_all(&resp[..(pos + 2)]).await?;
            conn.flush().await?;
            io::Result::Ok((conn, c2, dest_addr))
        }
        .boxed();

        // Phew! If you've gotten this far, then we're now entirely done with
        // the entire SOCKSv5 handshake!
        //
        // In order to handle ill-behaved clients, however, we have an added
        // feature here where we'll time out any initial connect operations
        // which take too long.
        //
        // Here we create a timeout future, using the `Timeout::new` method,
        // which will create a future that will resolve to `()` in 20 seconds.
        // We then apply this timeout to the entire handshake all at once by
        // performing a `select` between the timeout and the handshake itself.
        let delay = sleep(std::time::Duration::from_secs(20_u64));
        let pair = future::select(handshake_finish, delay.boxed())
            .then(|either| async move {
                match either {
                    future::Either::Left((Ok(pair), _)) => {
                        trace!("Get c1, c2 success");
                        Ok(pair)
                    }
                    future::Either::Left((Err(e), _)) => Err(e),
                    future::Either::Right(((), _)) => {
                        io::Result::Err(other("timeout during handshake"))
                    }
                }
            })
            .boxed();

        // At this point we've *actually* finished the handshake. Not only have
        // we read/written all the relevant bytes, but we've also managed to
        // complete in under our allotted timeout.
        //
        // At this point the remainder of the SOCKSv5 proxy is shuttle data back
        // and for between the two connections. That is, data is read from `c1`
        // and written to `c2`, and vice versa.
        //
        // To accomplish this, we put both sockets into their own `Rc` and then
        // create two independent `Transfer` futures representing each half of
        // the connection. These two futures are `join`ed together to represent
        // the proxy operation happening.
        pair.and_then(|(c1, c2, dest_addr)| async move {
            let c1_addr = (c1.local_addr(), c1.peer_addr());
            let c2_addr = (c2.local_addr(), c2.peer_addr());
            let (c1_read, c1_write) = c1.split();
            let (c2_read, c2_write) = c2.split();
            let half1 = transfer(c1_read, c1_addr.clone(), c2_write, c2_addr.clone());
            let half2 = transfer(c2_read, c2_addr, c1_write, c1_addr);
            let (res1, res2) = future::try_join(half1, half2).await?;
            io::Result::Ok((res1, res2, dest_addr))
        })
        .await
    }

    async fn run_tun_proc(
        &self,
        mut conn: impl TSocket,
        c2: io::Result<(Connection<impl TSocket>, SocketAddr)>,
        dest_addr: Box<String>,
    ) -> io::Result<(u64, u64, Box<String>)> {
        trace!("tun_proc: dest_addr: {}", *dest_addr);
        // Once we've gotten to this point, we're ready for the final part of
        // the SOCKSv5 handshake. We've got in our hands (c2) the client we're
        // going to proxy data to, so we write out relevant information to the
        // original client (c1) the "response packet" which is the final part of
        // this handshake.
        let handshake_finish = async move {
            let mut resp = [0u8; 32];

            // VER - protocol version
            resp[0] = 5;

            // REP - "reply field" -- what happened with the actual connect.
            //
            // In theory this should reply back with a bunch more kinds of
            // errors if possible, but for now we just recognize a few concrete
            // errors.
            resp[1] = match c2 {
                Ok(..) => 0,
                Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => 5,
                Err(..) => 1,
            };

            // RSV - reserved
            resp[2] = 0;

            if resp[1] != 0 {
                resp[3] = 1;
                resp[4..10].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
                conn.write_all(&resp[..10]).await?;
                conn.flush().await?;
                return Err(other("c2 connect fail"));
            }

            let (c2, remote_c2_local_addr) = c2.unwrap();
            // ATYP, BND.ADDR, and BND.PORT
            //
            // These three fields, when used with a "connect" command
            // (determined above), indicate the address that our proxy
            // connection was bound to remotely. There's a variable length
            // encoding of what's actually written depending on whether we're
            // using an IPv4 or IPv6 address, but otherwise it's pretty
            // standard.
            let pos = match remote_c2_local_addr {
                SocketAddr::V4(ref a) => {
                    resp[3] = 1;
                    resp[4..8].copy_from_slice(&a.ip().octets()[..]);
                    8
                }
                SocketAddr::V6(ref a) => {
                    resp[3] = 4;
                    let mut pos = 4;
                    for &segment in a.ip().segments().iter() {
                        resp[pos] = (segment >> 8) as u8;
                        resp[pos + 1] = segment as u8;
                        pos += 2;
                    }
                    pos
                }
            };

            resp[pos] = (remote_c2_local_addr.port() >> 8) as u8;
            resp[pos + 1] = remote_c2_local_addr.port() as u8;
            trace!("remote c2 local addr: {}", remote_c2_local_addr);
            // Slice our 32-byte `resp` buffer to the actual size, as it's
            // variable depending on what address we just encoding. Once that's
            // done, write out the whole buffer to our client.
            //
            // The returned type of the future here will be `(TcpStream,
            // TcpStream)` representing the client half and the proxy half of
            // the connection.
            conn.write_all(&resp[..(pos + 2)]).await?;
            conn.flush().await?;
            io::Result::Ok((conn, c2, dest_addr))
        }
        .boxed();

        let (conn, mut c2, _dest_addr) = handshake_finish.await?;
        let c1_addr = (conn.local_addr(), conn.peer_addr());
        let c2_addr = (c2.metadata.c_addr().clone(), c2.metadata.s_addr().clone());
        let dest_addr = Box::new(multiaddr_to_socketaddr(&c2_addr.1).unwrap().to_string());
        let (c1_read, c1_write) = conn.split();
        let (c2_read, c2_write) = c2.socket.take().unwrap().split();

        let half1 = transfer(c1_read, c1_addr.clone(), c2_write, c2_addr.clone());
        let half2 = transfer(c2_read, c2_addr, c1_write, c1_addr);
        let (res1, res2) = future::try_join(half1, half2).await?;
        io::Result::Ok((res1, res2, dest_addr))
    }

    async fn update_peer_conn_state(&self) -> bool {
        let delay = sleep(std::time::Duration::from_secs(5));

        let noise_transport =
            build_tcp_noise_transport(self.local_private_key.clone(), self.peer_public_key);

        let conn = noise_transport
            .dial(self.peer_addr.clone())
            .unwrap_or_else(|_| panic!("Transport dail {} fail", self.peer_addr));
        // let conn = TCP_TRANSPORT
        //     .dial(self.peer_addr.clone())
        //     .unwrap_or_else(|_| panic!("Transport dail {} fail", self.peer_addr));
        let peer_ready = future::select(conn, delay.boxed())
            .then(|either| async move {
                match either {
                    future::Either::Left((Ok(pair), _)) => Ok(pair),
                    future::Either::Left((Err(e), _)) => Err(other(&e.to_string())),
                    future::Either::Right(((), _)) => {
                        io::Result::Err(other("timeout during handshake"))
                    }
                }
            })
            .await
            .is_ok();

        self.peer_ready.store(peer_ready, Ordering::Relaxed);
        peer_ready
    }

    async fn serve_http(&self, mut conn: impl TSocket) -> io::Result<(u64, u64, Box<String>)> {
        let mut buf = [0_u8; 4 * 1024];
        const HEADER_LINE_END: &[u8] = b"\r\n";

        // Read the whole request ending with empty line \r\n\r\n
        let read_header = Self::read_http_header(&mut conn, &mut buf).boxed();
        let (mut header_size, read_len) =
            match future::select(read_header, sleep(Duration::from_secs(10)).boxed()).await {
                future::Either::Left((res, _)) => res,
                future::Either::Right(((), _)) => {
                    io::Result::Err(other("timeout during read request"))
                }
            }?;

        // Count header line.
        let header_count = buf[..header_size]
            .windows(HEADER_LINE_END.len())
            .filter(|window| *window == HEADER_LINE_END)
            .count()
            - 1;
        trace!(
            "Parse {} header lines {}",
            header_count,
            std::str::from_utf8(&buf)
                .map_err(|e| other(&format!("convert to utf8 fail {}", &e.to_string())))?
        );

        // Check requet headers
        let mut headers = vec![httparse::EMPTY_HEADER; header_count];
        let mut req = httparse::Request::new(&mut headers);
        let res = req.parse(&buf).map_err(|e| other(&e.to_string()))?;
        if !res.is_complete() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Pares request fail raw input {}",
                    std::str::from_utf8(&buf)
                        .map_err(|e| other(&format!("convert to utf8 fail {}", &e.to_string())))?,
                ),
            ));
        }

        if req.method.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Cannot parse method. raw input {}",
                    std::str::from_utf8(&buf)
                        .map_err(|e| other(&format!("convert to utf8 fail {}", &e.to_string())))?,
                ),
            ));
        }

        if req.version.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Cannot parse version. raw input {}",
                    std::str::from_utf8(&buf)
                        .map_err(|e| other(&format!("convert to utf8 fail {}", &e.to_string())))?,
                ),
            ));
        }

        // Get Host header from request
        let dest_addr = match (req.headers).iter().find(|h| h.name == "Host") {
            Some(a) => std::str::from_utf8(a.value)
                .map_err(|e| other(&format!("Convert to utf8 fail {}", &e.to_string())))?,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Cannot find Host header in request. raw input {}",
                        std::str::from_utf8(&buf).map_err(|e| other(&format!(
                            "Convert to utf8 fail {}",
                            &e.to_string()
                        )))?,
                    ),
                ))
            }
        };

        if req.method.unwrap() != "CONNECT" {
            header_size = 0;
        };

        // Find the ip of hostname
        let (remote_socket_addr, atyp) = http_hostname_to_ip(dest_addr).await?;

        // TODO: support auto-proxy-configuraiton return PAC file
        if socketaddr_to_multiaddr(&remote_socket_addr) == self.listen_addr {
            trace!("Http access proxy self");
            let response = format!("HTTP/1.{} 404 Not Found\r\n\r\n", req.version.unwrap());
            conn.write_all(response.as_bytes()).await?;
            conn.flush().await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Cannot self reponse as server. raw input {}",
                    std::str::from_utf8(&buf)
                        .map_err(|e| other(&format!("Convert to utf8 fail {}", &e.to_string())))?,
                ),
            ));
        }

        debug!("proxying to {}", remote_socket_addr);
        let mut pass = false;
        if atyp != v5::ATYP_IPV6 {
            if let SocketAddr::V4(addr_v4) = remote_socket_addr {
                pass = self.is_bypass_addr(addr_v4.ip());
                trace!("address: {} bypass: {}", addr_v4, pass)
            }
        }

        let (bypass_c2, tun_c2) = if !pass {
            (
                None,
                Some(self.build_tunnel(dest_addr.to_string(), atyp).await?),
            )
        } else {
            (
                Some(
                    TCP_TRANSPORT
                        .dial(socketaddr_to_multiaddr(&remote_socket_addr))?
                        .await?,
                ),
                None,
            )
        };

        // Send response to client for CONNECT request.
        if req.method.unwrap() == "CONNECT" {
            let response = format!(
                "HTTP/1.{} 200 Connection established\r\n\r\n",
                req.version.unwrap()
            );
            conn.write_all(response.as_bytes()).await?;
            conn.flush().await?;
        }

        let left = &buf[header_size..read_len];
        trace!("Left data size after request {}", left.len());

        let c1 = conn;
        if bypass_c2.is_some() {
            let mut c2 = bypass_c2.unwrap();
            // Deliver left data to remote server
            if !left.is_empty() {
                c2.write_all(left).await?;
                c2.flush().await?;
            }
            let c1_addr = (c1.local_addr(), c1.peer_addr());
            let c2_addr = (c2.local_addr(), c2.peer_addr());
            let (c1_read, c1_write) = c1.split();
            let (c2_read, c2_write) = c2.split();
            let half1 = transfer(c1_read, c1_addr.clone(), c2_write, c2_addr.clone());
            let half2 = transfer(c2_read, c2_addr, c1_write, c1_addr);
            let (res1, res2) = future::try_join(half1, half2).await?;
            io::Result::Ok((res1, res2, Box::new(dest_addr.to_string())))
        } else {
            let (mut c2, _remote_c2_local_addr) = tun_c2.unwrap();
            // Deliver left data to remote server
            if !left.is_empty() {
                c2.socket.as_mut().unwrap().write_all(left).await?;
                c2.socket.as_mut().unwrap().flush().await?;
            }
            let c1_addr = (c1.local_addr(), c1.peer_addr());
            let c2_addr = (c2.metadata.c_addr().clone(), c2.metadata.s_addr().clone());
            let dest_addr = Box::new(multiaddr_to_socketaddr(&c2_addr.1).unwrap().to_string());
            let (c1_read, c1_write) = c1.split();
            let (c2_read, c2_write) = c2.socket.take().unwrap().split();

            let half1 = transfer(c1_read, c1_addr.clone(), c2_write, c2_addr.clone());
            let half2 = transfer(c2_read, c2_addr, c1_write, c1_addr);
            let (res1, res2) = future::try_join(half1, half2).await?;
            io::Result::Ok((res1, res2, dest_addr))
        }
    }

    async fn read_http_header(
        conn: &mut impl TSocket,
        buf: &mut [u8],
    ) -> io::Result<(usize, usize)> {
        const HEADER_ENDING: &[u8] = b"\r\n\r\n";

        let mut idx = 0_usize;
        loop {
            let read_size = conn.read(&mut buf[idx..]).await?;
            if read_size == 0 {
                error!("Read 0 bytes");
                return Err(io::Error::new(io::ErrorKind::Other, "Read 0 bytes"));
            }
            idx += read_size;
            let found = buf[..idx]
                .windows(HEADER_ENDING.len())
                .rposition(|window| window == HEADER_ENDING)
                .map(|pos| pos + HEADER_ENDING.len());

            if found.is_some() {
                return Ok((found.unwrap(), idx));
            }
            if idx >= buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Cannot parse header {} too large",
                        std::str::from_utf8(buf).map_err(|e| other(&format!(
                            "Convert to utf8 fail {}",
                            &e.to_string()
                        )))?,
                    ),
                ));
            }
        }
    }
}

async fn update_peer_conn_state(node: Arc<StartNode>) {
    loop {
        let state = node.update_peer_conn_state().await;
        trace!("peer connection state: {}", state);
        sleep(Duration::from_secs(10)).await;
    }
}

fn concate_conn<S>(mut con: Connection<S>, node: Arc<StartNode>)
where
    S: TSocket,
{
    tokio::spawn(async move {
        match node
            .serve(con.socket.take().unwrap())
            .await
            .map_err(Box::new)
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
    proto: ProtoType,
    listen_addr: Multiaddr,
    peer_addr: Multiaddr,
    local_private_key: PrivateKey,
    peer_public_key: PublicKey,
    bypass_list: Option<NetAddrIpv4List>,
) -> Result<(), Box<dyn ::std::error::Error + Send + Sync + 'static>> {
    let start_node = Arc::new(StartNode::new(
        proto,
        listen_addr.clone(),
        peer_addr,
        local_private_key,
        peer_public_key,
        bypass_list,
    ));

    // Spawn a job to check peer connection state
    tokio::spawn(update_peer_conn_state(Arc::clone(&start_node)));
    let transport = build_tcp_transport();
    let (listener, _server_addr) = transport.listen_on(listen_addr)?;
    server_stream_handler(listener, concate_conn, start_node).await?;
    Ok(())
}
