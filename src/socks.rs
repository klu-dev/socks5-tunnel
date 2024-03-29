use std::{
    io,
    net::{IpAddr, SocketAddr},
    str,
};

use log::debug;
use tokio::net::lookup_host;

use crate::other;

#[allow(dead_code)]
pub(crate) mod v5 {
    pub const VERSION: u8 = 5;

    pub const METH_NO_AUTH: u8 = 0;
    pub const METH_GSSAPI: u8 = 1;
    pub const METH_USER_PASS: u8 = 2;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
    pub const CMD_UDP_ASSOCIATE: u8 = 3;

    pub const ATYP_IPV4: u8 = 1;
    pub const ATYP_IPV6: u8 = 4;
    pub const ATYP_DOMAIN: u8 = 3;
}

#[allow(dead_code)]
pub(crate) mod v4 {
    pub const VERSION: u8 = 4;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
}

// Extracts the name and port from addr_buf and returns them, converting
// the name to the form that the trust-dns client can use. If the original
// name can be parsed as an IP address, makes a SocketAddr from that
// address and the port and returns it; we skip DNS resolution in that
// case.
pub(crate) async fn socks_name_port(addr_buf: &[u8]) -> io::Result<(SocketAddr, Box<String>)> {
    // The last two bytes of the buffer are the port, and the other parts of it
    // are the hostname.
    let ip_or_dn = &addr_buf[..addr_buf.len() - 2];
    let ip_or_dn = str::from_utf8(ip_or_dn)
        .map_err(|_e| other("hostname buffer provided was not valid utf-8"))?;
    let pos = addr_buf.len() - 2;
    let port = ((addr_buf[pos] as u16) << 8) | (addr_buf[pos + 1] as u16);
    let dest_addr = format!("{}:{}", ip_or_dn, port);

    if let Ok(ip) = ip_or_dn.parse() {
        return Ok((SocketAddr::new(ip, port), Box::new(dest_addr)));
    }
    debug!("lookup_host {}", ip_or_dn);
    let ip_or_dn = &format!("{}:{}", ip_or_dn, port);
    let mut addrs = lookup_host(ip_or_dn).await?;
    let first = addrs
        .next()
        .ok_or_else(|| other(&format!("wrong hostname {}", ip_or_dn)))?;
    Ok((SocketAddr::new(first.ip(), port), Box::new(dest_addr)))
}

// Check if the string is ip or host name
pub(crate) async fn http_hostname_to_ip(hostname: &str) -> io::Result<(SocketAddr, u8)> {
    let mut addr = hostname.split(':');
    let ip_or_dn = addr
        .next()
        .ok_or_else(|| other(&format!("wrong hostname {}", hostname)))?;
    let port = addr
        .next()
        .unwrap_or("80")
        .parse::<u16>()
        .map_err(|e| other(&format!("Parse port fail {}", e.to_string().as_str())))?;
    if let Ok(ip) = ip_or_dn.parse() {
        let atyp = match ip {
            IpAddr::V4(_) => v5::ATYP_IPV4,
            IpAddr::V6(_) => v5::ATYP_IPV6,
        };
        return Ok((SocketAddr::new(ip, port), atyp));
    }
    debug!("lookup_host {}", ip_or_dn);
    let ip_or_dn = &format!("{}:{}", ip_or_dn, port);
    let mut addrs = lookup_host(ip_or_dn).await?;
    let first = addrs
        .next()
        .ok_or_else(|| other(&format!("wrong hostname {}", ip_or_dn)))?;
    Ok((SocketAddr::new(first.ip(), port), v5::ATYP_DOMAIN))
}
