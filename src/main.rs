//! Proxy for socks5 through encrpted tunnel
//!                     ______________________________________________
//!                     | __________________________________________  |
//!                     | |           Noise Encrypt Tunnels         | |
//! Browser ---> Client Mode Proxy                            Server Mode Proxy ------> Destination Web Site
//! 1. Generate secret key:
//! `.\socks5-tunnel.exe -g`
//! 2. Work in clinet mode:
//! `.\socks5-tunnel.exe -m client -l 127.0.0.1:1080 -p 127.0.0.1:2080 -k <local private key> -b <peer public key>`
//! 3. Work in server mode:
//! `.\socks5-tunnel.exe -m server -l 127.0.0.1:2080 -k <local private key> -b <peer public key>`
//!
//! Very connection from Browser will create a Noise encrypt connection between client proxy and server proxy to
//! deliver data from browser to destination web site.
//!
//! An alternative use multiplexer between client proxy and server proxy on one connection to decrease the number
//! of connections. One multiplexer is [Yamux protocol](https://github.com/hashicorp/yamux/blob/master/spec.md).
//! The problem is Yamux has no priority management. Different stream has the same priority. In extreme cases,
//! one stream may occupy the whole traffic and cause other streams starvation. But in some scenario such as
//! connection limitations case, multiplexer is useful.
//!
//! This program aims to solve that Chrome do not support socks5 authentication which use username/password and
//! considered not safe. It use fixed key pair as authentication. Assuming client proxy and server proxy konw peer
//! public key, which can be generated through command `.\socks5-tunnel.exe -g`, in advance through other ways.
//! Attackers need to know server public key and client private key, otherwise it can not connect to server.
//!
//! Compared with https proxy, the noise protocol is more simple without CA and has been used by [WireGuard](https://www.wireguard.com/)

#![warn(rust_2018_idioms)]

use ::log::error;
use crypto::{traits::ValidKey, x25519};
use rand::{rngs::StdRng, SeedableRng};
use tokio::io;

use crate::command::{parse_command_line, Command};
use crate::end_node::start_server_mode;
use crate::start_node::start_client_mode;

mod build_transport;
mod command;
mod end_node;
mod noise;
mod server;
mod socks;
mod start_node;
mod transport;

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let cmd = parse_command_line();

    match cmd {
        Command::GenerateKeypair => {
            generate_keypair();
        }
        Command::None => {
            println!("Parse command parameters fail.");
            println!("{}", command::COMMAND_HELP);

            return Err(other("Parse command fail."));
        }
        Command::ServerMode(listen_addr, local_priavte_key, peer_public_key) => {
            println!("Work in server mode...");
            println!("Listening on: {}", listen_addr);
            if let Err(e) =
                start_server_mode(listen_addr.clone(), local_priavte_key, peer_public_key).await
            {
                error!("Start server error for {}: {}", listen_addr, e);
            }
        }
        Command::ClientMode(
            proto,
            listen_addr,
            peer_addr,
            local_priavte_key,
            peer_public_key,
            bypass_list,
        ) => {
            println!("Work in client mode...");
            println!("Listening on: {}", listen_addr);
            if let Err(e) = start_client_mode(
                proto,
                listen_addr.clone(),
                peer_addr,
                local_priavte_key,
                peer_public_key,
                bypass_list,
            )
            .await
            {
                error!("Start server error for {}: {}", listen_addr, e);
            }
        }
    }
    Ok(())
}

fn generate_keypair() {
    let mut rng = StdRng::from_entropy();
    let private_key = x25519::PrivateKey::for_test(&mut rng);
    println!(
        "Private key:\n{}",
        hex::encode(private_key.to_bytes().as_slice())
    );
    println!(
        "Public key:\n{}",
        hex::encode(private_key.public_key().to_bytes().as_slice())
    );
}

fn other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}
