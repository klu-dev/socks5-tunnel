use crate::transport::tcp::socketaddr_to_multiaddr;
use crypto::x25519::{PrivateKey, PublicKey};
use parity_multiaddr::Multiaddr;
use std::net::SocketAddr;
use std::str::FromStr;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "socks5-tunnel",
    about = "Proxy for socks5 through encrpted tunnel\n\
*                   ______________________________________________\n\
*                   | __________________________________________  |\n\
*                   | |           Noise Encrypt Tunnel          | |\n\
Browser ---> Client Mode Proxy                            Server Mode Proxy ------> Destination Web Site\n\
Support three kind of command:\n\
1. Generate secret key:\n\
.\\socks5-tunnel.exe -g\n\
2. Work in clinet mode:\n\
.\\socks5-tunnel.exe -m client -l 127.0.0.1:1080 -p 127.0.0.1:2080 -k \
<local private key> -b <peer public key>\n\
3. Work in server mode:\n\
.\\socks5-tunnel.exe -m server -l 127.0.0.1:2080 -k \
<local private key> -b <peer public key>\n"
)]
pub struct Args {
    #[structopt(short = "g", long, help = "generate curve25519 keypair")]
    gen_key_pair: bool,
    // mode: client or server
    #[structopt(
        short = "m",
        long,
        required_if("gen_key_pair", "false"),
        help = "set working mode: client or server"
    )]
    mode: Option<CommandMode>,

    #[structopt(
        short = "l",
        long = "localaddr",
        required = false,
        default_value = "127.0.0.1:1080",
        help = "listen address: ip:port"
    )]
    local_addr: SocketAddr,

    #[structopt(
        short = "p",
        long = "peeraddr",
        required_if("mode", "client"),
        help = "peer address: ip:port"
    )]
    peer_addr: Option<SocketAddr>,

    #[structopt(
        short = "k",
        long = "localprivatekey",
        required_if("mode", "client"),
        required_if("mode", "server"),
        help = "local private key: Curve25519 256 bit"
    )]
    local_pirvate_key: Option<PrivateKey>,

    #[structopt(
        short = "b",
        long = "peerpublickey",
        required_if("mode", "client"),
        required_if("mode", "server"),
        help = "peer public key: Curve25519 256 bit 256 bit"
    )]
    peer_public_key: Option<PublicKey>,
}

pub fn parse_command_line() -> Command {
    let args = Args::from_args();

    if args.gen_key_pair {
        return Command::GenerateKeypair;
    }

    if let Some(mode) = args.mode {
        match mode {
            CommandMode::Client => {
                return Command::ClientMode(
                    socketaddr_to_multiaddr(args.local_addr),
                    socketaddr_to_multiaddr(args.peer_addr.unwrap()),
                    args.local_pirvate_key.unwrap(),
                    args.peer_public_key.unwrap(),
                )
            }
            CommandMode::Server => {
                return Command::ServerMode(
                    socketaddr_to_multiaddr(args.local_addr),
                    args.local_pirvate_key.unwrap(),
                    args.peer_public_key.unwrap(),
                )
            }
        }
    }

    Command::None
}

pub enum Command {
    None,
    GenerateKeypair,
    ClientMode(Multiaddr, Multiaddr, PrivateKey, PublicKey),
    ServerMode(Multiaddr, PrivateKey, PublicKey),
}

#[derive(Debug)]
pub enum CommandMode {
    Client,
    Server,
}

impl FromStr for CommandMode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "client" => Ok(CommandMode::Client),
            "server" => Ok(CommandMode::Server),
            _ => Err("Unknow mode. Option should be client or server"),
        }
    }
}
