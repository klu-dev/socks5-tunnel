// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! [Noise protocol framework][noise] support for use in Libra.
//!
//! The main feature of this module is [`NoiseSocket`](crate::socket::NoiseSocket) which
//! provides wire-framing for noise payloads.  Currently the only handshake pattern supported is IX.
//!
//! [noise]: http://noiseprotocol.org/

use crate::transport::ConnectionOrigin;
use futures::io::{AsyncRead, AsyncWrite};
use snow::{self, params::NoiseParams};
use std::io;

mod socket;

pub use self::socket::NoiseSocket;
use crypto::{x25519, ValidKey};

const NOISE_PARAMETER: &str = "Noise_KK_25519_AESGCM_SHA256";

/// The Noise protocol configuration to be used to perform a protocol upgrade on an underlying
/// socket.
pub struct NoiseConfig {
    key: x25519::PrivateKey,
    peer_key: x25519::PublicKey,
    parameters: NoiseParams,
}

impl NoiseConfig {
    /// Create a new NoiseConfig with the provided keypair
    pub fn new(key: x25519::PrivateKey, peer_key: x25519::PublicKey) -> Self {
        let parameters: NoiseParams = NOISE_PARAMETER.parse().expect("Invalid protocol name");
        Self {
            key,
            peer_key,
            parameters,
        }
    }

    /// Create a new NoiseConfig with an ephemeral static key.
    #[cfg(feature = "testing")]
    pub fn new_random(rng: &mut (impl rand::RngCore + rand::CryptoRng)) -> Self {
        let parameters: NoiseParams = NOISE_PARAMETER.parse().expect("Invalid protocol name");
        let key = x25519::PrivateKey::for_test(rng);
        Self { key, parameters }
    }

    /// Perform a protocol upgrade on an underlying connection. In addition perform the noise IX
    /// handshake to establish a noise session and exchange static public keys. Upon success,
    /// returns the static public key of the remote as well as a NoiseSocket.
    pub async fn upgrade_connection<TSocket>(
        &self,
        socket: TSocket,
        origin: ConnectionOrigin,
    ) -> io::Result<(Vec<u8>, NoiseSocket<TSocket>)>
    where
        TSocket: AsyncRead + AsyncWrite + Unpin,
    {
        // Instantiate the snow session
        // Note: We need to scope the Builder struct so that the compiler doesn't over eagerly
        // capture it into the Async State-machine.
        let session = {
            let key = self.key.to_bytes();
            let peer_key = self.peer_key.to_bytes();
            let builder = snow::Builder::new(self.parameters.clone())
                .local_private_key(&key)
                .remote_public_key(&peer_key);
            match origin {
                ConnectionOrigin::Inbound => builder.build_responder(),
                ConnectionOrigin::Outbound => builder.build_initiator(),
            }
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?
        };

        let handshake = socket::Handshake::new(socket, session);

        let socket = handshake.handshake_1rt().await?;
        let remote_static_key = socket
            .get_remote_static()
            .expect("Noise remote static key already taken")
            .to_owned();
        Ok((remote_static_key, socket))
    }
}
