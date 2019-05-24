//! Secure netcat

mod encoding;

use crate::encoding::pk_from_hex;
use encstream::{EncryptedDuplexStream, PublicKey, SecretKey};
use serde_json;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "scat", about = "Secure netcat")]
enum Opt {
    /// Generate a keypair
    #[structopt(name = "generate")]
    Generate {
        #[structopt(default_value = "/dev/stdout")]
        path_to_keypair_output: PathBuf,
    },
    /// Print the public key from a generated keypair file
    #[structopt(name = "getpub")]
    Getpub {
        #[structopt(default_value = "/dev/stdin")]
        path_to_keypair: PathBuf,
    },
    /// Listen on secret key
    #[structopt(name = "listen")]
    Listen {
        path_to_keypair_input: PathBuf,
        port: u16,
        /// public key of client
        #[structopt(parse(try_from_str = "pk_from_hex"))]
        authorized_host: PublicKey,
    },
    /// Send and recieve bytes to/from listening host
    #[structopt(name = "connect")]
    Connect {
        remote_address: SocketAddr,
        /// public key of host
        #[structopt(parse(try_from_str = "pk_from_hex"))]
        remote_public_key: PublicKey,
    },
}

// scat listen <secret-key-file> <port>

#[derive(serde::Serialize, serde::Deserialize)]
struct Keypair {
    secret: SecretKey,
    public: PublicKey,
}

fn main() {
    match Opt::from_args() {
        Opt::Generate {
            path_to_keypair_output,
        } => {
            // Generate
            // serialize to file
        }
        Opt::Getpub { path_to_keypair } => {
            // read pub from file
            // print pub as hex
        }
        Opt::Listen {
            path_to_keypair_input,
            port,
            authorized_host,
        } => {
            // read private key from file
            // listen on port on all interfaces
            // accept connections until a connection from authorized_host is recieved
            // xfer
        }
        Opt::Connect {
            remote_address,
            remote_public_key,
        } => {
            // read private key from file
            // connect to remote host
            // panic if hanshake fails
            // panic if remote host has wrong pk
            // xfer
        }
    }
}

fn xfer<W: io::Write, R: io::Read, Stream: io::Read + io::Write>(
    out: W,
    inp: R,
    stream: EncryptedDuplexStream<Stream>,
) {
    // spawn send and recv thread
    // join
}

fn send<R: io::Read>(inp: R) {}

fn recv<W: io::Write>(out: W) {}
