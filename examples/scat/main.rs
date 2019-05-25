//! Secure netcat

mod encoding;

use crate::encoding::{pk_from_hex, pk_to_hex};
use encstream::{generate_keypair, EncryptedDuplexStream, PublicKey, SecretKey};
use serde_json;
use std::fs::File;
use std::io;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
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
        path_to_keypair: PathBuf,
        port: u16,
        /// public key of client
        #[structopt(parse(try_from_str = "pk_from_hex"))]
        authorized_host: PublicKey,
    },
    /// Send and recieve bytes to/from listening host
    #[structopt(name = "connect")]
    Connect {
        path_to_keypair: PathBuf,
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
            let (secret, public) = generate_keypair();

            // serialize to file
            save_keypair(&path_to_keypair_output, &Keypair { secret, public })
        }
        Opt::Getpub { path_to_keypair } => {
            // read pub from file
            let pk = load_keypair(&path_to_keypair).public;

            // print pub as hex
            println!("{}", pk_to_hex(&pk));
        }
        Opt::Listen {
            path_to_keypair,
            port,
            authorized_host,
        } => {
            // read private key from file
            let sk = load_keypair(&path_to_keypair).secret;

            // listen on port on all interfaces
            let listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port))
                .expect("could not bind address");

            // accept connections until a connection from authorized_host is recieved
            let mut enc_stream = loop {
                let tcp_stream = listener
                    .accept()
                    .expect("error listening for tcp connection")
                    .0;
                match EncryptedDuplexStream::responder_handshake(tcp_stream, &sk) {
                    Ok(enc_stream) => {
                        if enc_stream.get_remote_static() == authorized_host {
                            break enc_stream;
                        }
                    }
                    _ => {}
                }
            };

            // xfer
            recv(&mut io::stdout(), &mut enc_stream);
            send(&mut io::stdin(), &mut enc_stream);
        }
        Opt::Connect {
            path_to_keypair,
            remote_address,
            remote_public_key,
        } => {
            // read private key from file
            let sk = load_keypair(&path_to_keypair).secret;

            // connect to remote host
            let tcp_stream =
                TcpStream::connect(remote_address).expect("cannot connect to remote host");

            // panic if hanshake fails
            let mut enc_stream = EncryptedDuplexStream::initiatior_handshake(tcp_stream, &sk)
                .expect("handshake failed");

            // panic if remote host has wrong pk
            if enc_stream.get_remote_static() != remote_public_key {
                panic!("remote public key does not match specified public key, aborting");
            }

            // xfer
            send(&mut io::stdin(), &mut enc_stream);
            recv(&mut io::stdout(), &mut enc_stream);
        }
    }
}

fn save_keypair(path: &PathBuf, keypair: &Keypair) {
    let file = File::create(path).expect("could not open keypair file for writing");
    serde_json::to_writer(file, keypair).expect("could not serialize keypair");
}

fn load_keypair(path: &PathBuf) -> Keypair {
    let file = File::open(path).expect("could not open keypair file for reading");
    let retp: Keypair = serde_json::from_reader(file).expect("could not deserialize keypair");
    retp
}

fn send<R: io::Read, Stream: io::Write>(inp: &mut R, stream: &mut EncryptedDuplexStream<Stream>) {
    let mut buf = [0u8; 65519];
    loop {
        let len = inp.read(&mut buf[1..]).expect("error reading from input");
        if len == 0 {
            stream
                .send(&[1])
                .expect("error sending terminating message to stream");
            break;
        }
        debug_assert_eq!(buf[0], 0);
        stream
            .send(&buf[..(len + 1)])
            .expect("error sending to stream");
    }
}

fn recv<W: io::Write, Stream: io::Read>(out: &mut W, stream: &mut EncryptedDuplexStream<Stream>) {
    let mut buf = [0u8; 65519];
    loop {
        let len = stream.recv(&mut buf).expect("error reading from stream");
        if len == 0 {
            panic!("got invalid data");
        }
        if buf[0] != 0 {
            break;
        }
        out.write_all(&buf[1..]).expect("error writing to output");
    }
}
