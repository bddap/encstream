//! Secure netcat

// This example uses futures to some extent, but file io doesn't play well with futures yet
// so reading from stdin and writing to stdout are performed as blocking opterations on separate
// threads.
//
// Solutions like https://crates.io/crates/futures-fs exists, but add complexity.

#![feature(async_await)]

mod encoding;

use crate::encoding::{pk_from_hex, pk_to_hex};
use encstream::{generate_keypair, EncStream, PublicKey, SecretKey};
use futures::executor::block_on;
use futures::{AsyncRead, AsyncWrite};
use futures_util::stream::StreamExt;
use romio::TcpListener;
use romio::TcpStream;
use serde_json;
use std::fs::File;
use std::io;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::thread;
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

#[derive(serde::Serialize, serde::Deserialize)]
struct Keypair {
    secret: SecretKey,
    public: PublicKey,
}

fn main() {
    block_on(async_main())
}

async fn async_main() {
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
            let mut listener =
                TcpListener::bind(&SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port))
                    .expect("could not bind address");

            // accept connections until a connection from authorized_host is recieved
            let mut incoming = listener.incoming();
            let enc_stream = loop {
                if let Some(tcp_stream) = incoming.next().await {
                    let tcp_stream = tcp_stream.expect("error initiating tcp connection");
                    match EncStream::responder_handshake(tcp_stream, &sk).await {
                        Ok(enc_stream) => {
                            if enc_stream.get_remote_static() == authorized_host {
                                break enc_stream;
                            }
                        }
                        _ => {}
                    }
                } else {
                    panic!("listener error");
                }
            };

            // This line is inappropriate. An async funciton should not perform blocking io.
            xfer(enc_stream);
        }
        Opt::Connect {
            path_to_keypair,
            remote_address,
            remote_public_key,
        } => {
            // read private key from file
            let sk = load_keypair(&path_to_keypair).secret;

            // connect to remote host
            let tcp_stream = TcpStream::connect(&remote_address)
                .await
                .expect("cannot connect to remote host");

            // panic if hanshake fails
            let enc_stream = EncStream::initiatior_handshake(tcp_stream, &sk)
                .await
                .expect("handshake failed");

            // panic if remote host has wrong pk
            if enc_stream.get_remote_static() != remote_public_key {
                panic!("remote public key does not match specified public key, aborting");
            }

            // This line is inappropriate. An async funciton should not perform blocking io.
            xfer(enc_stream);
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

/// Write stream output to stdout and stream input to stdin. Block until both
/// operations are complete.
fn xfer<S: 'static + AsyncWrite + AsyncRead + Unpin + Send>(stream: EncStream<S>) {
    // xfer
    let mut inp = io::stdin();
    let mut out = io::stdout();
    let (mut enc_inp, mut enc_out) = stream.split();
    let send = thread::spawn(move || block_on(send(&mut inp, &mut enc_out)));
    let recv = thread::spawn(move || block_on(recv(&mut out, &mut enc_inp)));
    let sr = send.join();
    let rr = recv.join();
    sr.expect("send thread panicked");
    rr.expect("send thread panicked");
}

async fn send<'a, R: io::Read, Stream: AsyncWrite + Unpin>(
    inp: &'a mut R,
    stream: &'a mut EncStream<Stream>,
) {
    let mut buf = [0u8; 65519];
    loop {
        // This line is inappropriate. An async funciton should not perform blocking io.
        let len = inp.read(&mut buf[1..]).expect("error reading from input");
        if len == 0 {
            stream
                .send(&[1])
                .await
                .expect("error sending terminating message to stream");
            break;
        }
        debug_assert_eq!(buf[0], 0);
        stream
            .send(&buf[..len + 1])
            .await
            .expect("error sending to stream");
    }
}

async fn recv<'a, W: io::Write, Stream: AsyncRead + Unpin>(
    out: &'a mut W,
    stream: &'a mut EncStream<Stream>,
) {
    let mut buf = [0u8; 65519];
    loop {
        let len = stream
            .recv(&mut buf)
            .await
            .expect("error reading from stream");
        if len == 0 {
            panic!("got invalid data");
        }
        if buf[0] != 0 {
            break;
        }
        // This line is inappropriate. An async funciton should not perform blocking io.
        out.write_all(&buf[1..len])
            .expect("error writing to output");
    }
}
