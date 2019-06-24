use crate::builder::builder;
use crate::crypt::{decrypt_read, encrypt_write};
use crate::fragment::{read_noise, write_noise};
use crate::keys::{PublicKey, SecretKey};
use crate::read_encstream::ReadEncStream;
use either::Either;
use futures::io::{ReadHalf, WriteHalf};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite};
use snow::error::SnowError;
use std::io;
use std::sync::{Arc, Mutex};

/// Transformation on a read write stream, encrypts reads and writes.
pub struct EncStream<Stream> {
    underlying: Stream,
    session: Arc<Mutex<snow::Session>>,
}

impl<Stream: Unpin> EncStream<Stream> {
    pub async fn initiatior_handshake(
        mut stream: Stream,
        sk: &SecretKey,
    ) -> Result<EncStream<Stream>, Either<io::Error, SnowError>>
    where
        Stream: AsyncRead + AsyncWrite,
    {
        let mut session = builder()
            .local_private_key(&sk.0)
            .build_initiator()
            .expect("build initiatior failed");

        // XX:
        // -> e
        handshake_send(&mut stream, &mut session)
            .await
            .map_err(Either::Left)?;
        // <- e, ee, s, es
        handshake_recv(&mut stream, &mut session).await?;
        // -> s, se
        handshake_send(&mut stream, &mut session)
            .await
            .map_err(Either::Left)?;

        Ok(EncStream {
            underlying: stream,
            session: Arc::new(Mutex::new(
                session.into_transport_mode().map_err(Either::Right)?,
            )),
        })
    }

    pub async fn responder_handshake(
        mut stream: Stream,
        sk: &SecretKey,
    ) -> Result<EncStream<Stream>, Either<io::Error, SnowError>>
    where
        Stream: AsyncRead + AsyncWrite,
    {
        let mut session = builder()
            .local_private_key(&sk.0)
            .build_responder()
            .expect("build responder failed");

        // XX:
        // -> e
        handshake_recv(&mut stream, &mut session).await?;
        // <- e, ee, s, es
        handshake_send(&mut stream, &mut session)
            .await
            .map_err(Either::Left)?;
        // -> s, se
        handshake_recv(&mut stream, &mut session).await?;

        Ok(EncStream {
            underlying: stream,
            session: Arc::new(Mutex::new(
                session.into_transport_mode().map_err(Either::Right)?,
            )),
        })
    }

    /// Get the static public key of remote host
    pub fn get_remote_static(&self) -> PublicKey {
        PublicKey::from_slice(
            self.session
                .lock()
                .expect("Noise session poisioned.")
                .get_remote_static()
                .expect("remote static key not set"),
        )
    }

    /// # Panics
    ///
    /// Panics if message.len() > 65519
    pub async fn send<'a>(&'a mut self, message: &'a [u8]) -> Result<(), io::Error>
    where
        Stream: AsyncWrite,
    {
        encrypt_write(&mut self.underlying, &self.session, message).await
    }

    pub async fn recv<'a>(
        &'a mut self,
        message: &'a mut [u8; 65519],
    ) -> Result<usize, Either<io::Error, SnowError>>
    where
        Stream: AsyncRead,
    {
        decrypt_read(&mut self.underlying, &mut self.session, message).await
    }

    /// Split stream into a read half and a write half.
    pub fn split(self) -> (EncStream<ReadHalf<Stream>>, EncStream<WriteHalf<Stream>>)
    where
        Stream: AsyncWrite + AsyncRead,
    {
        let (read, write) = self.underlying.split();
        (
            EncStream {
                underlying: read,
                session: self.session.clone(),
            },
            EncStream {
                underlying: write,
                session: self.session,
            },
        )
    }

    /// Split stream into a read half and a write half.
    pub fn streams(self) -> (ReadEncStream<ReadHalf<Stream>>, ())
    where
        Stream: AsyncWrite + AsyncRead,
    {
        let (read, _write) = self.underlying.split();
        (ReadEncStream::new_post_handshake(read, self.session), ())
    }
}

/// read message and drop payload if any.
/// used when executing noise protocol handshake.
async fn handshake_recv<'a, R: AsyncRead + Unpin>(
    stream: &'a mut R,
    session: &'a mut snow::Session,
) -> Result<(), Either<io::Error, SnowError>> {
    debug_assert!(is_handshake_state(session));
    let mut buf = [0u8; 65535];
    let mut trash = [0u8; 65519];
    let len = read_noise(stream, &mut buf).await.map_err(Either::Left)?;
    session
        .read_message(&buf[..len], &mut trash)
        .map_err(Either::Right)
        .map(|_| ())
}

async fn handshake_send<'a, W: AsyncWrite + Unpin>(
    stream: &'a mut W,
    session: &'a mut snow::Session,
) -> Result<(), io::Error> {
    debug_assert!(is_handshake_state(session));
    let mut buf = [0u8; 65535];
    let len = session
        .write_message(&[], &mut buf)
        .expect("Output exceeded the max message length for the Noise Protocol (65535 bytes).");
    write_noise(stream, &buf[..len]).await
}

fn is_handshake_state(session: &snow::Session) -> bool {
    match session {
        snow::Session::Handshake(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;
    use futures::{executor::block_on, future::join};
    use futures_util::stream::StreamExt;
    use romio::{TcpListener, TcpStream};
    use std::{
        future::Future,
        net::{Ipv6Addr, SocketAddr},
        thread,
    };

    trait ChottoMatte {
        type Item;
        fn wait(self) -> Self::Item;
    }

    impl<F: Future> ChottoMatte for F {
        type Item = F::Output;
        fn wait(self) -> F::Output {
            block_on(self)
        }
    }

    fn server_client<
        ServeF: 'static + Fn(TcpListener) + Sync + Send,
        ClientF: 'static + Fn(SocketAddr) + Sync + Send,
    >(
        sf: ServeF,
        cf: ClientF,
    ) {
        // listen on loopback on ephemeral port
        let listener = TcpListener::bind(&SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0))
            .expect("failed to bind port");
        // get listen address
        let listener_addr = listener
            .local_addr()
            .expect("listener has no local address?");
        // start server thread listening on listener
        let server = thread::Builder::new()
            .name("server".to_string())
            .spawn(move || sf(listener))
            .expect("failed to spawn server thread");

        // start client thread with address to serve
        let client = thread::Builder::new()
            .name("client".to_string())
            .spawn(move || cf(listener_addr))
            .expect("failed to spawn client thread");

        server.join().expect("server thread panicked");
        client.join().expect("client thread panicked");
    }

    trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
    impl Stream for TcpStream {}

    fn server_client_generic<
        ServeF: 'static + Fn(Box<dyn Stream>) + Sync + Send,
        ClientF: 'static + Fn(Box<dyn Stream>) + Sync + Send,
    >(
        sf: ServeF,
        cf: ClientF,
    ) {
        // we use tcp just because it's easy
        server_client(
            move |mut listener| {
                let tcpstream = listener
                    .incoming()
                    .next()
                    .wait()
                    .expect("server received no connection or accept failed")
                    .expect("server got a stream, but some other failure occured");
                sf(Box::new(tcpstream));
            },
            move |listener_addr| {
                let tcpstream = TcpStream::connect(&listener_addr)
                    .wait()
                    .expect("client failed to connect to server");
                cf(Box::new(tcpstream));
            },
        );
    }

    #[test]
    fn handshake() {
        let (server_sk, server_pk) = generate_keypair();
        let (client_sk, client_pk) = generate_keypair();

        server_client_generic(
            move |stream| {
                let enc = EncStream::responder_handshake(stream, &server_sk)
                    .wait()
                    .expect("handshake failed");
                assert_eq!(enc.get_remote_static(), client_pk);
            },
            move |stream| {
                let enc = EncStream::initiatior_handshake(stream, &client_sk)
                    .wait()
                    .expect("handshake failed");
                assert_eq!(enc.get_remote_static(), server_pk);
            },
        );
    }

    #[test]
    fn messages() {
        let (server_sk, _server_pk) = generate_keypair();
        let (client_sk, _client_pk) = generate_keypair();

        let len_to_test: Vec<usize> = vec![0, 65519, 65518];
        let len_to_test_cpy: Vec<usize> = len_to_test.clone();

        server_client_generic(
            move |stream| {
                let mut enc = EncStream::responder_handshake(stream, &server_sk)
                    .wait()
                    .expect("handshake failed");
                let mut buf = [0u8; 65519];
                for i in &len_to_test {
                    let len = enc.recv(&mut buf).wait().expect("recv failed");
                    assert_eq!(len, *i);
                }
            },
            move |stream| {
                let mut enc = EncStream::initiatior_handshake(stream, &client_sk)
                    .wait()
                    .expect("handshake failed");
                for i in &len_to_test_cpy {
                    let _len = enc.send(&[1u8; 65519][..(*i)]).wait().expect("send failed");
                }
            },
        );
    }

    fn server_client_post_handshake<
        ServeF: 'static + Fn(EncStream<Box<dyn Stream>>) + Sync + Send,
        ClientF: 'static + Fn(EncStream<Box<dyn Stream>>) + Sync + Send,
    >(
        sf: ServeF,
        cf: ClientF,
    ) {
        let (server_sk, _server_pk) = generate_keypair();
        let (client_sk, _client_pk) = generate_keypair();

        server_client_generic(
            move |stream| {
                sf(EncStream::responder_handshake(stream, &server_sk)
                    .wait()
                    .unwrap())
            },
            move |stream| {
                cf(EncStream::initiatior_handshake(stream, &client_sk)
                    .wait()
                    .unwrap())
            },
        );
    }

    #[test]
    fn many_bytes() {
        server_client_post_handshake(
            |mut encstream| {
                let mut buf = [0u8; 65519];
                while let Ok(_) = encstream.recv(&mut buf).wait() {}
            },
            |mut encstream| {
                for _ in 0..100 {
                    encstream.send(&[2u8; 65519]).wait().unwrap();
                }
            },
        );
    }

    #[test]
    fn split() {
        // Echo server using split stream
        let iterations = 100;

        server_client_post_handshake(
            move |encstream| {
                // echo server
                let mut buf = [0u8; 65519];
                let (mut inp, mut outp) = encstream.split();
                block_on(async {
                    for _ in 0..iterations {
                        let len = inp.recv(&mut buf).await.expect("server failed to recieve");
                        outp.send(&buf[..len]).await.expect("server failed to send");
                    }
                });
            },
            move |encstream| {
                let (mut inp, mut outp) = encstream.split();
                block_on(join(
                    async {
                        for _ in 0..iterations {
                            outp.send(b"hello").await.unwrap();
                        }
                    },
                    async {
                        let mut buf = [0u8; 65519];
                        for _ in 0..iterations {
                            let len = inp.recv(&mut buf).await.unwrap();
                            assert_eq!(buf[..len], b"hello"[..]);
                        }
                    },
                ));
            },
        );
    }

    // Make sure write and read can happen simultaneously on a split stream.
    #[test]
    fn simultaneous_write() {
        use std::time;

        // Begin write operations on both sides before starting reads

        let iterations = 1_000;

        let write_then_read = move |encstream: EncStream<Box<dyn Stream + 'static>>| {
            let to_send = vec![1u8; 65519];

            let (mut read, mut write) = encstream.split();

            // start write thread
            let wt = thread::spawn(move || {
                for _ in 0..iterations {
                    write.send(&to_send).wait().unwrap();
                }
            });

            // start read thread
            let mut trash = Box::new([0u8; 65519]);
            thread::sleep(time::Duration::from_millis(10));
            for _ in 0..iterations {
                read.recv(&mut trash).wait().unwrap();
            }

            wt.join().expect("write thread failed");
        };

        server_client_post_handshake(write_then_read, write_then_read);

        // When compiled in release mode, this test transfers 247MiBs on my 2015 i7.
        // This implies that noise stream cyphers will not be a bottleneck unless
        // network capacity is on the order of 247MiBs.

        // This test spawns a four threads: server send, server recv, client send,
        // client recv Each thread runs at 60% capacity on my 2015 i7. Syscalls
        // are likely the bottleneck.
    }
}
