use either::Either;
use serde::{Deserialize, Serialize};
use snow::error::SnowError;
use std::convert::TryInto;
use std::io;

/// Wrapper around A stream implementing io::Read and io::Write.
/// Data written to EncryptedDuplexStream is encrypted.
pub struct EncryptedDuplexStream<Stream> {
    underlying: Stream,
    session: snow::Session,
}

impl<Stream: io::Read + io::Write> EncryptedDuplexStream<Stream> {
    pub fn initiatior_handshake(
        mut stream: Stream,
        sk: &SecretKey,
    ) -> Result<EncryptedDuplexStream<Stream>, Either<io::Error, SnowError>> {
        let mut session = builder()
            .local_private_key(&sk.0)
            .build_initiator()
            .expect("build initiatior failed");

        // XX:
        handshake_send(&mut stream, &mut session)?; // -> e
        handshake_recv(&mut stream, &mut session)?; // <- e, ee, s, es
        handshake_send(&mut stream, &mut session)?; // -> s, se

        Ok(EncryptedDuplexStream {
            underlying: stream,
            session: session.into_transport_mode().map_err(Either::Right)?,
        })
    }

    pub fn responder_handshake(
        mut stream: Stream,
        sk: &SecretKey,
    ) -> Result<EncryptedDuplexStream<Stream>, Either<io::Error, SnowError>> {
        let mut session = builder()
            .local_private_key(&sk.0)
            .build_responder()
            .expect("build responder failed");

        // XX:
        handshake_recv(&mut stream, &mut session)?; // -> e
        handshake_send(&mut stream, &mut session)?; // <- e, ee, s, es
        handshake_recv(&mut stream, &mut session)?; // -> s, se

        Ok(EncryptedDuplexStream {
            underlying: stream,
            session: session.into_transport_mode().map_err(Either::Right)?,
        })
    }
}

impl<T> EncryptedDuplexStream<T> {
    /// Get the static public key of remote host
    pub fn get_remote_static(&self) -> PublicKey {
        PublicKey::from_slice(
            self.session
                .get_remote_static()
                .expect("remote static key not set"),
        )
    }
}

impl<W: io::Write> EncryptedDuplexStream<W> {
    /// Encrypt and send one snow message.
    ///
    /// # Panics
    ///
    /// panics if buf.len() > 65535 - 16
    pub fn send(&mut self, buf: &[u8]) -> Result<(), Either<io::Error, SnowError>> {
        assert!(buf.len() <= 65535 - 16);
        let mut encbuf = [0u8; 65535];
        let len = self
            .session
            .write_message(buf, &mut encbuf)
            .map_err(Either::Right)?;
        debug_assert_eq!(len, buf.len() + 16);
        put_message(&mut self.underlying, &encbuf[..len]).map_err(Either::Left)
    }
}

impl<R: io::Read> EncryptedDuplexStream<R> {
    /// Recive one entire snow message.
    pub fn recv(&mut self, buf: &mut [u8; 65519]) -> Result<usize, Either<io::Error, SnowError>> {
        let mut encbuf = [0u8; 65535];
        let enclen = get_message(&mut self.underlying, &mut encbuf).map_err(Either::Left)?;
        self.session
            .read_message(&encbuf[..enclen], buf)
            .map_err(Either::Right)
    }
}

#[derive(Serialize, Deserialize)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    /// # Panics
    ///
    /// panics if slice.len() is not 32
    fn from_slice(slice: &[u8]) -> Self {
        let mut ret = [0u8; 32];
        ret.copy_from_slice(slice);
        Self(ret)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// # Panics
    ///
    /// panics if slice.len() is not 32
    fn from_slice(slice: &[u8]) -> Self {
        let mut ret = [0u8; 32];
        ret.copy_from_slice(slice);
        Self(ret)
    }
}

fn builder() -> snow::Builder<'static> {
    snow::Builder::new(
        "Noise_XX_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .expect("failed to parse noise protocol description"),
    )
}

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let kp = builder()
        .generate_keypair()
        .expect("gernerate keypair failed");
    (
        SecretKey::from_slice(&kp.private),
        PublicKey::from_slice(&kp.public),
    )
}

fn get_message<R: io::Read>(stream: &mut R, buf: &mut [u8; 65535]) -> io::Result<usize> {
    let mut two_bytes = [0u8; 2];
    stream.read_exact(&mut two_bytes)?;
    let len = u16::from_be_bytes(two_bytes) as usize;
    stream.read_exact(&mut buf[..len])?;
    Ok(len)
}

/// # Panics
///
/// panics if buf.len() > 65535
fn put_message<W: io::Write>(stream: &mut W, buf: &[u8]) -> io::Result<()> {
    let len: u16 = buf.len().try_into().expect("buffer too large");
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&buf)?;
    Ok(())
}

// read message and drop payload if any
// used when executing noise protocol handshake
fn handshake_recv<R: io::Read>(
    stream: &mut R,
    session: &mut snow::Session,
) -> Result<(), Either<io::Error, SnowError>> {
    debug_assert!(is_handshake_state(session));
    let mut buf = [0u8; 65535];
    let mut throw_away = [0u8; 65535];
    let len = get_message(stream, &mut buf).map_err(Either::Left)?;
    session
        .read_message(&buf[..len], &mut throw_away)
        .map_err(Either::Right)
        .map(|_| ())
}

fn handshake_send<W: io::Write>(
    stream: &mut W,
    session: &mut snow::Session,
) -> Result<(), Either<io::Error, SnowError>> {
    debug_assert!(is_handshake_state(session));
    let mut buf = [0u8; 65535];
    let len = session
        .write_message(&[], &mut buf)
        .map_err(Either::Right)?;
    put_message(stream, &buf[..len]).map_err(Either::Left)?;
    stream.flush().map_err(Either::Left)
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
    use std::io;
    use std::net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream};
    use std::thread;

    fn server_client<
        ServeF: 'static + Fn(TcpListener) + Sync + Send,
        ClientF: 'static + Fn(SocketAddr) + Sync + Send,
    >(
        sf: ServeF,
        cf: ClientF,
    ) {
        // listen on loopback on ephemeral port
        let listener = TcpListener::bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0))
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

    trait Stream: io::Read + io::Write {}

    impl Stream for TcpStream {}

    fn server_client_generic<
        ServeF: 'static + Fn(Box<Stream>) + Sync + Send,
        ClientF: 'static + Fn(Box<Stream>) + Sync + Send,
    >(
        sf: ServeF,
        cf: ClientF,
    ) {
        // we use tcp just because it's easy
        server_client(
            move |listener| {
                let tcpstream = listener
                    .accept()
                    .expect("server received no connection or accept failed")
                    .0;
                sf(Box::new(tcpstream));
            },
            move |listener_addr| {
                let tcpstream =
                    TcpStream::connect(listener_addr).expect("client failed to connect to server");
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
                let enc = EncryptedDuplexStream::responder_handshake(stream, &server_sk)
                    .expect("handshake failed");
                assert_eq!(enc.get_remote_static(), client_pk);
            },
            move |stream| {
                let enc = EncryptedDuplexStream::initiatior_handshake(stream, &client_sk)
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
                let mut enc = EncryptedDuplexStream::responder_handshake(stream, &server_sk)
                    .expect("handshake failed");
                let mut buf = [0u8; 65519];
                for i in &len_to_test {
                    let len = enc.recv(&mut buf).expect("recv failed");
                    assert_eq!(len, *i);
                }
            },
            move |stream| {
                let mut enc = EncryptedDuplexStream::initiatior_handshake(stream, &client_sk)
                    .expect("handshake failed");
                for i in &len_to_test_cpy {
                    let _len = enc.send(&[1u8; 65519][..(*i)]).expect("send failed");
                }
            },
        );
    }

    fn server_client_post_handshake<
        ServeF: 'static + Fn(EncryptedDuplexStream<Box<Stream>>) + Sync + Send,
        ClientF: 'static + Fn(EncryptedDuplexStream<Box<Stream>>) + Sync + Send,
    >(
        sf: ServeF,
        cf: ClientF,
    ) {
        let (server_sk, _server_pk) = generate_keypair();
        let (client_sk, _client_pk) = generate_keypair();

        server_client_generic(
            move |stream| {
                sf(EncryptedDuplexStream::responder_handshake(stream, &server_sk).unwrap())
            },
            move |stream| {
                cf(EncryptedDuplexStream::initiatior_handshake(stream, &client_sk).unwrap())
            },
        );
    }

    #[test]
    fn many_bytes() {
        server_client_post_handshake(
            |mut encstream| {
                let mut buf = [0u8; 65519];
                while let Ok(_) = encstream.recv(&mut buf) {}
            },
            |mut encstream| {
                for _ in 0..100 {
                    encstream.send(&[2u8; 65519]).unwrap();
                }
            },
        );
    }
}
