use std::convert::TryInto;
use std::io;

// Potential issue, do we need to flush the TcpStream during handshake to speed things up.
// It is prefferrable not to include anything tcp specific so we can be generic over
// io::Read + io::Write. Maybe encourage the user to set tcp stream to immediate mode
// before handshake?
// Wait, flush is defined on the write trait. It's not tcp specific.

struct EncryptedDuplexStream<Stream> {
    underlying: Stream,
    session: snow::Session,
}

impl<Stream: io::Read + io::Write> EncryptedDuplexStream<Stream> {
    pub fn initiatior_handshake(
        mut stream: Stream,
        sk: &SecretKey,
    ) -> io::Result<EncryptedDuplexStream<Stream>> {
        let mut session = builder()
            .local_private_key(&sk.0)
            .build_initiator()
            .unwrap();

        // XX:
        handshake_send(&mut stream, &mut session)?; // -> e
        handshake_recv(&mut stream, &mut session)?; // <- e, ee, s, es
        handshake_send(&mut stream, &mut session)?; // -> s, se

        Ok(EncryptedDuplexStream {
            underlying: stream,
            session: session
                .into_transport_mode()
                .map_err(|_| io::Error::from(io::ErrorKind::Other))?,
        })
    }

    pub fn responder_handshake(
        mut stream: Stream,
        sk: &SecretKey,
    ) -> io::Result<EncryptedDuplexStream<Stream>> {
        let mut session = builder()
            .local_private_key(&sk.0)
            .build_responder()
            .unwrap();

        // XX:
        handshake_recv(&mut stream, &mut session)?; // -> e
        handshake_send(&mut stream, &mut session)?; // <- e, ee, s, es
        handshake_recv(&mut stream, &mut session)?; // -> s, se

        Ok(EncryptedDuplexStream {
            underlying: stream,
            session: session
                .into_transport_mode()
                .map_err(|_| io::Error::from(io::ErrorKind::Other))?,
        })
    }

    /// Get the static public key of remote host
    fn get_remote_static(&self) -> PublicKey {
        PublicKey::from_slice(self.session.get_remote_static().unwrap())
    }

    /// Encrypt and send one snow message.
    ///
    /// # Panics
    ///
    /// panics if buf.len() > 65535
    fn send(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut encbuf = [0u8; 65535];
        let len = self
            .session
            .write_message(buf, &mut encbuf)
            .map_err(|_| io::Error::from(io::ErrorKind::Other))?;
        put_message(&mut self.underlying, &encbuf[..len])
    }

    /// Recive one entire snow message.
    fn recv(&mut self, buf: &mut [u8; 65535]) -> io::Result<usize> {
        let mut encbuf = [0u8; 65535];
        let enclen = get_message(&mut self.underlying, &mut encbuf)?;
        self.session
            .read_message(&encbuf[..enclen], buf)
            .map_err(|_| io::Error::from(io::ErrorKind::Other))
    }
}

pub struct SecretKey([u8; 32]);

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

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct PublicKey([u8; 32]);

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
    snow::Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
}

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let kp = builder().generate_keypair().unwrap();
    (
        SecretKey::from_slice(&kp.private),
        PublicKey::from_slice(&kp.public),
    )
}

fn get_message<Stream: io::Read + io::Write>(
    stream: &mut Stream,
    buf: &mut [u8; 65535],
) -> io::Result<usize> {
    let mut two_bytes = [0u8; 2];
    stream.read_exact(&mut two_bytes)?;
    let len = u16::from_be_bytes(two_bytes) as usize;
    stream.read_exact(&mut buf[..len])?;
    Ok(len)
}

/// # Panics
///
/// panics if buf.len() > 65535
fn put_message<Stream: io::Read + io::Write>(stream: &mut Stream, buf: &[u8]) -> io::Result<()> {
    let len: u16 = buf.len().try_into().unwrap();
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&buf)?;
    Ok(())
}

// read message and drop payload if any
// used when executing noise protocol handshake
fn handshake_recv<Stream: io::Read + io::Write>(
    stream: &mut Stream,
    session: &mut snow::Session,
) -> io::Result<()> {
    debug_assert!(is_handshake_state(session));
    let mut buf = [0u8; 65535];
    let mut throw_away = [0u8; 65535];
    let len = get_message(stream, &mut buf)?;
    session
        .read_message(&buf[..len], &mut throw_away)
        .map_err(|_| io::Error::from(io::ErrorKind::Other))
        .map(|_| ())
}

fn handshake_send<Stream: io::Read + io::Write>(
    stream: &mut Stream,
    session: &mut snow::Session,
) -> io::Result<()> {
    debug_assert!(is_handshake_state(session));
    let mut buf = [0u8; 65535];
    let len = session
        .write_message(&[], &mut buf)
        .map_err(|_| io::Error::from(io::ErrorKind::Other))?;
    put_message(stream, &buf[..len])?;
    stream.flush()
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
    use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
    use std::thread;

    fn server_client<
        ServeF: 'static + Fn(TcpListener) + Sync + Send,
        ClientF: 'static + Fn(SocketAddr) + Sync + Send,
    >(
        sf: ServeF,
        cf: ClientF,
    ) {
        // listen on loopback on ephemeral port
        let listener = TcpListener::bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0)).unwrap();
        // get listen address
        let listener_addr = listener.local_addr().unwrap();
        // start server thread listening on listener
        let server = thread::spawn(move || sf(listener));

        // start client thread with address to serve
        cf(listener_addr);

        server.join().unwrap();
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
                let tcpstream = listener.accept().unwrap().0;
                sf(Box::new(tcpstream));
            },
            move |listener_addr| {
                let tcpstream = TcpStream::connect(listener_addr).unwrap();
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
                let enc = EncryptedDuplexStream::responder_handshake(stream, &server_sk).unwrap();
                assert_eq!(enc.get_remote_static(), client_pk);
            },
            move |stream| {
                let enc = EncryptedDuplexStream::initiatior_handshake(stream, &client_sk).unwrap();
                assert_eq!(enc.get_remote_static(), server_pk);
            },
        );
    }

    #[test]
    fn messages() {
        let (server_sk, _server_pk) = generate_keypair();
        let (client_sk, _client_pk) = generate_keypair();

        let len_to_test: Vec<u16> = vec![0u16, 0u16, 65535u16, 65535u16, 65534u16];
        let len_to_test_cpy: Vec<u16> = len_to_test.clone();

        server_client_generic(
            move |stream| {
                let mut enc =
                    EncryptedDuplexStream::responder_handshake(stream, &server_sk).unwrap();
                let mut buf = [0u8; 65535];
                for i in &len_to_test {
                    println!("{}", i);
                    let len = enc.recv(&mut buf).unwrap();
                    assert_eq!(len, *i as usize);
                }
            },
            move |stream| {
                let mut enc =
                    EncryptedDuplexStream::initiatior_handshake(stream, &client_sk).unwrap();
                for i in &len_to_test_cpy {
                    let _len = enc.send(&[1u8; 65535][..(*i as usize)]).unwrap();
                }
            },
        );
    }
}
