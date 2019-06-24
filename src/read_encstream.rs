use core::ops::Deref;
use futures::try_ready;
use futures::AsyncRead;
use std::convert::TryInto;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Context;
use std::task::Poll;

/// Sent as the first byte of encrypted payload when the stream is done. This
/// tag is encrypted to mitigate early termination attacks.
/// See http://www.noiseprotocol.org/noise.html#application-responsibilities
/// This tag may be present even when the payload contains data.
/// The presence of this tag indicates no more frames will be sent.
const END_OF_STREAM: u8 = 0;

/// More frames may follow.
const CONTINUE_STREAM: u8 = 1;

pub struct ReadEncStream<S> {
    encstream: S,
    cypherbuf: CryptBuf,
    plainbuf: Buf,
    session: Arc<Mutex<snow::Session>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for ReadEncStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        while self.plainbuf.empty() {
            // fill cyphertext to tagged length
            try_ready!(self.fill_cypherbuf(ctx));

            // decrypt into plaintext
            if self.decrypt().is_err() {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
        }
        Poll::Ready(Ok(self.plainbuf.drain_into(buf)))
    }
}

impl<S> ReadEncStream<S> {
    /// Create new Encrypted Read Stream, it is assumed that session handshake
    /// is already complete and that session is in transport mode. If session is
    /// not in transport mode, errors will occur later.
    pub(crate) fn new_post_handshake(s: S, session: Arc<Mutex<snow::Session>>) -> ReadEncStream<S> {
        assert!(is_transport_state(&session.lock().unwrap()));
        Self {
            encstream: s,
            cypherbuf: CryptBuf::new(),
            plainbuf: Buf::new(),
            session,
        }
    }

    fn decrypt(&mut self) -> Result<(), snow::error::SnowError> {
        let mut session = self.session.lock().expect("Noise session poisioned.");
        self.cypherbuf
            .decrypt_into(&mut self.plainbuf, &mut session)
    }

    /// Read from underlying into cypherbuf
    fn fill_cypherbuf(&mut self, ctx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin,
    {
        self.cypherbuf.fill(&mut self.encstream, ctx)
    }
}

/// A plaintext buffer
struct Buf {
    buf: Box<[u8]>,
    len: usize,
}

impl Buf {
    fn new() -> Buf {
        Buf {
            buf: vec![0u8; 2usize.pow(16)].into_boxed_slice(), /* enough len for a 16 bit tag
                                                                * then a payload */
            len: 0,
        }
    }

    /// dump as many bytes from self as possible into target, return number of
    /// bytes dumped
    fn drain_into(&mut self, target: &mut [u8]) -> usize {
        let will_drain = usize::min(self.len(), target.len());
        target[..will_drain].copy_from_slice(&self.buf[..will_drain]);
        self.buf.rotate_left(will_drain);
        self.len -= will_drain;
        will_drain
    }

    fn empty(&self) -> bool {
        self.len == 0
    }
}

impl Deref for Buf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
}

/// A cyphertext buffer
struct CryptBuf {
    buf: Box<[u8]>, // the first two bytes of cryptbuf are a target length tag
    len: usize,     // Number of filled bytes, including the target length prefix
}

impl CryptBuf {
    fn new() -> CryptBuf {
        CryptBuf {
            buf: vec![0u8; 2 + 2usize.pow(16)].into_boxed_slice(), /* enough len for a 16 bit tag
                                                                    * then a payload */
            len: 0,
        }
    }

    fn fill<S: AsyncRead + Unpin>(
        &mut self,
        s: &mut S,
        ctx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.len < 2 {
            try_ready!(self.fill_to(s, ctx, 2));
        }
        let mut len_buf = [0u8; 2];
        len_buf[0] = self.buf[0];
        len_buf[1] = self.buf[1];
        let len = u16::from_be_bytes(len_buf) as usize;
        self.fill_to(s, ctx, len + 2)
    }

    /// Fill buffer until len is exactly target_len
    fn fill_to<S: AsyncRead + Unpin>(
        &mut self,
        s: &mut S,
        ctx: &mut Context<'_>,
        target_len: usize,
    ) -> Poll<io::Result<()>> {
        while self.len < target_len {
            let count = try_ready!(poll_read(s, ctx, &mut self.buf[self.len..target_len]));
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.len += count;
        }
        debug_assert!(self.len == target_len);
        Poll::Ready(Ok(()))
    }

    fn empty(&self) -> bool {
        self.len() == 0
    }

    fn clear(&mut self) {
        self.len = 0
    }

    fn decrypt_into(
        &mut self,
        target: &mut Buf,
        session: &mut snow::Session,
    ) -> Result<(), snow::error::SnowError> {
        debug_assert!(target.empty());
        let len = session.read_message(&self, &mut target.buf)?;
        target.len = len
            .try_into()
            .expect("snow decrypted more bytes than was available in the target buffer");
        self.clear();
        Ok(())
    }
}

impl Deref for CryptBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        if self.len <= 2 {
            &[]
        } else {
            &self.buf[2..self.len]
        }
    }
}

/// borowck workaround moves r into a Pin to call AsyncRead::poll_read
fn poll_read(
    r: &mut (impl AsyncRead + Unpin),
    cx: &mut Context<'_>,
    buf: &mut [u8],
) -> Poll<io::Result<usize>> {
    Pin::new(r).poll_read(cx, buf)
}

fn is_transport_state(session: &snow::Session) -> bool {
    match session {
        snow::Session::Transport(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;
    use crate::EncStream;
    use futures::executor::block_on;
    use futures::AsyncReadExt;
    use futures::AsyncWrite;
    use futures::Future;
    use futures_util::stream::StreamExt;
    use romio::TcpListener;
    use romio::TcpStream;
    use std::net::Ipv6Addr;
    use std::net::SocketAddr;
    use std::thread;

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
    fn recv() {
        const XFR: usize = 65519 + 2;

        let to_send: Vec<u8> = (0..XFR)
            .map(|n| (n % (2usize.pow(8))).try_into().unwrap())
            .collect();
        let to_send_copy: Vec<u8> = (0..XFR)
            .map(|n| (n % (2usize.pow(8))).try_into().unwrap())
            .collect();

        server_client_generic(
            move |stream| {
                // Do handshake
                let mut enc = EncStream::responder_handshake(stream, &generate_keypair().0)
                    .wait()
                    .expect("server handshake failed");

                // send XFR bytes
                for subslice in to_send.chunks(65519) {
                    enc.send(subslice).wait().expect("server failed to send");
                }
            },
            move |stream| {
                // Do handshake
                let enc = EncStream::initiatior_handshake(stream, &generate_keypair().0)
                    .wait()
                    .expect("client handshake failed");

                // Grab read stream
                let mut read_stream = enc.streams().0;

                let mut buf = Vec::with_capacity(XFR);

                // read XFR bytes
                read_stream.read_to_end(&mut buf).wait().unwrap();

                assert_eq!(buf, to_send_copy);
            },
        );
    }
}
