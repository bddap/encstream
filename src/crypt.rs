//! decrypt and encrypt messages from and to AsyncRead and AsyncWrite streams

use crate::fragment::{read_noise, write_noise};
use either::Either;
use futures::{AsyncRead, AsyncWrite};
use snow::{error::SnowError, Session};
use std::io;

pub async fn encrypt_write<'a, W: AsyncWrite + Unpin>(
    w: &'a mut W,
    session: &'a mut Session,
    plaintext: &'a [u8],
) -> Result<(), io::Error> {
    assert!(plaintext.len() <= 65519);
    let mut buf = [0u8; 65535];
    let len = session
        .write_message(plaintext, &mut buf)
        .expect("Output exceeded the max message length for the Noise Protocol (65535 bytes).");
    write_noise(w, &buf[..len]).await
}

pub async fn decrypt_read<'a, R: AsyncRead + Unpin>(
    r: &'a mut R,
    session: &'a mut Session,
    plaintext: &'a mut [u8; 65519],
) -> Result<usize, Either<io::Error, SnowError>> {
    let mut buf = [0u8; 65535];
    let len = read_noise(r, &mut buf).await.map_err(Either::Left)?;
    session
        .read_message(&buf[..len], &mut plaintext[..])
        .map_err(Either::Right)
}
