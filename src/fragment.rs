//! read and write noise protocol messages to AsyncRead and AsyncWrite streams

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::convert::TryInto;
use std::io;

pub async fn write_noise<'a, W: AsyncWrite + Unpin>(
    w: &'a mut W,
    message: &'a [u8],
) -> Result<(), io::Error> {
    assert!(message.len() <= 65535);
    let len: u16 = message.len().try_into().unwrap();
    let mut buf = [0u8; 65537];
    buf[..2].copy_from_slice(&len.to_be_bytes());
    buf[2..message.len() + 2].copy_from_slice(&message);
    w.write_all(&buf[..message.len() + 2]).await
}

pub async fn read_noise<'a, R: AsyncRead + Unpin>(
    r: &'a mut R,
    message: &'a mut [u8; 65535],
) -> Result<usize, io::Error> {
    let mut len_bytes = [0u8; 2];
    r.read_exact(&mut len_bytes[..]).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;
    r.read_exact(&mut message[..len]).await?;
    Ok(len)
}
