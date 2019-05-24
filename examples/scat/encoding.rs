use encstream::PublicKey;
use hex::{decode, encode, FromHexError};

pub fn pk_from_hex(src: &str) -> Result<PublicKey, ParseErr> {
    parse_as_array32(src).map(PublicKey)
}

pub fn pk_to_hex(pk: &PublicKey) -> String {
    encode(&pk.0)
}

fn parse_as_array32(src: &str) -> Result<[u8; 32], ParseErr> {
    decode(src)
        .map_err(std::convert::Into::into)
        .and_then(vec_to_array32)
}

fn vec_to_array32(bytes: Vec<u8>) -> Result<[u8; 32], ParseErr> {
    if bytes.len() != 32 {
        Err(ParseErr::BadLength)
    } else {
        let mut slice = [0; 32];
        for (i, byte) in bytes.iter().enumerate() {
            slice[i] = *byte;
        }
        Ok(slice)
    }
}

#[derive(Debug)]
pub enum ParseErr {
    InvalidHex,
    BadLength,
}

impl ToString for ParseErr {
    fn to_string(&self) -> String {
        match self {
            ParseErr::InvalidHex => "ParseErr".into(),
            ParseErr::BadLength => "BadLength".into(),
        }
    }
}

impl From<FromHexError> for ParseErr {
    fn from(_other: FromHexError) -> Self {
        ParseErr::InvalidHex
    }
}
