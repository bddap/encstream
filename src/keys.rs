use crate::builder::builder;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    /// # Panics
    ///
    /// panics if slice.len() is not 32
    pub fn from_slice(slice: &[u8]) -> Self {
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
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut ret = [0u8; 32];
        ret.copy_from_slice(slice);
        Self(ret)
    }
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
