pub(crate) mod encryption;
pub(crate) mod hash;
pub(crate) mod key_exchange;
pub(crate) mod mac;
pub(crate) mod public_key;

use crate::constant::algorithms as constant;

use self::{hash::HashCtx, key_exchange::KeyExchange};

pub enum Enc {
    Chacha20Poly1305Openssh,
    Aes128Ctr,
}

impl Enc {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Enc::Chacha20Poly1305Openssh => constant::enc::CHACHA20_POLY1305_OPENSSH,
            Enc::Aes128Ctr => constant::enc::AES128_CTR,
        }
    }
}
pub enum Kex {
    Curve25519Sha256,
    EcdhSha2Nistrp256,
}

impl Kex {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Kex::Curve25519Sha256 => constant::kex::CURVE25519_SHA256,
            Kex::EcdhSha2Nistrp256 => constant::kex::ECDH_SHA2_NISTP256,
        }
    }
}

pub enum PubKey {
    SshEd25519,
    #[cfg(feature = "dangerous-rsa-sha1")]
    SshRsa,
    RsaSha2_256,
}

impl PubKey {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            PubKey::SshEd25519 => constant::pubkey::SSH_ED25519,
            #[cfg(feature = "dangerous-rsa-sha1")]
            PubKey::SshRsa => constant::pubkey::SSH_RSA,
            PubKey::RsaSha2_256 => constant::pubkey::RSA_SHA2_256,
        }
    }
}

pub enum Mac {
    HmacSha1,
}

impl Mac {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Mac::HmacSha1 => constant::mac::HMAC_SHA1,
        }
    }
}

pub enum Compress {
    None,
}

impl Compress {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Compress::None => constant::compress::NONE,
        }
    }
}

#[derive(Default)]
pub(crate) struct Digest {
    pub hash_ctx: HashCtx,
    pub key_exchange: Option<Box<dyn KeyExchange>>,
}

impl Digest {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}
