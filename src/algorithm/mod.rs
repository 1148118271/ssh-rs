pub(crate) mod encryption;
pub(crate) mod hash;
pub(crate) mod key_exchange;
pub(crate) mod mac;
pub(crate) mod public_key;

use crate::constant::algorithms as constant;

use self::{hash::HashCtx, key_exchange::KeyExchange};

#[derive(Copy, Clone, PartialEq, Eq)]
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

    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s {
            constant::enc::CHACHA20_POLY1305_OPENSSH => Some(Enc::Chacha20Poly1305Openssh),
            constant::enc::AES128_CTR => Some(Enc::Aes128Ctr),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
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

    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s {
            constant::kex::CURVE25519_SHA256 => Some(Kex::Curve25519Sha256),
            constant::kex::ECDH_SHA2_NISTP256 => Some(Kex::EcdhSha2Nistrp256),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum PubKey {
    SshEd25519,
    #[cfg(feature = "dangerous-rsa-sha1")]
    SshRsa,
    RsaSha2_256,
    RsaSha2_512,
}

impl PubKey {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            PubKey::SshEd25519 => constant::pubkey::SSH_ED25519,
            #[cfg(feature = "dangerous-rsa-sha1")]
            PubKey::SshRsa => constant::pubkey::SSH_RSA,
            PubKey::RsaSha2_256 => constant::pubkey::RSA_SHA2_256,
            PubKey::RsaSha2_512 => constant::pubkey::RSA_SHA2_512,
        }
    }

    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s {
            constant::pubkey::SSH_ED25519 => Some(PubKey::SshEd25519),
            #[cfg(feature = "dangerous-rsa-sha1")]
            constant::pubkey::SSH_RSA => Some(PubKey::SshRsa),
            constant::pubkey::RSA_SHA2_256 => Some(PubKey::RsaSha2_256),
            constant::pubkey::RSA_SHA2_512 => Some(PubKey::RsaSha2_512),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Mac {
    HmacSha1,
    HmacSha2_256,
    HmacSha2_512,
}

impl Mac {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Mac::HmacSha1 => constant::mac::HMAC_SHA1,
            Mac::HmacSha2_256 => constant::mac::HMAC_SHA2_256,
            Mac::HmacSha2_512 => constant::mac::HMAC_SHA2_512,
        }
    }

    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s {
            constant::mac::HMAC_SHA1 => Some(Mac::HmacSha1),
            constant::mac::HMAC_SHA2_256 => Some(Mac::HmacSha2_256),
            constant::mac::HMAC_SHA2_512 => Some(Mac::HmacSha2_512),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Compress {
    None,
}

impl Compress {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Compress::None => constant::compress::NONE,
        }
    }

    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s {
            constant::compress::NONE => Some(Compress::None),
            _ => None,
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
