pub(crate) mod encryption;
pub(crate) mod hash;
pub(crate) mod key_exchange;
pub(crate) mod mac;
pub(crate) mod public_key;

use crate::constant::algorithms;

pub enum Enc {
    Chacha20Poly1305Openssh,
    Aes128Ctr,
}

impl Enc {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Enc::Chacha20Poly1305Openssh => algorithms::enc::CHACHA20_POLY1305_OPENSSH,
            Enc::Aes128Ctr => algorithms::enc::AES128_CTR,
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
            Kex::Curve25519Sha256 => algorithms::kex::CURVE25519_SHA256,
            Kex::EcdhSha2Nistrp256 => algorithms::kex::ECDH_SHA2_NISTP256,
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
            PubKey::SshEd25519 => algorithms::pubkey::SSH_ED25519,
            #[cfg(feature = "dangerous-rsa-sha1")]
            PubKey::SshRsa => algorithms::pubkey::SSH_RSA,
            PubKey::RsaSha2_256 => algorithms::pubkey::RSA_SHA2_256,
        }
    }
}

pub enum Mac {
    HmacSha1,
}

impl Mac {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Mac::HmacSha1 => algorithms::mac::HMAC_SHA1,
        }
    }
}

pub enum Compress {
    None,
}

impl Compress {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Compress::None => algorithms::compress::NONE,
        }
    }
}
