use crate::algorithm::hash;
use crate::algorithm::hash::HashType;
use crate::data::Data;
use crate::h::H;
use crate::{SshError, SshResult};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::PublicKeyParts;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Clone, Default)]
pub struct KeyPair {
    pub(crate) private_key: String,
    pub(crate) key_type: KeyPairType,
    pub(crate) blob: Vec<u8>,
}

impl KeyPair {
    pub fn new() -> Self {
        KeyPair {
            ..Default::default()
        }
    }

    pub fn from_path<P: AsRef<Path>>(key_path: P, key_type: KeyPairType) -> SshResult<Self> {
        let mut file = File::open(key_path).unwrap();
        let mut prks = String::new();
        file.read_to_string(&mut prks)?;
        KeyPair::from_str(&prks, key_type)
    }

    pub fn from_str(key_str: &str, key_type: KeyPairType) -> SshResult<Self> {
        let rprk = match rsa::RsaPrivateKey::from_pkcs1_pem(key_str) {
            Ok(e) => e,
            Err(e) => return Err(SshError::from(e.to_string())),
        };
        let rpuk = rprk.to_public_key();
        let es = rpuk.e().to_bytes_be();
        let ns = rpuk.n().to_bytes_be();
        let mut blob = Data::new();
        blob.put_str(key_type.as_str());
        blob.put_mpint(&es);
        blob.put_mpint(&ns);
        let blob = blob.to_vec();
        let pair = KeyPair {
            private_key: key_str.to_string(),
            key_type,
            blob,
        };
        Ok(pair)
    }

    pub fn get_blob(&self) -> Vec<u8> {
        self.blob.to_vec()
    }

    pub(crate) fn signature(&self, buf: &[u8], h: H, hash_type: HashType) -> Vec<u8> {
        let session_id = hash::digest(h.as_bytes().as_slice(), hash_type);
        let mut sd = Data::new();
        sd.put_u8s(session_id.as_slice());
        sd.extend_from_slice(buf);
        let (scheme, digest) = match self.key_type {
            KeyPairType::SshRsa => (
                rsa::PaddingScheme::new_pkcs1v15_sign::<sha2::Sha256>(),
                ring::digest::digest(&ring::digest::SHA256, sd.as_slice()),
            ),
            #[cfg(feature = "dangerous-rsa-sha1")]
            KeyPairType::SshRsaSha1 => (
                rsa::PaddingScheme::new_pkcs1v15_sign::<sha1::Sha1>(),
                ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, sd.as_slice()),
            ),
        };
        let msg = digest.as_ref();

        let rprk = rsa::RsaPrivateKey::from_pkcs1_pem(self.private_key.as_str()).unwrap();

        let sign = rprk.sign(scheme, msg).unwrap();
        let mut ss = Data::new();
        ss.put_str(self.key_type.as_str());
        ss.put_u8s(sign.as_slice());
        ss.to_vec()
    }
}

#[derive(Clone)]
pub enum KeyPairType {
    SshRsa,
    #[cfg(feature = "dangerous-rsa-sha1")]
    SshRsaSha1,
}

impl Default for KeyPairType {
    fn default() -> Self {
        KeyPairType::SshRsa
    }
}

impl KeyPairType {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            // use to rsa-sha2-256 by default according to
            // https://www.rfc-editor.org/rfc/rfc8332#section-3
            KeyPairType::SshRsa => crate::constant::algorithms::pubkey::RSA_SHA2_256,
            #[cfg(feature = "dangerous-rsa-sha1")]
            KeyPairType::SshRsaSha1 => crate::constant::algorithms::pubkey::SSH_RSA,
        }
    }
}
