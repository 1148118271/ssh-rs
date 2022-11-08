use std::fmt::Debug;

use crate::algorithm::hash::HashType;
use crate::data::Data;
use crate::h::H;
use crate::{algorithm::hash, constant::algorithms};
use crate::{SshError, SshResult};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::PublicKeyParts;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Clone, Default)]
pub struct KeyPair {
    pub(crate) private_key: String,
    pub(crate) _key_type: KeyType,
}

impl KeyPair {
    pub fn from_path<P: AsRef<Path>>(key_path: P, key_type: KeyType) -> SshResult<Self> {
        let mut file = match File::open(key_path) {
            Ok(file) => file,
            Err(e) => return Err(SshError::from(e.to_string())),
        };
        let mut prks = String::new();
        file.read_to_string(&mut prks)?;
        KeyPair::from_str(&prks, key_type)
    }

    pub fn from_str(key_str: &str, key_type: KeyType) -> SshResult<Self> {
        // first validate the key
        let _rprk = match rsa::RsaPrivateKey::from_pkcs1_pem(key_str) {
            Ok(e) => e,
            Err(e) => return Err(SshError::from(e.to_string())),
        };

        // then store it
        let pair = KeyPair {
            private_key: key_str.to_string(),
            _key_type: key_type,
        };
        Ok(pair)
    }

    pub fn get_blob(&self, alg: &str) -> Vec<u8> {
        // already valid key string, just unwrap it.
        let rprk = rsa::RsaPrivateKey::from_pkcs1_pem(&self.private_key).unwrap();
        let rpuk = rprk.to_public_key();
        let es = rpuk.e().to_bytes_be();
        let ns = rpuk.n().to_bytes_be();
        let mut blob = Data::new();
        blob.put_str(alg);
        blob.put_mpint(&es);
        blob.put_mpint(&ns);
        blob.to_vec()
    }

    pub(crate) fn signature(&self, buf: &[u8], h: H, hash_type: HashType, alg: &str) -> Vec<u8> {
        let session_id = hash::digest(h.as_bytes().as_slice(), hash_type);
        let mut sd = Data::new();
        sd.put_u8s(session_id.as_slice());
        sd.extend_from_slice(buf);
        let (scheme, digest) = match alg {
            algorithms::pubkey::RSA_SHA2_256 => (
                rsa::PaddingScheme::new_pkcs1v15_sign::<sha2::Sha256>(),
                ring::digest::digest(&ring::digest::SHA256, sd.as_slice()),
            ),
            #[cfg(feature = "dangerous-rsa-sha1")]
            algorithms::pubkey::SSH_RSA => (
                rsa::PaddingScheme::new_pkcs1v15_sign::<sha1::Sha1>(),
                ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, sd.as_slice()),
            ),
            _ => todo!(),
        };
        let msg = digest.as_ref();

        let rprk = rsa::RsaPrivateKey::from_pkcs1_pem(self.private_key.as_str()).unwrap();

        let sign = rprk.sign(scheme, msg).unwrap();
        let mut ss = Data::new();
        ss.put_str(alg);
        ss.put_u8s(sign.as_slice());
        ss.to_vec()
    }
}

#[derive(Clone)]
pub enum KeyType {
    SshRsa,
}

impl Default for KeyType {
    fn default() -> Self {
        KeyType::SshRsa
    }
}

#[derive(Clone, Default)]
pub(crate) struct AuthInfo {
    pub username: String,
    pub password: String,
    pub key_pair: Option<KeyPair>,
}

impl Debug for AuthInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "username: {}", self.username)?;
        Ok(())
    }
}

impl AuthInfo {
    pub fn username<U>(&mut self, u: U) -> SshResult<()>
    where
        U: ToString,
    {
        self.username = u.to_string();
        Ok(())
    }

    pub fn password<P>(&mut self, p: P) -> SshResult<()>
    where
        P: ToString,
    {
        self.password = p.to_string();
        Ok(())
    }

    pub fn private_key<K>(&mut self, k: K) -> SshResult<()>
    where
        K: ToString,
    {
        self.key_pair = Some((KeyPair::from_str(&k.to_string(), KeyType::SshRsa))?);
        Ok(())
    }

    pub fn private_key_path<P>(&mut self, p: P) -> SshResult<()>
    where
        P: AsRef<Path>,
    {
        self.key_pair = Some((KeyPair::from_path(p, KeyType::SshRsa))?);
        Ok(())
    }
}
