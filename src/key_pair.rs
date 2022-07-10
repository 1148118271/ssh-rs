use std::fs::File;
use std::io::Read;
use std::path::Path;
use rsa::pkcs1::FromRsaPrivateKey;
use rsa::{BigUint, PublicKeyParts};
use crate::algorithm::hash::h;
use crate::config;
use crate::constant::{ssh_msg_code, ssh_str};
use crate::data::Data;
use crate::key_pair_type::KeyPairType;

pub struct KeyPair {
    pub(crate) private_key: String,
    pub(crate) key_type: String,
    pub(crate) blob: Vec<u8>,
    pub(crate) es: Vec<u8>,
    pub(crate) ns: Vec<u8>,
}



impl KeyPair {

    pub fn new() -> Self {
        KeyPair {
            private_key: "".to_string(),
            key_type: "".to_string(),
            blob: vec![],
            es: vec![],
            ns: vec![]
        }
    }

    // todo 异常判断
    pub fn from_path<P: AsRef<Path>>(key_path: P, key_type: KeyPairType) -> Self {
        let mut file = File::open(key_path).unwrap();
        let mut prks = String::new();
        file.read_to_string(&mut prks).unwrap();
        KeyPair::from_str(&prks, key_type)
    }


    pub fn from_str(key_str: &str, key_type: KeyPairType) -> Self {
        let key_type_str = key_type_to_str(key_type);
        let rprk = rsa::RsaPrivateKey::from_pkcs1_pem(key_str).unwrap();
        let rpuk = rprk.to_public_key();
        let es = rpuk.e().to_bytes_be();
        let ns = rpuk.n().to_bytes_be();
        let mut blob = Data::new();
        blob.put_str(key_type_str);
        blob.put_mpint(&es);
        blob.put_mpint(&ns);
        let blob = blob.to_vec();
        KeyPair {
            private_key: key_str.to_string(),
            key_type: key_type_str.to_string(),
            blob,
            es,
            ns
        }
    }

    pub fn get_blob(&self) -> Vec<u8> {
        self.blob.to_vec()
    }


    pub(crate) fn signature(&self, buf: &[u8]) -> Vec<u8> {
        let session_id = h::get().digest();
        let mut sd = Data::new();
        sd.put_u8s(session_id.as_slice());
        sd.extend_from_slice(buf);
        let scheme = rsa::PaddingScheme::PKCS1v15Sign {
            hash: Some(rsa::Hash::SHA1)
        };
        let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, sd.as_slice());
        let msg = digest.as_ref();


        let mut rprk = rsa::RsaPrivateKey::from_pkcs1_pem(self.private_key.as_str()).unwrap();

        let sign = rprk.sign(scheme, msg).unwrap();
        let mut ss = Data::new();
        ss.put_str(self.key_type.as_str());
        ss.put_u8s(sign.as_slice());
        ss.to_vec()
    }
}


fn key_type_to_str<'a>(key_type: KeyPairType) -> &'a str {
    match key_type {
        KeyPairType::SshRsa => "ssh-rsa"
    }
}





