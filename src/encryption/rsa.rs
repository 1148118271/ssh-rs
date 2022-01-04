use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::rsa;
use openssl::rsa::Rsa;
use openssl::sign;
use openssl::sign::Verifier;
use ring::signature::RsaPublicKeyComponents;
use crate::encryption::PublicKey;
use crate::error::SshErrorKind;
use crate::packet::Data;
use crate::SshError;

pub(crate) struct RSA;

impl PublicKey for RSA {
    fn new() -> Self where Self: Sized {
        Self
    }

    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError> {
        let mut data = Data((&ks[4..]).to_vec());
        data.get_u8s();
        let e = match BigNum::from_slice(&(data.get_u8s())) {
            Ok(e) => e,
            Err(_) => return Err(SshError::from(SshErrorKind::SignatureError))
        };
        let n = match BigNum::from_slice(&(data.get_u8s())) {
            Ok(n) => n,
            Err(_) => return Err(SshError::from(SshErrorKind::SignatureError))
        };
        let puk = match rsa::Rsa::from_public_components(n, e) {
            Ok(v) => v,
            Err(_) => return Err(SshError::from(SshErrorKind::SignatureError))
        };
        let pkey = match PKey::from_rsa(puk) {
            Ok(v) => v,
            Err(_) => return Err(SshError::from(SshErrorKind::SignatureError))
        };
        let mut verifier = match Verifier::new(MessageDigest::sha1(), &pkey) {
            Ok(v) => v,
            Err(_) => return Err(SshError::from(SshErrorKind::SignatureError))
        };
        match verifier.verify_oneshot(sig, message) {
            Ok(ok) => Ok(ok),
            Err(_) => Ok(false)
        }

    }
}