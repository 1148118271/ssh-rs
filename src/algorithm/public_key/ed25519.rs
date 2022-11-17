use crate::algorithm::public_key::PublicKey;
use crate::model::Data;
use crate::SshError;
use ring::signature;

pub(super) struct Ed25519;

impl PublicKey for Ed25519 {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self
    }

    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError> {
        let mut data = Data::from(ks[4..].to_vec());
        data.get_u8s();
        let host_key = data.get_u8s();
        let pub_key = signature::UnparsedPublicKey::new(&signature::ED25519, host_key);
        Ok(pub_key.verify(message, sig).is_ok())
    }
}
