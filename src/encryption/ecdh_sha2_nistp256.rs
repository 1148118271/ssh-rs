use ring::agreement;
use ring::agreement::{EphemeralPrivateKey, PublicKey};
use crate::error::SshErrorKind;
use crate::encryption::{KeyExchange, SshError};

pub struct EcdhP256 {
    pub private_key: EphemeralPrivateKey,
    pub public_key: PublicKey
}

impl KeyExchange for EcdhP256 {
    fn new() -> Result<Self, SshError> {
        let rng = ring::rand::SystemRandom::new();
        let private_key =
            match agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng) {
            Ok(v) => v,
            Err(_) => return Err(SshError::from(SshErrorKind::EncryptionError))
        };
        match private_key.compute_public_key() {
            Ok(public_key) =>
                Ok(EcdhP256 {
                    private_key,
                    public_key
                }),
            Err(_) => Err(SshError::from(SshErrorKind::EncryptionError))
        }
    }

    fn get_public_key(&self) -> &[u8] {
        self.public_key.as_ref()
    }


    fn get_shared_secret(&self, puk: Vec<u8>) -> Result<Vec<u8>, SshError> {
        let mut public_key = [0u8; 65];
        public_key.copy_from_slice(&puk);
        let server_pub =
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, puk);
        let private_key = unsafe { (&self.private_key as *const EphemeralPrivateKey).read() };
        match agreement::agree_ephemeral(
            private_key,
           &server_pub,
            ring::error::Unspecified,
            |_key_material| {
                Ok(_key_material.to_vec())
            },
        ) {
            Ok(o) => Ok(o),
            Err(_) => Err(SshError::from(SshErrorKind::EncryptionError))
        }
    }

}