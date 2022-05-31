use ring::agreement;
use ring::agreement::{EphemeralPrivateKey, PublicKey};
use crate::error::{SshError, SshErrorKind};
use crate::encryption::KeyExchange;

pub struct CURVE25519 {
    pub private_key: EphemeralPrivateKey,
    pub public_key: PublicKey
}


impl KeyExchange for CURVE25519 {

    fn new() -> Result<Self, SshError> {
        let rng = ring::rand::SystemRandom::new();
        let private_key = match agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng) {
            Ok(v) => v,
            Err(_) => return Err(SshError::from(SshErrorKind::EncryptionError))
        };
        match private_key.compute_public_key() {
            Ok(public_key) =>
                Ok(CURVE25519 {
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
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&puk);

        let server_pub = agreement::UnparsedPublicKey::new(&agreement::X25519, public_key);
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


#[test]
pub fn test2() {
    let i = 38400_u32;
    let i1 = u32::from_be_bytes([0, 0, 0x96, 0]);
    println!("{:?}", i1);
}