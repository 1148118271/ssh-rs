use ring::agreement;
use ring::agreement::{EphemeralPrivateKey, PublicKey};
use ring::error::Unspecified;
use crate::error::{SshError, SshErrorKind};

pub struct CURVE25519 {
    pub private_key: EphemeralPrivateKey,
    pub public_key: PublicKey
}


impl CURVE25519 {
    pub fn new() -> Result<CURVE25519, SshError> {
        let rng = ring::rand::SystemRandom::new();
        let private_key = match agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng) {
            Ok(v) => v,
            Err(e) => return Err(SshError::from(SshErrorKind::EncryptionError))
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

    pub fn get_shared_secret(self, puk: [u8; 32]) -> Result<Vec<u8>, SshError> {
        let server_pub = agreement::UnparsedPublicKey::new(&agreement::X25519, puk);
        match agreement::agree_ephemeral(
            self.private_key,
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