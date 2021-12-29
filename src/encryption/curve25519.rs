use ring::agreement;
use ring::agreement::{EphemeralPrivateKey, PublicKey};

pub struct CURVE25519 {
    pub private_key: EphemeralPrivateKey,
    pub public_key: PublicKey
}


impl CURVE25519 {
    pub fn new() -> Self {
        let rng = ring::rand::SystemRandom::new();
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
        let public_key = private_key.compute_public_key().unwrap();
        CURVE25519 {
            private_key,
            public_key
        }
    }

    pub fn get_shared_secret(self, puk: [u8; 32]) -> Vec<u8> {
        let server_pub = agreement::UnparsedPublicKey::new(&agreement::X25519, puk);
        // let server_pub = PublicKey::from(puk);
        agreement::agree_ephemeral(
            self.private_key,
            &server_pub,
            ring::error::Unspecified,
            |_key_material| {
                Ok(_key_material.to_vec())
            },
        ).unwrap()
    }
}


#[test]
pub fn test2() {
    let i = 38400_u32;
    let i1 = u32::from_be_bytes([0, 0, 0x96, 0]);
    println!("{:?}", i1);
}