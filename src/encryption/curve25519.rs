use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

#[derive(Clone)]
pub struct CURVE25519 {
    pub private_key: StaticSecret,
    pub public_key: PublicKey
}


impl CURVE25519 {
    pub fn new() -> Self {
        let private_key = StaticSecret::new(&mut OsRng);
        let public_key = PublicKey::from(&private_key);
        CURVE25519 {
            private_key,
            public_key
        }
    }

    pub fn get_shared_secret(self, puk: [u8; 32]) -> SharedSecret {
        let server_pub = PublicKey::from(puk);
        self.private_key.diffie_hellman(&server_pub)
    }
}


#[test]
pub fn test2() {
    let i = 38400_u32;
    let i1 = u32::from_be_bytes([0, 0, 0x96, 0]);
    println!("{:?}", i1);
}