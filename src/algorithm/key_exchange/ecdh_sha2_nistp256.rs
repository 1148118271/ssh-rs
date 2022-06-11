use ring::agreement::{ECDH_P256, EphemeralPrivateKey, PublicKey, UnparsedPublicKey};
use crate::algorithm::key_exchange::KeyExchange;
use crate::error::SshErrorKind;
use crate::{SshError, SshResult};
use crate::constant::{HASH, HashType};

pub struct EcdhP256 {
    pub private_key: EphemeralPrivateKey,
    pub public_key: PublicKey
}

impl KeyExchange for EcdhP256 {
    fn new() -> SshResult<Self> {
        let rng = ring::rand::SystemRandom::new();
        let private_key =
            match EphemeralPrivateKey::generate(&ECDH_P256, &rng) {
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


    fn get_shared_secret(&self, puk: Vec<u8>) -> SshResult<Vec<u8>> {
        let mut public_key = [0u8; 65];
        public_key.copy_from_slice(&puk);
        let server_pub = UnparsedPublicKey::new(&ECDH_P256, puk);
        let private_key = unsafe { (&self.private_key as *const EphemeralPrivateKey).read() };
        crate::algorithm::key_exchange::agree_ephemeral(private_key, &server_pub)
    }

    fn get_hash_type(&self) -> HashType {
        HashType::SHA256
    }
}