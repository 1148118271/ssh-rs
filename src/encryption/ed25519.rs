use ring::signature;


pub fn verify_signature(host_key: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let pub_key =
        signature::UnparsedPublicKey::new(&signature::ED25519, host_key);
    pub_key.verify(message, sig).is_ok()
}