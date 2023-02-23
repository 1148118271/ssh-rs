mod test {
    use paste::paste;
    use ssh_rs::{algorithm, ssh};
    use std::env;

    macro_rules! env_getter {
        ($field:ident, $default: expr) => {
            paste! {
                pub fn [<get_ $field>]() -> String {
                    env::var("SSH_RS_TEST_".to_owned() + stringify!([<$field:upper>])).unwrap_or($default.to_owned())
                }
            }
        };
    }
    env_getter!(username, "ubuntu");
    env_getter!(server, "127.0.0.1:22");
    env_getter!(pem_rsa, "./rsa_old");

    #[cfg(feature = "dangerous-rsa-sha1")]
    #[test]
    fn test_ssh_rsa() {
        let session = ssh::create_session_without_default()
            .username(&get_username())
            .private_key_path(&get_pem_rsa())
            .add_kex_algorithms(algorithm::Kex::EcdhSha2Nistrp256)
            .add_pubkey_algorithms(algorithm::PubKey::SshRsa)
            .add_enc_algorithms(algorithm::Enc::Chacha20Poly1305Openssh)
            .add_compress_algorithms(algorithm::Compress::None)
            .add_mac_algortihms(algorithm::Mac::HmacSha1)
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }

    #[cfg(feature = "dangerous-algorithms")]
    #[test]
    fn test_dh_group1() {
        let session = ssh::create_session_without_default()
            .username(&get_username())
            .private_key_path(&get_pem_rsa())
            .add_kex_algorithms(algorithm::Kex::DiffieHellmanGroup1Sha1)
            .add_pubkey_algorithms(algorithm::PubKey::SshRsa)
            .add_enc_algorithms(algorithm::Enc::Aes128Ctr)
            .add_compress_algorithms(algorithm::Compress::None)
            .add_mac_algortihms(algorithm::Mac::HmacSha1)
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }

    #[test]
    fn test_curve25519_sha256() {
        let session = ssh::create_session_without_default()
            .username(&get_username())
            .private_key_path(&get_pem_rsa())
            .add_kex_algorithms(algorithm::Kex::Curve25519Sha256)
            .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_256)
            .add_enc_algorithms(algorithm::Enc::Aes128Ctr)
            .add_compress_algorithms(algorithm::Compress::None)
            .add_mac_algortihms(algorithm::Mac::HmacSha1)
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }

    #[test]
    fn test_ecdh_sha2_nistp256() {
        let session = ssh::create_session_without_default()
            .username(&get_username())
            .private_key_path(&get_pem_rsa())
            .add_kex_algorithms(algorithm::Kex::EcdhSha2Nistrp256)
            .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_256)
            .add_enc_algorithms(algorithm::Enc::Aes128Ctr)
            .add_compress_algorithms(algorithm::Compress::None)
            .add_mac_algortihms(algorithm::Mac::HmacSha1)
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }

    #[test]
    fn test_dh_group14_sha1() {
        let session = ssh::create_session_without_default()
            .username(&get_username())
            .private_key_path(&get_pem_rsa())
            .add_kex_algorithms(algorithm::Kex::DiffieHellmanGroup14Sha1)
            .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_256)
            .add_enc_algorithms(algorithm::Enc::Aes128Ctr)
            .add_compress_algorithms(algorithm::Compress::None)
            .add_mac_algortihms(algorithm::Mac::HmacSha1)
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }

    #[test]
    fn test_dh_group14_sha256() {
        let session = ssh::create_session_without_default()
            .username(&get_username())
            .private_key_path(&get_pem_rsa())
            .add_kex_algorithms(algorithm::Kex::DiffieHellmanGroup14Sha256)
            .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_256)
            .add_enc_algorithms(algorithm::Enc::Aes128Ctr)
            .add_compress_algorithms(algorithm::Compress::None)
            .add_mac_algortihms(algorithm::Mac::HmacSha1)
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }

    #[test]
    fn test_aes192() {
        let session = ssh::create_session_without_default()
            .username(&get_username())
            .private_key_path(&get_pem_rsa())
            .add_kex_algorithms(algorithm::Kex::DiffieHellmanGroup14Sha256)
            .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_256)
            .add_enc_algorithms(algorithm::Enc::Aes192Ctr)
            .add_compress_algorithms(algorithm::Compress::None)
            .add_mac_algortihms(algorithm::Mac::HmacSha1)
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }

    #[test]
    fn test_aes256() {
        let session = ssh::create_session_without_default()
            .username(&get_username())
            .private_key_path(&get_pem_rsa())
            .add_kex_algorithms(algorithm::Kex::DiffieHellmanGroup14Sha256)
            .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_256)
            .add_enc_algorithms(algorithm::Enc::Aes256Ctr)
            .add_compress_algorithms(algorithm::Compress::None)
            .add_mac_algortihms(algorithm::Mac::HmacSha1)
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }

    #[test]
    fn test_chacha20_poly1305() {
        let session = ssh::create_session_without_default()
            .username(&get_username())
            .private_key_path(&get_pem_rsa())
            .add_kex_algorithms(algorithm::Kex::DiffieHellmanGroup14Sha256)
            .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_256)
            .add_enc_algorithms(algorithm::Enc::Chacha20Poly1305Openssh)
            .add_compress_algorithms(algorithm::Compress::None)
            .add_mac_algortihms(algorithm::Mac::HmacSha1)
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }

    #[test]
    fn test_hmac_sha256() {
        let session = ssh::create_session_without_default()
            .username(&get_username())
            .private_key_path(&get_pem_rsa())
            .add_kex_algorithms(algorithm::Kex::DiffieHellmanGroup14Sha256)
            .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_256)
            .add_enc_algorithms(algorithm::Enc::Chacha20Poly1305Openssh)
            .add_compress_algorithms(algorithm::Compress::None)
            .add_mac_algortihms(algorithm::Mac::HmacSha2_256)
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }

    #[test]
    fn test_hmac_sha512() {
        let session = ssh::create_session_without_default()
            .username(&get_username())
            .private_key_path(&get_pem_rsa())
            .add_kex_algorithms(algorithm::Kex::DiffieHellmanGroup14Sha256)
            .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_256)
            .add_enc_algorithms(algorithm::Enc::Chacha20Poly1305Openssh)
            .add_compress_algorithms(algorithm::Compress::None)
            .add_mac_algortihms(algorithm::Mac::HmacSha2_512)
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }
}
