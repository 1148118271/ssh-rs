use std::fmt::Debug;

use crate::algorithm::encryption::{AesCtr128, ChaCha20Poly1305, Encryption};
use crate::algorithm::hash::hash::Hash;
use crate::algorithm::key_exchange::curve25519::CURVE25519;
use crate::algorithm::key_exchange::ecdh_sha2_nistp256::EcdhP256;
use crate::algorithm::key_exchange::KeyExchange;
use crate::algorithm::mac::hmac_sha1::HMacSha1;
use crate::algorithm::mac::Mac;
#[cfg(feature = "dangerous-rsa-sha1")]
use crate::algorithm::public_key::RsaSha1;
use crate::algorithm::public_key::{Ed25519, PublicKey, RsaSha256};
use crate::constant::{algorithms, CLIENT_VERSION};
use crate::data::Data;
use crate::slog::log;
use crate::user_info::UserInfo;
use crate::{SshError, SshResult};

#[derive(Clone, Default, Debug)]
pub struct Config {
    pub auth: UserInfo,
    pub version: VersionConfig,
    pub algorithm: AlgorithmConfig,
}

impl Config {
    pub fn disable_default_algorithms() -> Config {
        Config {
            algorithm: AlgorithmConfig::disable_default(),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug)]
pub struct VersionConfig {
    pub client_version: String,
    pub server_version: String,
}

impl Default for VersionConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl VersionConfig {
    pub fn new() -> Self {
        VersionConfig {
            client_version: CLIENT_VERSION.to_string(),
            server_version: String::new(),
        }
    }
    pub fn validation(&self) -> SshResult<()> {
        if !self.server_version.contains("SSH-2.0") {
            log::error!("error in version negotiation, version mismatch.");
            return Err(SshError::from(
                "error in version negotiation, version mismatch.",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct AlgorithmConfig {
    pub client: AlgorithmList,
    pub server: AlgorithmList,
    pub(crate) negotiated: AlgorithmList,
}

impl Default for AlgorithmConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmConfig {
    pub fn new() -> Self {
        AlgorithmConfig {
            client: AlgorithmList::client_default(),
            server: AlgorithmList::new(),
            negotiated: AlgorithmList::new(),
        }
    }

    pub fn disable_default() -> Self {
        AlgorithmConfig {
            client: AlgorithmList::new(),
            server: AlgorithmList::new(),
            negotiated: AlgorithmList::new(),
        }
    }

    /// 匹配合适的mac算法
    /// 目前支持：
    ///     1. hmac-sha1
    pub fn matching_mac_algorithm(&mut self) -> SshResult<Box<dyn Mac>> {
        // 目前是加密和解密使用一个算法
        // 所以直接取一个算法为准
        let mac_algorithm: String = get_algorithm(&self.client.c_mac.0, &self.server.c_mac.0);

        self.negotiated.c_mac.0.push(mac_algorithm.clone());
        self.negotiated.s_mac.0.push(mac_algorithm.clone());

        match mac_algorithm.as_str() {
            algorithms::mac::HMAC_SHA1 => Ok(Box::new(HMacSha1::new())),
            _ => {
                log::error!(
                    "description the mac algorithm fails to match, \
                algorithms supported by the server: {},\
                algorithms supported by the client: {}",
                    self.server.c_mac.to_string(),
                    self.client.c_mac.to_string()
                );
                Err(SshError::from("key exchange error."))
            }
        }
    }

    /// 匹配合适的加密算法
    /// 目前支持:
    ///     1. chacha20-poly1305@openssh.com
    ///     2. aes128-ctr
    pub fn matching_encryption_algorithm(
        &mut self,
        hash: Hash,
        mac: Box<dyn Mac>,
    ) -> SshResult<Box<dyn Encryption>> {
        // 目前是加密和解密使用一个算法
        // 所以直接取一个算法为准
        let encryption_algorithm: String =
            get_algorithm(&self.client.c_encryption.0, &self.server.c_encryption.0);

        self.negotiated
            .c_encryption
            .0
            .push(encryption_algorithm.clone());
        self.negotiated
            .s_encryption
            .0
            .push(encryption_algorithm.clone());

        match encryption_algorithm.as_str() {
            algorithms::enc::CHACHA20_POLY1305_OPENSSH => {
                Ok(Box::new(ChaCha20Poly1305::new(hash, mac)))
            }
            algorithms::enc::AES128_CTR => Ok(Box::new(AesCtr128::new(hash, mac))),
            _ => {
                log::error!(
                    "description the encryption algorithm fails to match, \
                algorithms supported by the server: {},\
                algorithms supported by the client: {}",
                    self.server.c_encryption.to_string(),
                    self.client.c_encryption.to_string()
                );
                Err(SshError::from("key exchange error."))
            }
        }
    }

    /// PubkeyAcceptedAlgorithms
    /// Currently support:
    ///     1. ed25519.rs
    ///     2. rsa-sha2-256
    ///     3. rsa-sha (behind feature "dangerous-rsa-sha1")
    pub fn matching_public_key_algorithm(&mut self) -> SshResult<Box<dyn PublicKey>> {
        let public_key_algorithm: String =
            get_algorithm(&self.client.public_key.0, &self.server.public_key.0);

        self.negotiated
            .public_key
            .0
            .push(public_key_algorithm.clone());

        match public_key_algorithm.as_str() {
            algorithms::pubkey::SSH_ED25519 => Ok(Box::new(Ed25519::new())),
            algorithms::pubkey::RSA_SHA2_256 => Ok(Box::new(RsaSha256::new())),
            #[cfg(feature = "dangerous-rsa-sha1")]
            algorithms::pubkey::SSH_RSA => Ok(Box::new(RsaSha1::new())),
            _ => {
                log::error!(
                    "description the signature algorithm fails to match, \
                algorithms supported by the server: {},\
                algorithms supported by the client: {}",
                    self.server.public_key.to_string(),
                    self.client.public_key.to_string()
                );
                Err(SshError::from("key exchange error."))
            }
        }
    }

    /// 匹配合适的密钥交换算法
    /// 目前支持:
    ///     1. curve25519-sha256
    ///     2. ecdh-sha2-nistp256
    pub fn matching_key_exchange_algorithm(&mut self) -> SshResult<Box<dyn KeyExchange>> {
        let key_exchange_algorithm: String =
            get_algorithm(&self.client.key_exchange.0, &self.server.key_exchange.0);

        self.negotiated
            .key_exchange
            .0
            .push(key_exchange_algorithm.clone());

        match key_exchange_algorithm.as_str() {
            algorithms::kex::CURVE25519_SHA256 => Ok(Box::new(CURVE25519::new()?)),
            algorithms::kex::ECDH_SHA2_NISTP256 => Ok(Box::new(EcdhP256::new()?)),
            _ => {
                log::error!(
                    "description the DH algorithm fails to match, \
                algorithms supported by the server: {},\
                algorithms supported by the client: {}",
                    self.server.key_exchange.to_string(),
                    self.client.key_exchange.to_string()
                );
                Err(SshError::from("key exchange error."))
            }
        }
    }
}

fn get_algorithm(c_algorithm: &Vec<String>, s_algorithm: &[String]) -> String {
    for x in c_algorithm {
        if s_algorithm.contains(x) {
            return x.clone();
        }
    }
    String::new()
}

#[derive(Clone, Debug)]
pub struct AlgorithmList {
    pub key_exchange: KeyExchangeAlgorithm,
    pub public_key: PublicKeyAlgorithm,
    pub c_encryption: EncryptionAlgorithm,
    pub s_encryption: EncryptionAlgorithm,
    pub c_mac: MacAlgorithm,
    pub s_mac: MacAlgorithm,
    pub c_compression: CompressionAlgorithm,
    pub s_compression: CompressionAlgorithm,
}

impl Default for AlgorithmList {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmList {
    pub fn new() -> Self {
        AlgorithmList {
            key_exchange: KeyExchangeAlgorithm(vec![]),
            public_key: PublicKeyAlgorithm(vec![]),
            c_encryption: EncryptionAlgorithm(vec![]),
            s_encryption: EncryptionAlgorithm(vec![]),
            c_mac: MacAlgorithm(vec![]),
            s_mac: MacAlgorithm(vec![]),
            c_compression: CompressionAlgorithm(vec![]),
            s_compression: CompressionAlgorithm(vec![]),
        }
    }

    pub fn client_default() -> Self {
        AlgorithmList {
            key_exchange: KeyExchangeAlgorithm::get_client(),
            public_key: PublicKeyAlgorithm::get_client(),
            c_encryption: EncryptionAlgorithm::get_client(),
            s_encryption: EncryptionAlgorithm::get_client(),
            c_mac: MacAlgorithm::get_client(),
            s_mac: MacAlgorithm::get_client(),
            c_compression: CompressionAlgorithm::get_client(),
            s_compression: CompressionAlgorithm::get_client(),
        }
    }

    pub fn as_i(&self) -> Vec<u8> {
        let mut data = Data::new();
        data.put_str(self.key_exchange.to_string().as_str());
        data.put_str(self.public_key.to_string().as_str());
        data.put_str(self.c_encryption.to_string().as_str());
        data.put_str(self.s_encryption.to_string().as_str());
        data.put_str(self.c_mac.to_string().as_str());
        data.put_str(self.s_mac.to_string().as_str());
        data.put_str(self.c_compression.to_string().as_str());
        data.put_str(self.s_compression.to_string().as_str());
        data.to_vec()
    }
}
