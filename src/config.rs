use crate::constant::{algorithms, CLIENT_VERSION};
use crate::data::Data;
use crate::error::SshErrorKind;
use crate::encryption::{PublicKey, RSA, SIGN, Ed25519};
use crate::slog::log;
use crate::{SshError, SshResult};
use crate::algorithm::key_exchange::curve25519::CURVE25519;
use crate::algorithm::key_exchange::ecdh_sha2_nistp256::EcdhP256;
use crate::algorithm::key_exchange::KeyExchange;
use crate::algorithm::public_key::PublicKey;


pub(crate) static mut CONFIG: Option<Config> = None;


pub(crate) fn init(config: Config) {
    unsafe {
        CONFIG = Some(config);
    }
}

pub(crate) fn config() -> &'static mut Config {
    unsafe {
        if CONFIG.is_none() {
            CONFIG = Some(Config::new())
        }
        CONFIG.as_mut().unwrap()
    }
}


#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) user: UserConfig,
    pub(crate) version: VersionConfig,
    pub(crate) algorithm: AlgorithmConfig,
}
impl Config {
    pub(crate) fn new() -> Self {
        Config {
            user: UserConfig::new(),
            version: VersionConfig::new(),
            algorithm: AlgorithmConfig::new()
        }
    }
}

#[derive(Clone)]
pub(crate) struct UserConfig {
    pub(crate) username: String,
    pub(crate) password: String,
}
impl UserConfig {
    pub(crate) fn new() -> Self {
        UserConfig {
            username: String::new(),
            password: String::new()
        }
    }
}


#[derive(Clone)]
pub(crate) struct VersionConfig {
    pub(crate) client_version: String,
    pub(crate) server_version: String,
}
impl VersionConfig {
    pub(crate) fn new() -> Self {
        VersionConfig {
            client_version: CLIENT_VERSION.to_string(),
            server_version: String::new()
        }
    }
    pub(crate) fn validation(&self) -> SshResult<()> {
        if !self.server_version.contains("SSH-2.0") {
            log::error!("error in version negotiation, version mismatch.");
            return Err(SshError::from(SshErrorKind::VersionError))
        }
       Ok(())
    }
}


#[derive(Clone)]
pub(crate) struct AlgorithmConfig {
    pub(crate) client_algorithm: AlgorithmList,
    pub(crate) server_algorithm: AlgorithmList,
}
impl AlgorithmConfig {
    pub(crate) fn new() -> Self {
        AlgorithmConfig {
            client_algorithm: AlgorithmList::client_algorithm(),
            server_algorithm: AlgorithmList::new()
        }
    }

    pub(crate) fn matching_algorithm(&self) -> SshResult<(Box<dyn KeyExchange>, Box<dyn PublicKey>)> {
        let key_exchange_algorithm = self.matching_key_exchange_algorithm()?;

        let public_key_algorithm = self.matching_public_key_algorithm()?;

        if !self.server_algorithm.c_encryption_algorithm
            .0
            .contains(&(algorithms::ENCRYPTION_CHACHA20_POLY1305_OPENSSH.to_string()))
        {
            log::error!("description the encryption algorithm fails to match, \
                algorithms supported by the server: {},\
                algorithms supported by the client: {}",
                    self.server_algorithm.c_encryption_algorithm.to_string(),
                    self.client_algorithm.c_encryption_algorithm.to_string()
                );
            return Err(SshError::from(SshErrorKind::KeyExchangeError))
        }
        Ok((key_exchange_algorithm, public_key_algorithm))
    }

    /// 匹配合适的公钥签名算法
    /// 目前支持:
    ///     1. ed25519.rs
    ///     2. ssh-rsa
    pub(crate) fn matching_public_key_algorithm(&self) -> SshResult<Box<dyn PublicKey>> {
        let public_key_algorithm: String = get_algorithm(
            &self.client_algorithm.public_key_algorithm.0,
            &self.server_algorithm.public_key_algorithm.0
        );
        match public_key_algorithm.as_str() {
            algorithms::PUBLIC_KEY_ED25519 => Ok(Box::new(Ed25519::new())),
            algorithms::PUBLIC_KEY_RSA => Ok(Box::new(RSA::new())),
            _ => {
                log::error!("description the signature algorithm fails to match, \
                algorithms supported by the server: {},\
                algorithms supported by the client: {}",
                    self.server_algorithm.public_key_algorithm.to_string(),
                    self.client_algorithm.public_key_algorithm.to_string()
                );
                return Err(SshError::from(SshErrorKind::KeyExchangeError))
            }
        }
    }

    /// 匹配合适的密钥交换算法
    /// 目前支持:
    ///     1. curve25519-sha256
    ///     2. ecdh-sha2-nistp256
    pub(crate) fn matching_key_exchange_algorithm(&self) -> SshResult<Box<dyn KeyExchange>> {
        let key_exchange_algorithm: String = get_algorithm(
            &self.client_algorithm.key_exchange_algorithm.0,
            &self.server_algorithm.key_exchange_algorithm.0
        );
        match key_exchange_algorithm.as_str() {
            algorithms::DH_CURVE25519_SHA256 => Ok(Box::new(CURVE25519::new()?)),
            algorithms::DH_ECDH_SHA2_NISTP256 => Ok(Box::new(EcdhP256::new()?)),
            _ => {
                log::error!("description The DH algorithm fails to match, \
                algorithms supported by the server: {},\
                algorithms supported by the client: {}",
                    self.server_algorithm.key_exchange_algorithm.to_string(),
                    self.client_algorithm.key_exchange_algorithm.to_string()
                );
                Err(SshError::from(SshErrorKind::KeyExchangeError))
            }
        }
    }

}

fn get_algorithm(c_algorithm: &Vec<String>, s_algorithm: &Vec<String>) -> String {
    for x in c_algorithm {
        if s_algorithm.contains(x) {
            return x.clone()
        }
    }
    return String::new();
}

#[derive(Clone)]
pub(crate) struct AlgorithmList {
    pub(crate) key_exchange_algorithm: KeyExchangeAlgorithm,
    pub(crate) public_key_algorithm: PublicKeyAlgorithm,
    pub(crate) c_encryption_algorithm: EncryptionAlgorithm,
    pub(crate) s_encryption_algorithm: EncryptionAlgorithm,
    pub(crate) c_mac_algorithm: MacAlgorithm,
    pub(crate) s_mac_algorithm: MacAlgorithm,
    pub(crate) c_compression_algorithm: CompressionAlgorithm,
    pub(crate) s_compression_algorithm: CompressionAlgorithm,
}
impl AlgorithmList {
    pub(crate) fn new() -> Self {
        AlgorithmList {
            key_exchange_algorithm: KeyExchangeAlgorithm(vec![]),
            public_key_algorithm: PublicKeyAlgorithm(vec![]),
            c_encryption_algorithm: EncryptionAlgorithm(vec![]),
            s_encryption_algorithm: EncryptionAlgorithm(vec![]),
            c_mac_algorithm: MacAlgorithm(vec![]),
            s_mac_algorithm: MacAlgorithm(vec![]),
            c_compression_algorithm: CompressionAlgorithm(vec![]),
            s_compression_algorithm: CompressionAlgorithm(vec![])
        }
    }

    pub(crate) fn client_algorithm() -> Self {
        AlgorithmList {
            key_exchange_algorithm: KeyExchangeAlgorithm::get_client(),
            public_key_algorithm: PublicKeyAlgorithm::get_client(),
            c_encryption_algorithm: EncryptionAlgorithm::get_client(),
            s_encryption_algorithm: EncryptionAlgorithm::get_client(),
            c_mac_algorithm: MacAlgorithm::get_client(),
            s_mac_algorithm: MacAlgorithm::get_client(),
            c_compression_algorithm: CompressionAlgorithm::get_client(),
            s_compression_algorithm: CompressionAlgorithm::get_client()
        }
    }

    pub(crate) fn as_i(&self) -> Vec<u8> {
        let mut data = Data::new();
        data.put_str(self.key_exchange_algorithm.to_string().as_str());
        data.put_str(self.public_key_algorithm.to_string().as_str());
        data.put_str(self.c_encryption_algorithm.to_string().as_str());
        data.put_str(self.s_encryption_algorithm.to_string().as_str());
        data.put_str(self.c_mac_algorithm.to_string().as_str());
        data.put_str(self.s_mac_algorithm.to_string().as_str());
        data.put_str(self.c_compression_algorithm.to_string().as_str());
        data.put_str(self.s_compression_algorithm.to_string().as_str());
        data.to_vec()
    }
}

impl ToString for AlgorithmList {
    fn to_string(&self) -> String {
        format!("\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
            self.key_exchange_algorithm.to_string().as_str(),
            self.public_key_algorithm.to_string().as_str(),
            self.c_encryption_algorithm.to_string().as_str(),
            self.s_encryption_algorithm.to_string().as_str(),
            self.c_mac_algorithm.to_string().as_str(),
            self.s_mac_algorithm.to_string().as_str(),
            self.c_compression_algorithm.to_string().as_str(),
            self.s_compression_algorithm.to_string().as_str(),
        )
    }
}


#[derive(Clone)]
pub(crate) struct KeyExchangeAlgorithm(pub(crate) Vec<String>);
impl KeyExchangeAlgorithm {
    pub(crate) fn get_client() -> Self {
        KeyExchangeAlgorithm(
            vec![
                algorithms::DH_CURVE25519_SHA256.to_string(),
                algorithms::DH_ECDH_SHA2_NISTP256.to_string()
            ]
        )
    }
}

impl ToString for KeyExchangeAlgorithm {
    fn to_string(&self) -> String {
        to_string(&self.0)
    }
}


#[derive(Clone)]
pub(crate) struct PublicKeyAlgorithm(pub(crate) Vec<String>);
impl PublicKeyAlgorithm {
    pub(crate) fn get_client() -> Self {
        PublicKeyAlgorithm(
            vec![
                algorithms::PUBLIC_KEY_ED25519.to_string(),
                algorithms::PUBLIC_KEY_RSA.to_string()
            ]
        )
    }
}

impl ToString for PublicKeyAlgorithm {
    fn to_string(&self) -> String {
        to_string(&self.0)
    }
}

#[derive(Clone)]
pub(crate) struct EncryptionAlgorithm(pub(crate) Vec<String>);
impl EncryptionAlgorithm {
    pub(crate) fn get_client() -> Self {
        EncryptionAlgorithm(
            vec![
                algorithms::ENCRYPTION_CHACHA20_POLY1305_OPENSSH.to_string(),
            ]
        )
    }
}
impl ToString for EncryptionAlgorithm {
    fn to_string(&self) -> String {
        to_string(&self.0)
    }
}

#[derive(Clone)]
pub(crate) struct MacAlgorithm(pub(crate) Vec<String>);
impl MacAlgorithm {
    pub(crate) fn get_client() -> Self {
        MacAlgorithm(
            vec![
                algorithms::MAC_ALGORITHMS.to_string(),
            ]
        )
    }
}
impl ToString for MacAlgorithm {
    fn to_string(&self) -> String {
        to_string(&self.0)
    }
}


#[derive(Clone)]
pub(crate) struct CompressionAlgorithm(pub(crate) Vec<String>);
impl CompressionAlgorithm {
    pub(crate) fn get_client() -> Self {
        CompressionAlgorithm(
            vec![
                algorithms::COMPRESSION_ALGORITHMS.to_string(),
            ]
        )
    }
}
impl ToString for CompressionAlgorithm {
    fn to_string(&self) -> String {
        to_string(&self.0)
    }
}


fn to_string(v: &[String]) -> String {
    let mut s = String::new();
    if v.is_empty() { return s }
    for (i, val) in v.iter().enumerate() {
        if i == 0 {
            s.push_str(val);
            continue
        }
        s.push_str(format!(",{}", val).as_str());
    }
    s
}