use std::fs::File;
use std::io::Read;
use std::path::Path;
use crate::config_auth::AuthType;
use crate::key_pair::KeyPair;

pub struct UserInfo {
    pub(crate) auth_type: AuthType,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) key_pair: KeyPair
}


// TODO 异常未处理
// TODO 密钥填充方式未判断
impl UserInfo {

    pub fn new() -> Self {
        UserInfo {
            auth_type: AuthType::Password,
            username: "".to_string(),
            password: "".to_string(),
            key_pair: KeyPair::new()
        }
    }

    pub fn from_key_pair<S: ToString>(user_name: S, key_pair: KeyPair) -> Self {
        UserInfo {
            auth_type: AuthType::PublicKey,
            username: user_name.to_string(),
            password: "".to_string(),
            key_pair
        }
    }

    pub fn from_password<S: ToString>(user_name: S, password: S) -> Self {
        UserInfo {
            auth_type: AuthType::Password,
            username: user_name.to_string(),
            password: password.to_string(),
            key_pair: KeyPair::new()
        }
    }
}