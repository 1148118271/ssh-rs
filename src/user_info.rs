use std::fmt::Debug;

use crate::key_pair::KeyPair;

#[derive(Clone, Default)]
pub struct UserInfo {
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) key_pair: Option<KeyPair>,
}

impl Debug for UserInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "username: {}", self.username)?;
        Ok(())
    }
}
