
#[derive(Clone)]
pub(crate) struct AuthConfig {
    pub(crate) auth_type: AuthType,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) public_key: String,
}



impl AuthConfig {
    pub(crate) fn new() -> Self {
        AuthConfig {
            auth_type: AuthType::Password,
            username: String::new(),
            password: String::new(),
            public_key: String::new()
        }
    }
}



#[derive(Clone)]
pub(crate) enum AuthType {
    Password,
    PublicKey
}