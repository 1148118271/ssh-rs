
#[derive(Clone)]
pub(crate) struct AuthConfig {
    pub(crate) auth_type: AuthType,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) private_key: String,
    pub(crate) private_key_algorithm_name: String,
}



impl AuthConfig {
    pub(crate) fn new() -> Self {
        AuthConfig {
            auth_type: AuthType::Password,
            username: String::new(),
            password: String::new(),
            private_key: String::new(),
            private_key_algorithm_name: String::new()
        }
    }

    pub(crate) fn from_password<S: ToString>(user_name: S, password: S) {

        

        // let string = user_name.into();
        // AuthConfig {
        //     auth_type: AuthType::Password,
        //     username: "".to_string(),
        //     password: "".to_string(),
        //     private_key: "".to_string(),
        //     private_key_algorithm_name: "".to_string()
        // }
    }
}



#[derive(Clone)]
pub(crate) enum AuthType {
    Password,
    PublicKey
}