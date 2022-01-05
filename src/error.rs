use std::fmt::{Debug, Display, Formatter};
use std::{fmt, io};
use std::error::Error;

pub struct SshError {
    inner: SshErrorKind
}

impl SshError {
    pub fn kind(&self) -> SshErrorKind {
        match &self.inner {
            SshErrorKind::IoError(ie) => {
                SshErrorKind::IoError(io::Error::from(ie.kind()))
            }
            _ => {
                unsafe {std::ptr::read(&self.inner as *const SshErrorKind)}
            }
        }
    }
}


impl Debug for SshError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.inner {
            SshErrorKind::IoError(ie) => {
                write!(f, r"IoError: {{ Kind({:?}), Message({})}}", ie.kind(), ie.to_string())
            }
            _ => { write!(f, r"Error: {{ Kind({:?}), Message({}) }}", self.inner, self.inner.as_str()) }
        }
    }
}

impl Display for SshError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.inner {
            SshErrorKind::IoError(ie) => {
                write!(f, r"IoError: {{ Kind({:?}) }}", ie.kind())
            }
            _ => { write!(f, r"Error: {{ Kind({:?}) }}", self.inner) }
        }

    }
}


#[derive(Debug)]
pub enum SshErrorKind {
    IoError(io::Error),
    EncryptionError,
    FromUtf8Error,
    ChannelFailureError,
    PasswordError,
    UserNullError,
    PasswordNullError,
    SignatureError,
    VersionError,
    KeyExchangeError
}



impl PartialEq<Self> for SshErrorKind {
    fn eq(&self, other: &Self) -> bool {
       match (&self, &other) {
           (&SshErrorKind::IoError(io1), &SshErrorKind::IoError(io2)) => io1.kind() == io2.kind(),
           (&SshErrorKind::EncryptionError, &SshErrorKind::EncryptionError) => true,
           (&SshErrorKind::FromUtf8Error, &SshErrorKind::FromUtf8Error) => true,
           (&SshErrorKind::ChannelFailureError, &SshErrorKind::ChannelFailureError) => true,
           (&SshErrorKind::PasswordError, &SshErrorKind::PasswordError) => true,
           (&SshErrorKind::UserNullError, &SshErrorKind::UserNullError) => true,
           (&SshErrorKind::PasswordNullError, &SshErrorKind::PasswordNullError) => true,
           (&SshErrorKind::SignatureError, &SshErrorKind::SignatureError) => true,
           (&SshErrorKind::VersionError, &SshErrorKind::VersionError) => true,
           (&SshErrorKind::KeyExchangeError, &SshErrorKind::KeyExchangeError) => true,
           _ => false
       }
    }
}




impl SshErrorKind {
    fn as_str(&self) -> &'static str {
        match self {
            SshErrorKind::EncryptionError => "Key generation or encryption or decryption is abnormal",
            SshErrorKind::FromUtf8Error => "The UTF8 conversion is abnormal",
            SshErrorKind::ChannelFailureError => "Connection channel failure",
            SshErrorKind::PasswordError => "Password authentication failed",
            SshErrorKind::UserNullError => "The user cannot be empty",
            SshErrorKind::PasswordNullError => "The password cannot be empty",
            SshErrorKind::SignatureError => "Signature verification failure",
            SshErrorKind::VersionError => "Version not supported",
            SshErrorKind::KeyExchangeError => "The key exchange algorithm does not match",
            _ => ""
        }
    }
}

impl Error for SshError {
    fn description(&self) -> &str {
        match &self.inner {
            SshErrorKind::IoError(io) => io.description(),
            _ => self.inner.as_str()
        }
    }
}

impl From<SshErrorKind> for SshError {
    fn from(kind: SshErrorKind) -> SshError {
        SshError {
            inner: kind
        }
    }
}

impl From<io::Error> for SshError {
    fn from(kind: io::Error) -> Self {
        SshError {
            inner: SshErrorKind::IoError(io::Error::from(kind.kind()))
        }
    }
}

#[test]
fn test() {
    match get_error() {
        Ok(_) => {}
        Err(e) => {
            if e.kind() == SshErrorKind::SignatureError { }
        }
    }
    //get_error().unwrap();
}

fn get_error() -> Result<(), SshError> {
    return Err(SshError::from(SshErrorKind::EncryptionError))
    // return Err(SshError::from(SshErrorKind::IoError(io::Error::from(io::ErrorKind::WouldBlock))))
}