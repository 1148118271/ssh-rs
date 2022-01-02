use std::fmt::{Debug, Display, Formatter};
use std::{fmt, io};

pub struct SshError {
    inner: SshErrorKind
}

impl SshError {
    pub fn kind(&self) -> SshErrorKind {
        match &self.inner {
            SshErrorKind::IoError(ie) => {
                SshErrorKind::IoError(io::Error::from(ie.kind()))
            }
            _ => { unsafe {std::ptr::read(&self.inner as *const SshErrorKind)} }
        }
    }
}


impl Debug for SshError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.inner, f)
    }
}

impl Display for SshError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}


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
}


impl Debug for SshErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SshErrorKind::IoError(ie) => {
                write!(f, r"IoError: {{ Kind({:?}), Message({})}}", ie.kind(), ie.to_string())
            }
            _ => { write!(f, r"IoError: {{ Kind({:?}), Message({}) }}", self, self.as_str()) }
        }
    }
}

impl Display for SshErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SshErrorKind::IoError(ie) => {
                write!(f, r"IoError: {{ Kind({:?}) }}", ie.kind())
            }
            _ => { write!(f, r"IoError: {{ Kind({:?}) }}", self) }
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
            _ => ""
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