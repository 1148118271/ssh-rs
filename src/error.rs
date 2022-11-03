use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::{fmt, io};

pub type SshResult<I> = Result<I, SshError>;

pub struct SshError {
    inner: SshErrorKind,
}

impl SshError {
    pub fn kind(&self) -> &SshErrorKind {
        &self.inner
    }
}

impl Debug for SshError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.inner {
            SshErrorKind::IoError(ie) => {
                write!(f, r"IoError: {{ Kind({:?}), Message({}) }}", ie.kind(), ie)
            }
            _ => {
                write!(
                    f,
                    r"Error: {{ Kind({:?}), Message({}) }}",
                    self.inner,
                    self.inner
                )
            }
        }
    }
}

impl Display for SshError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.inner {
            SshErrorKind::IoError(ie) => {
                write!(f, r"IoError: {{ Kind({:?}) }}", ie.kind())
            }
            _ => {
                write!(f, r"Error: {{ Kind({:?}) }}", self.inner)
            }
        }
    }
}

#[derive(Debug)]
pub enum SshErrorKind {
    IoError(io::Error),
    SshError(String),
    Timeout,
}

impl PartialEq<Self> for SshErrorKind {
    fn eq(&self, other: &Self) -> bool {
        match (&self, &other) {
            (&SshErrorKind::SshError(v1), &SshErrorKind::SshError(v2)) => v1.eq(v2),
            (&SshErrorKind::IoError(io1), &SshErrorKind::IoError(io2)) => io1.kind() == io2.kind(),
            (&SshErrorKind::Timeout, &SshErrorKind::Timeout) => true,
            _ => false,
        }
    }
}

impl fmt::Display for SshErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            SshErrorKind::SshError(e) => write!(f, "{}", e),
            SshErrorKind::IoError(v) => write!(f, "{}", v),
            SshErrorKind::Timeout => write!(f, "time out."),
        }
    }
}

impl Error for SshError {}

impl From<SshErrorKind> for SshError {
    fn from(kind: SshErrorKind) -> SshError {
        SshError { inner: kind }
    }
}

impl From<&str> for SshError {
    fn from(kind: &str) -> SshError {
        SshError {
            inner: SshErrorKind::SshError(kind.to_string()),
        }
    }
}

impl From<String> for SshError {
    fn from(kind: String) -> SshError {
        SshError {
            inner: SshErrorKind::SshError(kind),
        }
    }
}

impl From<io::Error> for SshError {
    fn from(kind: io::Error) -> Self {
        SshError {
            inner: SshErrorKind::IoError(io::Error::from(kind.kind())),
        }
    }
}
