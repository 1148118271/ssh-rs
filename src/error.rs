use std::{
    error::Error,
    fmt::{self, Debug, Display, Formatter},
    io,
    sync::mpsc::{RecvError, SendError},
};

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
                    self.inner, self.inner
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
    SendError(String),
    RecvError(String),
    Timeout,
}

impl fmt::Display for SshErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            SshErrorKind::SshError(e) => write!(f, "{}", e),
            SshErrorKind::IoError(v) => write!(f, "{}", v),
            SshErrorKind::SendError(e) => write!(f, "{}", e),
            SshErrorKind::RecvError(e) => write!(f, "{}", e),
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

impl<T> From<SendError<T>> for SshError {
    fn from(e: SendError<T>) -> Self {
        Self {
            inner: SshErrorKind::SendError(e.to_string()),
        }
    }
}

impl From<RecvError> for SshError {
    fn from(e: RecvError) -> Self {
        Self {
            inner: SshErrorKind::RecvError(e.to_string()),
        }
    }
}
