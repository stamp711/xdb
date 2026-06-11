use std::fmt;

use nix::errno::Errno;

#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::new(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) trait ErrnoContext<T> {
    fn context(self, prefix: &str) -> Result<T>;
}

impl<T> ErrnoContext<T> for std::result::Result<T, Errno> {
    fn context(self, prefix: &str) -> Result<T> {
        self.map_err(|errno| Error::new(format!("{prefix}: {}", errno.desc())))
    }
}
