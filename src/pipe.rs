use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use nix::fcntl::OFlag;
use nix::unistd;

use crate::error::{ErrnoContext, Error, Result};

pub struct Pipe {
    read: Option<OwnedFd>,
    write: Option<OwnedFd>,
}

impl Pipe {
    const BUFFER_SIZE: usize = 1024;

    pub fn new(close_on_exec: bool) -> Result<Self> {
        let flags = if close_on_exec {
            OFlag::O_CLOEXEC
        } else {
            OFlag::empty()
        };
        let (read, write) = unistd::pipe2(flags).context("Pipe creation failed")?;
        Ok(Self {
            read: Some(read),
            write: Some(write),
        })
    }

    pub fn write_end(&self) -> Option<BorrowedFd<'_>> {
        self.write.as_ref().map(AsFd::as_fd)
    }

    pub fn close_read(&mut self) {
        self.read = None;
    }

    pub fn close_write(&mut self) {
        self.write = None;
    }

    pub fn read(&mut self) -> Result<Vec<u8>> {
        let fd = self
            .read
            .as_ref()
            .ok_or_else(|| Error::new("Read end of pipe is closed"))?;
        let mut buffer = [0u8; Self::BUFFER_SIZE];
        let bytes_read = unistd::read(fd, &mut buffer).context("Read from pipe failed")?;
        Ok(buffer[..bytes_read].to_vec())
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<()> {
        let fd = self
            .write
            .as_ref()
            .ok_or_else(|| Error::new("Write end of pipe is closed"))?;
        let bytes_written = unistd::write(fd, buf).context("Write to pipe failed")?;
        if bytes_written != buf.len() {
            return Err(Error::new("Partial write to pipe"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_round_trips() {
        let mut pipe = Pipe::new(false).unwrap();
        pipe.write(b"hello there").unwrap();
        assert_eq!(pipe.read().unwrap(), b"hello there");
    }

    #[test]
    fn read_after_close_fails() {
        let mut pipe = Pipe::new(false).unwrap();
        pipe.close_read();
        assert!(pipe.read().is_err());
    }
}
