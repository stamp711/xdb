pub mod bit;
pub mod error;
mod inferior;
pub mod parse;
pub mod pipe;
pub mod process;
pub mod register_info;
pub mod registers;

pub use error::{Error, Result};
pub use nix::unistd::Pid;
pub use pipe::Pipe;
pub use process::{Process, ProcessState, StopReason};
pub use register_info::{REGISTER_INFOS, RegisterId, RegisterInfo};
pub use registers::{RegisterValue, Registers};
