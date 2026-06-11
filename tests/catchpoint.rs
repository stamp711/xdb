mod common;

use std::collections::HashSet;

use common::target_path;
use nix::sys::signal::Signal;
use xdb::syscalls::syscall_name_to_id;
use xdb::{Process, ProcessState, SyscallCatchPolicy, TrapType};

#[test]
fn syscall_catchpoint() {
    let dev_null = std::fs::File::options()
        .write(true)
        .open("/dev/null")
        .unwrap();
    let mut process = Process::launch(
        &target_path("anti_debugger"),
        true,
        Some(std::os::fd::AsFd::as_fd(&dev_null)),
    )
    .unwrap();

    let write_syscall = syscall_name_to_id("write").unwrap();
    process.set_syscall_catch_policy(SyscallCatchPolicy::Some(HashSet::from([write_syscall])));

    process.resume().unwrap();
    let reason = process.wait_on_signal().unwrap();
    assert_eq!(reason.state, ProcessState::Stopped);
    assert_eq!(reason.info, Signal::SIGTRAP as u8);
    assert_eq!(reason.trap, Some(TrapType::Syscall));
    let syscall = reason.syscall.unwrap();
    assert_eq!(syscall.id, write_syscall);
    assert!(syscall.is_entry);

    process.resume().unwrap();
    let reason = process.wait_on_signal().unwrap();
    assert_eq!(reason.trap, Some(TrapType::Syscall));
    let syscall = reason.syscall.unwrap();
    assert_eq!(syscall.id, write_syscall);
    assert!(!syscall.is_entry);
}
