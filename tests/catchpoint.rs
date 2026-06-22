mod common;

use std::collections::HashSet;

use common::target_path;
use xdb::syscalls::syscall_name_to_id;
use xdb::{Process, StopReason, SyscallCatchPolicy, TrapType};

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
    let StopReason::Trapped(TrapType::Syscall(syscall)) = &reason else {
        panic!("expected a syscall trap");
    };
    assert_eq!(syscall.id, write_syscall);
    assert!(syscall.is_entry);

    process.resume().unwrap();
    let reason = process.wait_on_signal().unwrap();
    let StopReason::Trapped(TrapType::Syscall(syscall)) = &reason else {
        panic!("expected a syscall trap");
    };
    assert_eq!(syscall.id, write_syscall);
    assert!(!syscall.is_entry);
}
