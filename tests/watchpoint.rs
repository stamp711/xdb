mod common;

use common::target_path;
use xdb::{Pipe, Process, StoppointMode, VirtAddr};

fn launch_anti_debugger() -> (Process, Pipe, VirtAddr) {
    let mut channel = Pipe::new(false).unwrap();
    let mut process = Process::launch(
        &target_path("anti_debugger"),
        true,
        Some(channel.write_end().unwrap()),
    )
    .unwrap();
    channel.close_write();

    process.resume().unwrap();
    process.wait_on_signal().unwrap();

    let bytes = channel.read().unwrap();
    let func = VirtAddr(u64::from_le_bytes(bytes[..8].try_into().unwrap()));
    (process, channel, func)
}

#[test]
fn hardware_breakpoint_evades_memory_checksums() {
    let (mut process, mut channel, func) = launch_anti_debugger();

    // A software breakpoint patches the code, which the checksum detects.
    let soft = process.create_breakpoint_site(func, false, false).unwrap();
    process.enable_breakpoint_site(soft).unwrap();
    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(channel.read().unwrap(), b"Putting pepperoni on pizza...\n");

    // A hardware breakpoint leaves the code untouched.
    process.remove_breakpoint_site_by_id(soft).unwrap();
    let hard = process.create_breakpoint_site(func, true, false).unwrap();
    process.enable_breakpoint_site(hard).unwrap();
    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(process.get_pc().unwrap(), func);

    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(channel.read().unwrap(), b"Putting pineapple on pizza...\n");
}

#[test]
fn watchpoint_detects_read() {
    let (mut process, mut channel, func) = launch_anti_debugger();

    let watchpoint = process
        .create_watchpoint(func, StoppointMode::ReadWrite, 1)
        .unwrap();
    process.enable_watchpoint(watchpoint).unwrap();

    // The checksum reads the watched byte, tripping the watchpoint.
    process.resume().unwrap();
    process.wait_on_signal().unwrap();

    // Step past the read, then catch the function entry with a software breakpoint.
    process.step_instruction().unwrap();
    let bp = process.create_breakpoint_site(func, false, false).unwrap();
    process.enable_breakpoint_site(bp).unwrap();

    process.resume().unwrap();
    let reason = process.wait_on_signal().unwrap();
    assert!(reason.is_trapped());

    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(channel.read().unwrap(), b"Putting pineapple on pizza...\n");
}
