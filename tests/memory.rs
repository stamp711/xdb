mod common;

use common::target_path;
use xdb::{Pipe, Process, VirtAddr};

fn read_pointer(channel: &mut Pipe) -> VirtAddr {
    let bytes = channel.read().unwrap();
    VirtAddr(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
}

#[test]
fn read_and_write_memory() {
    let mut channel = Pipe::new(false).unwrap();
    let mut process = Process::launch(
        &target_path("memory"),
        true,
        Some(channel.write_end().unwrap()),
    )
    .unwrap();
    channel.close_write();

    process.resume().unwrap();
    process.wait_on_signal().unwrap();

    let a_address = read_pointer(&mut channel);
    assert_eq!(
        process.read_memory_as::<u64>(a_address).unwrap(),
        0xcafe_cafe
    );

    process.resume().unwrap();
    process.wait_on_signal().unwrap();

    let b_address = read_pointer(&mut channel);
    process.write_memory(b_address, b"test\0").unwrap();

    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(channel.read().unwrap(), b"test");
}
