mod common;

use common::target_path;
use xdb::bit::{to_byte64, to_byte128};
use xdb::register_info::RegisterId;
use xdb::registers::f80_to_f64;
use xdb::{Pipe, Process, RegisterValue};

#[test]
fn write_registers() {
    let mut channel = Pipe::new(false).unwrap();
    let mut process = Process::launch(
        &target_path("reg_write"),
        true,
        Some(channel.write_end().unwrap()),
    )
    .unwrap();
    channel.close_write();

    process.resume().unwrap();
    process.wait_on_signal().unwrap();

    process
        .write_register_by_id(RegisterId::rsi, RegisterValue::U64(0xdeadbeef))
        .unwrap();
    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(channel.read().unwrap(), b"0xdeadbeef");

    process
        .write_register_by_id(RegisterId::mm0, RegisterValue::U64(0xba5e_ba11))
        .unwrap();
    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(channel.read().unwrap(), b"0xba5eba11");

    process
        .write_register_by_id(RegisterId::xmm0, RegisterValue::F64(42.24))
        .unwrap();
    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(channel.read().unwrap(), b"42.24");

    process
        .write_register_by_id(RegisterId::st0, RegisterValue::F64(12.21))
        .unwrap();
    // Bits 11-13 of the status word track the top of the x87 stack; the tag
    // word marks st0 valid (00) and the rest empty (11).
    process
        .write_register_by_id(RegisterId::fsw, RegisterValue::U16(0b0011_1000_0000_0000))
        .unwrap();
    process
        .write_register_by_id(RegisterId::ftw, RegisterValue::U16(0b0011_1111_1111_1111))
        .unwrap();
    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(channel.read().unwrap(), b"12.21");
}

#[test]
fn read_registers() {
    let mut process = Process::launch(&target_path("reg_read"), true, None).unwrap();

    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(
        process.registers().read_as::<u64>(RegisterId::r13).unwrap(),
        0xdead_beef_cafe_babe
    );

    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(
        process
            .registers()
            .read_as::<u32>(RegisterId::r13d)
            .unwrap(),
        0xabcd_ef01
    );

    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(
        process
            .registers()
            .read_as::<u16>(RegisterId::r13w)
            .unwrap(),
        0x1234
    );

    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(
        process.registers().read_as::<u8>(RegisterId::r13b).unwrap(),
        42
    );

    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(
        process.registers().read_as::<u8>(RegisterId::ah).unwrap(),
        41
    );

    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(
        process
            .registers()
            .read_as::<[u8; 8]>(RegisterId::mm0)
            .unwrap(),
        to_byte64(0xba5e_ba11_u64)
    );

    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert_eq!(
        process
            .registers()
            .read_as::<[u8; 16]>(RegisterId::xmm0)
            .unwrap(),
        to_byte128(42.25_f64)
    );

    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    let st0 = process.registers().read(RegisterId::st0).unwrap();
    let RegisterValue::LongDouble(bytes) = st0 else {
        panic!("expected long double, got {st0:?}");
    };
    assert_eq!(f80_to_f64(bytes), 42.25);
}
