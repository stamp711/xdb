use xdb::register_info::{RegisterFormat, RegisterId, RegisterInfo, RegisterKind};
use xdb::registers::f80_to_f64;
use xdb::{Error, Process, REGISTER_INFOS, RegisterValue, parse};

pub fn handle(process: &mut Process, args: &[&str]) -> xdb::Result<()> {
    match args.get(1).copied() {
        Some("read") => read(process, args),
        Some("write") => write(process, args),
        _ => {
            super::print_help(&["help", "register"]);
            Ok(())
        }
    }
}

fn read(process: &Process, args: &[&str]) -> xdb::Result<()> {
    match args.get(2).copied() {
        None | Some("all") => {
            let all = args.get(2).is_some();
            for info in REGISTER_INFOS {
                let is_gpr = info.kind == RegisterKind::Gpr && info.id != RegisterId::orig_rax;
                if all || is_gpr {
                    let value = process.registers().read(info)?;
                    println!("{}:\t{}", info.name, format_value(value));
                }
            }
            Ok(())
        }
        Some(name) => {
            let Some(info) = xdb::register_info::register_info_by_name(name) else {
                eprintln!("No such register");
                return Ok(());
            };
            let value = process.registers().read(info)?;
            println!("{}:\t{}", info.name, format_value(value));
            Ok(())
        }
    }
}

fn write(process: &mut Process, args: &[&str]) -> xdb::Result<()> {
    let (Some(name), Some(value_str)) = (args.get(2).copied(), args.get(3).copied()) else {
        super::print_help(&["help", "register"]);
        return Ok(());
    };

    let Some(info) = xdb::register_info::register_info_by_name(name) else {
        eprintln!("No such register");
        return Ok(());
    };

    let value = parse_register_value(info, value_str)?;
    process.write_register(info, value)
}

fn parse_register_value(info: &RegisterInfo, s: &str) -> xdb::Result<RegisterValue> {
    let invalid = || Error::new("Invalid format");
    let radix = if s.starts_with("0x") { 16 } else { 10 };

    match info.format {
        RegisterFormat::Uint => match info.size {
            1 => parse::to_integral::<u8>(s, radix)
                .map(RegisterValue::U8)
                .ok_or_else(invalid),
            2 => parse::to_integral::<u16>(s, radix)
                .map(RegisterValue::U16)
                .ok_or_else(invalid),
            4 => parse::to_integral::<u32>(s, radix)
                .map(RegisterValue::U32)
                .ok_or_else(invalid),
            8 => parse::to_integral::<u64>(s, radix)
                .map(RegisterValue::U64)
                .ok_or_else(invalid),
            _ => Err(invalid()),
        },
        RegisterFormat::DoubleFloat | RegisterFormat::LongDouble => parse::to_float(s)
            .map(RegisterValue::F64)
            .ok_or_else(invalid),
        RegisterFormat::Vector => match info.size {
            8 => parse::parse_vector_fixed::<8>(s).map(RegisterValue::Byte64),
            16 => parse::parse_vector_fixed::<16>(s).map(RegisterValue::Byte128),
            _ => Err(invalid()),
        },
    }
}

fn format_value(value: RegisterValue) -> String {
    match value {
        RegisterValue::U8(v) => format!("{v:#04x}"),
        RegisterValue::U16(v) => format!("{v:#06x}"),
        RegisterValue::U32(v) => format!("{v:#010x}"),
        RegisterValue::U64(v) => format!("{v:#018x}"),
        RegisterValue::I8(v) => format!("{v}"),
        RegisterValue::I16(v) => format!("{v}"),
        RegisterValue::I32(v) => format!("{v}"),
        RegisterValue::I64(v) => format!("{v}"),
        RegisterValue::F32(v) => format!("{v}"),
        RegisterValue::F64(v) => format!("{v}"),
        RegisterValue::LongDouble(bytes) => format!("{}", f80_to_f64(bytes)),
        RegisterValue::Byte64(bytes) => format_byte_array(&bytes),
        RegisterValue::Byte128(bytes) => format_byte_array(&bytes),
    }
}

fn format_byte_array(bytes: &[u8]) -> String {
    let parts: Vec<String> = bytes.iter().map(|b| format!("{b:#04x}")).collect();
    format!("[{}]", parts.join(", "))
}
