use crate::bit::{self, from_bytes};
use crate::error::{Error, Result};
use crate::register_info::{RegisterFormat, RegisterId, RegisterInfo};

pub(crate) const USER_SIZE: usize = size_of::<libc::user>();
pub(crate) const USER_REGS_OFFSET: usize = std::mem::offset_of!(libc::user, regs);
pub(crate) const USER_I387_OFFSET: usize = std::mem::offset_of!(libc::user, i387);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RegisterValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    LongDouble([u8; 16]),
    Byte64([u8; 8]),
    Byte128([u8; 16]),
}

impl RegisterValue {
    pub fn byte_width(&self) -> usize {
        match self {
            Self::U8(_) | Self::I8(_) => 1,
            Self::U16(_) | Self::I16(_) => 2,
            Self::U32(_) | Self::I32(_) | Self::F32(_) => 4,
            Self::U64(_) | Self::I64(_) | Self::F64(_) | Self::Byte64(_) => 8,
            Self::LongDouble(_) | Self::Byte128(_) => 16,
        }
    }
}

macro_rules! value_try_from {
    ($($ty:ty => $variant:ident),* $(,)?) => {
        $(impl TryFrom<RegisterValue> for $ty {
            type Error = Error;

            fn try_from(value: RegisterValue) -> Result<Self> {
                match value {
                    RegisterValue::$variant(v) => Ok(v),
                    other => Err(Error::new(format!(
                        concat!("Register value is not ", stringify!($variant), ": {:?}"),
                        other
                    ))),
                }
            }
        })*
    };
}

value_try_from! {
    u8 => U8,
    u16 => U16,
    u32 => U32,
    u64 => U64,
    f64 => F64,
}

impl TryFrom<RegisterValue> for [u8; 8] {
    type Error = Error;

    fn try_from(value: RegisterValue) -> Result<Self> {
        match value {
            RegisterValue::Byte64(v) => Ok(v),
            other => Err(Error::new(format!(
                "Register value is not Byte64: {other:?}"
            ))),
        }
    }
}

impl TryFrom<RegisterValue> for [u8; 16] {
    type Error = Error;

    fn try_from(value: RegisterValue) -> Result<Self> {
        match value {
            RegisterValue::Byte128(v) | RegisterValue::LongDouble(v) => Ok(v),
            other => Err(Error::new(format!(
                "Register value is not Byte128: {other:?}"
            ))),
        }
    }
}

/// The cached `user` area of the inferior, stored as raw bytes so that padding
/// never holds uninitialized memory. All access goes through the offsets in
/// the register table.
pub struct Registers {
    pub(crate) data: [u8; USER_SIZE],
}

impl Registers {
    pub(crate) fn new() -> Self {
        Self {
            data: [0; USER_SIZE],
        }
    }

    pub fn read(&self, info: &RegisterInfo) -> Result<RegisterValue> {
        let bytes = &self.data[info.offset..info.offset + info.size];
        match info.format {
            RegisterFormat::Uint => match info.size {
                1 => Ok(RegisterValue::U8(from_bytes(bytes))),
                2 => Ok(RegisterValue::U16(from_bytes(bytes))),
                4 => Ok(RegisterValue::U32(from_bytes(bytes))),
                8 => Ok(RegisterValue::U64(from_bytes(bytes))),
                size => Err(Error::new(format!(
                    "Unexpected size for uint register format: {size}"
                ))),
            },
            RegisterFormat::DoubleFloat => Ok(RegisterValue::F64(from_bytes(bytes))),
            RegisterFormat::LongDouble => Ok(RegisterValue::LongDouble(from_bytes(bytes))),
            RegisterFormat::Vector => match info.size {
                8 => Ok(RegisterValue::Byte64(from_bytes(bytes))),
                16 => Ok(RegisterValue::Byte128(from_bytes(bytes))),
                size => Err(Error::new(format!(
                    "Unexpected size for vector register format: {size}"
                ))),
            },
        }
    }

    pub fn read_by_id(&self, id: RegisterId) -> Result<RegisterValue> {
        self.read(id.info())
    }

    pub fn read_by_id_as<T>(&self, id: RegisterId) -> Result<T>
    where
        T: TryFrom<RegisterValue, Error = Error>,
    {
        T::try_from(self.read_by_id(id)?)
    }
}

/// Widen a value to a full 16-byte register image: floats convert to the
/// register's float format, signed integers sign-extend to the register size,
/// everything else is used verbatim and zero-padded.
pub(crate) fn widen(info: &RegisterInfo, value: RegisterValue) -> Result<[u8; 16]> {
    if value.byte_width() > info.size {
        return Err(Error::new(format!(
            "Unexpected size for value in write operation: val size {} vs register size {}",
            value.byte_width(),
            info.size
        )));
    }

    let widened = match value {
        RegisterValue::F32(v) => widen_float(info, f64::from(v)),
        RegisterValue::F64(v) => widen_float(info, v),
        RegisterValue::I8(v) => widen_signed(info, i64::from(v)),
        RegisterValue::I16(v) => widen_signed(info, i64::from(v)),
        RegisterValue::I32(v) => widen_signed(info, i64::from(v)),
        RegisterValue::I64(v) => widen_signed(info, v),
        RegisterValue::U8(v) => bit::to_byte128(v),
        RegisterValue::U16(v) => bit::to_byte128(v),
        RegisterValue::U32(v) => bit::to_byte128(v),
        RegisterValue::U64(v) => bit::to_byte128(v),
        RegisterValue::Byte64(v) => bit::to_byte128(v),
        RegisterValue::LongDouble(v) | RegisterValue::Byte128(v) => v,
    };
    Ok(widened)
}

fn widen_float(info: &RegisterInfo, value: f64) -> [u8; 16] {
    match info.format {
        RegisterFormat::DoubleFloat => bit::to_byte128(value),
        RegisterFormat::LongDouble => f80_from_f64(value),
        _ => bit::to_byte128(value),
    }
}

fn widen_signed(info: &RegisterInfo, value: i64) -> [u8; 16] {
    if info.format == RegisterFormat::Uint {
        match info.size {
            1 => bit::to_byte128(value as u8),
            2 => bit::to_byte128(value as u16),
            4 => bit::to_byte128(value as u32),
            _ => bit::to_byte128(value as u64),
        }
    } else {
        bit::to_byte128(value)
    }
}

/// Encode an `f64` as an x87 80-bit extended float (in 16 bytes, low 10 used).
pub fn f80_from_f64(value: f64) -> [u8; 16] {
    let bits = value.to_bits();
    let sign = (bits >> 63) as u16;
    let exp = ((bits >> 52) & 0x7FF) as i32;
    let frac = bits & ((1u64 << 52) - 1);

    let (exp80, mantissa): (u16, u64) = if exp == 0x7FF {
        // Infinity or NaN: x87 wants the explicit integer bit set.
        (0x7FFF, (1u64 << 63) | (frac << 11))
    } else if exp == 0 {
        if frac == 0 {
            (0, 0)
        } else {
            // Subnormal f64 becomes a normal f80.
            let msb = 63 - frac.leading_zeros() as i32;
            let unbiased = msb - 1074;
            ((unbiased + 16383) as u16, frac << (63 - msb))
        }
    } else {
        (((exp - 1023) + 16383) as u16, (1u64 << 63) | (frac << 11))
    };

    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&mantissa.to_le_bytes());
    out[8..10].copy_from_slice(&((sign << 15) | exp80).to_le_bytes());
    out
}

/// Decode an x87 80-bit extended float to the nearest `f64` (truncating the
/// extra mantissa bits).
pub fn f80_to_f64(bytes: [u8; 16]) -> f64 {
    let mantissa = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let sign_exp = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    let sign = u64::from(sign_exp >> 15);
    let exp = i32::from(sign_exp & 0x7FFF);

    if exp == 0 && mantissa == 0 {
        return f64::from_bits(sign << 63);
    }
    if exp == 0x7FFF {
        let frac = (mantissa << 1) >> 12;
        let bits = (sign << 63) | (0x7FFu64 << 52) | frac;
        return f64::from_bits(bits);
    }

    let exp64 = exp - 16383 + 1023;
    if exp64 >= 0x7FF {
        return f64::from_bits((sign << 63) | (0x7FFu64 << 52));
    }
    if exp64 <= 0 {
        return f64::from_bits(sign << 63);
    }

    let frac = (mantissa & !(1u64 << 63)) >> 11;
    f64::from_bits((sign << 63) | ((exp64 as u64) << 52) | frac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f80_round_trips() {
        for value in [
            0.0,
            -0.0,
            1.0,
            -1.5,
            42.25,
            12.21,
            f64::INFINITY,
            f64::MIN_POSITIVE,
        ] {
            assert_eq!(f80_to_f64(f80_from_f64(value)), value);
        }
        assert!(f80_to_f64(f80_from_f64(f64::NAN)).is_nan());
    }
}
