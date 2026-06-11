use crate::error::{Error, Result};

pub trait ParseRadix: Sized {
    fn from_str_radix(s: &str, radix: u32) -> std::result::Result<Self, std::num::ParseIntError>;
}

macro_rules! impl_parse_radix {
    ($($ty:ty),*) => {
        $(impl ParseRadix for $ty {
            fn from_str_radix(s: &str, radix: u32) -> std::result::Result<Self, std::num::ParseIntError> {
                <$ty>::from_str_radix(s, radix)
            }
        })*
    };
}

impl_parse_radix!(u8, u16, u32, u64, usize, i8, i16, i32, i64);

pub fn to_integral<T: ParseRadix>(s: &str, radix: u32) -> Option<T> {
    let digits = if radix == 16 {
        s.strip_prefix("0x").unwrap_or(s)
    } else {
        s
    };
    T::from_str_radix(digits, radix).ok()
}

pub fn to_float(s: &str) -> Option<f64> {
    s.parse().ok()
}

/// Parse a byte vector literal like `[0xca, 0xfe]`.
pub fn parse_vector(s: &str) -> Result<Vec<u8>> {
    let invalid = || Error::new("Invalid vector value format");

    let inner = s
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or_else(invalid)?;
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }

    inner
        .split(',')
        .map(|part| {
            let part = part.trim();
            if !part.starts_with("0x") {
                return Err(invalid());
            }
            to_integral::<u8>(part, 16).ok_or_else(invalid)
        })
        .collect()
}

pub fn parse_vector_fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
    let bytes = parse_vector(s)?;
    bytes
        .try_into()
        .map_err(|_| Error::new("Invalid vector value format"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integral_parsing() {
        assert_eq!(to_integral::<u64>("0x2a", 16), Some(0x2a));
        assert_eq!(to_integral::<u64>("2a", 16), Some(0x2a));
        assert_eq!(to_integral::<u32>("42", 10), Some(42));
        assert_eq!(to_integral::<u8>("trailing1", 10), None);
    }

    #[test]
    fn vector_parsing() {
        assert_eq!(parse_vector("[0xca,0xfe]").unwrap(), vec![0xca, 0xfe]);
        assert_eq!(parse_vector("[0xca, 0xfe]").unwrap(), vec![0xca, 0xfe]);
        assert_eq!(parse_vector_fixed::<2>("[0x01,0x02]").unwrap(), [1, 2]);
        assert!(parse_vector("0xca,0xfe").is_err());
        assert!(parse_vector_fixed::<3>("[0x01,0x02]").is_err());
    }
}
