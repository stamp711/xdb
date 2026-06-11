/// Marker for types that are valid for any bit pattern and contain no padding,
/// so they can be round-tripped through raw bytes. The impls below are the
/// whole sanctioned list; everything else must parse through `Cursor`.
pub trait Pod: Copy {}

impl Pod for u8 {}
impl Pod for u16 {}
impl Pod for u32 {}
impl Pod for u64 {}
impl Pod for i8 {}
impl Pod for i16 {}
impl Pod for i32 {}
impl Pod for i64 {}
impl Pod for f32 {}
impl Pod for f64 {}
impl Pod for [u8; 8] {}
impl Pod for [u8; 16] {}
impl Pod for libc::user_regs_struct {}
impl Pod for libc::user_fpregs_struct {}

pub fn from_bytes<T: Pod>(bytes: &[u8]) -> T {
    assert!(bytes.len() >= size_of::<T>());
    // SAFETY: length checked above; T: Pod means any bit pattern is valid.
    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) }
}

pub fn as_bytes<T: Pod>(value: &T) -> &[u8] {
    // SAFETY: T: Pod has no padding, so all bytes are initialized.
    unsafe { std::slice::from_raw_parts(std::ptr::from_ref(value).cast::<u8>(), size_of::<T>()) }
}

pub fn to_byte64<T: Pod>(value: T) -> [u8; 8] {
    let mut out = [0u8; 8];
    let bytes = as_bytes(&value);
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

pub fn to_byte128<T: Pod>(value: T) -> [u8; 16] {
    let mut out = [0u8; 16];
    let bytes = as_bytes(&value);
    out[..bytes.len()].copy_from_slice(bytes);
    out
}
