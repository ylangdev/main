use shared::byte_order::ByteOrder;

use std::ffi::CStr;

pub fn u8_at(buffer: &[u8], offset: usize) -> u8 {
    buffer[offset]
}

pub fn u16_at(o: ByteOrder, buffer: &[u8], offset: usize) -> u16 {
    o.read_u16([buffer[offset], buffer[offset + 1]])
}

pub fn u32_at(o: ByteOrder, buffer: &[u8], offset: usize) -> u32 {
    o.read_u32([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ])
}

pub fn u64_at(o: ByteOrder, buffer: &[u8], offset: usize) -> u64 {
    o.read_u64([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ])
}
pub fn name_at<'a>(strtab: &'a [u8], offset: u32) -> Option<&'a CStr> {
    let start = usize::try_from(offset).ok()?;
    CStr::from_bytes_until_nul(strtab.get(start..)?).ok()
}
