use std::ffi::CStr;

use shared::byte_order::ByteOrder;

use crate::{ElfError, Result};

pub fn u8_at(buffer: &[u8], offset: usize) -> u8 {
    buffer.get(offset).copied().unwrap_or_default()
}

pub fn u16_at(o: ByteOrder, buffer: &[u8], offset: usize) -> u16 {
    let bytes = buffer
        .get(offset..offset + 2)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0; 2]);
    o.read_u16(bytes)
}

pub fn u32_at(o: ByteOrder, buffer: &[u8], offset: usize) -> u32 {
    let bytes = buffer
        .get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0; 4]);
    o.read_u32(bytes)
}

pub fn u64_at(o: ByteOrder, buffer: &[u8], offset: usize) -> u64 {
    let bytes = buffer
        .get(offset..offset + 8)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0; 8]);
    o.read_u64(bytes)
}

pub fn slice_at<'a>(
    buf: &'a [u8],
    what: &'static str,
    offset: u64,
    size: u64,
) -> Result<&'a [u8]> {
    let start = usize::try_from(offset).map_err(|_| ElfError::Overflow { what })?;
    let len = usize::try_from(size).map_err(|_| ElfError::Overflow { what })?;
    let end = start.checked_add(len).ok_or(ElfError::Overflow { what })?;

    buf.get(start..end).ok_or(ElfError::OutOfBounds {
        what,
        offset,
        size,
        buffer_len: buf.len(),
    })
}

pub fn name_at(strtab: &[u8], offset: u32) -> Option<&CStr> {
    let slice = strtab.get(offset as usize..)?;
    CStr::from_bytes_until_nul(slice).ok()
}
