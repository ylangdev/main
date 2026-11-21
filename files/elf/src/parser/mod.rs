pub mod b32;
pub mod b64;
pub mod shared;

use ::shared::byte_order::ByteOrder;
use ::shared::structs::parse_static_struct;

use crate::parser::shared::slice_at;
use crate::types::header::{
    Ehdr32, Ehdr64, ElfClass, ElfData, ElfType, Ident, EHDR32_SIZE, EHDR64_SIZE, EI_NIDENT,
    EV_CURRENT,
};
use crate::types::machine::Machine;
use crate::{ElfError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfHeader {
    pub file_type: ElfType,
    pub machine: Machine,
    pub version: u32,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfFile<'a> {
    buf: &'a [u8],
    pub class: ElfClass,
    pub data: ElfData,
    pub byte_order: ByteOrder,
    pub ehdr: ElfHeader,
}

impl<'a> ElfFile<'a> {
    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }
}

pub fn parse_elf(bytes: &[u8]) -> Result<ElfFile<'_>> {
    let ident = Ident::parse(bytes)?;
    ident.check_magic()?;

    let class = ident.class()?;
    let data = ident.data()?;
    let byte_order = match data {
        ElfData::Little => ByteOrder::LittleEndian,
        ElfData::Big => ByteOrder::BigEndian,
    };

    let ehdr = match class {
        ElfClass::Elf32 => parse_ehdr32(byte_order, bytes)?,
        ElfClass::Elf64 => parse_ehdr64(byte_order, bytes)?,
    };

    Ok(ElfFile {
        buf: bytes,
        class,
        data,
        byte_order,
        ehdr,
    })
}

fn parse_ehdr32(byte_order: ByteOrder, bytes: &[u8]) -> Result<ElfHeader> {
    let body_len = EHDR32_SIZE - EI_NIDENT;
    let raw_slice = slice_at(bytes, "ELF32 header", EI_NIDENT as u64, body_len as u64)
        .map_err(|_| ElfError::UnexpectedEof {
            offset: 0,
            needed: EHDR32_SIZE,
            available: bytes.len(),
        })?;

    let raw = parse_static_struct::<36, Ehdr32>(byte_order, raw_slice)
        .ok_or(ElfError::UnexpectedEof {
            offset: 0,
            needed: EHDR32_SIZE,
            available: bytes.len(),
        })?;

    if raw.e_version != u32::from(EV_CURRENT) {
        return Err(ElfError::UnsupportedVersion(raw.e_version));
    }

    if usize::from(raw.e_ehsize) != EHDR32_SIZE {
        return Err(ElfError::InvalidHeaderSize {
            expected: EHDR32_SIZE as u16,
            found: raw.e_ehsize,
        });
    }

    Ok(ElfHeader {
        file_type: ElfType::from(raw.e_type),
        machine: Machine::from(raw.e_machine),
        version: raw.e_version,
        entry: u64::from(raw.e_entry),
        phoff: u64::from(raw.e_phoff),
        shoff: u64::from(raw.e_shoff),
        flags: raw.e_flags,
        ehsize: raw.e_ehsize,
        phentsize: raw.e_phentsize,
        phnum: raw.e_phnum,
        shentsize: raw.e_shentsize,
        shnum: raw.e_shnum,
        shstrndx: raw.e_shstrndx,
    })
}

fn parse_ehdr64(byte_order: ByteOrder, bytes: &[u8]) -> Result<ElfHeader> {
    let body_len = EHDR64_SIZE - EI_NIDENT;
    let raw_slice = slice_at(bytes, "ELF64 header", EI_NIDENT as u64, body_len as u64)
        .map_err(|_| ElfError::UnexpectedEof {
            offset: 0,
            needed: EHDR64_SIZE,
            available: bytes.len(),
        })?;

    let raw = parse_static_struct::<48, Ehdr64>(byte_order, raw_slice)
        .ok_or(ElfError::UnexpectedEof {
            offset: 0,
            needed: EHDR64_SIZE,
            available: bytes.len(),
        })?;

    if raw.e_version != u32::from(EV_CURRENT) {
        return Err(ElfError::UnsupportedVersion(raw.e_version));
    }

    if usize::from(raw.e_ehsize) != EHDR64_SIZE {
        return Err(ElfError::InvalidHeaderSize {
            expected: EHDR64_SIZE as u16,
            found: raw.e_ehsize,
        });
    }

    Ok(ElfHeader {
        file_type: ElfType::from(raw.e_type),
        machine: Machine::from(raw.e_machine),
        version: raw.e_version,
        entry: raw.e_entry,
        phoff: raw.e_phoff,
        shoff: raw.e_shoff,
        flags: raw.e_flags,
        ehsize: raw.e_ehsize,
        phentsize: raw.e_phentsize,
        phnum: raw.e_phnum,
        shentsize: raw.e_shentsize,
        shnum: raw.e_shnum,
        shstrndx: raw.e_shstrndx,
    })
}
