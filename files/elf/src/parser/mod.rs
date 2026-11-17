use crate::Result;
pub mod b64;
pub mod shared;

use ::shared::byte_order::ByteOrder;
use zerocopy::{BigEndian, LittleEndian};

use crate::types::header::{Ehdr32, Ehdr64, ElfClass, ElfData, ElfType, Ident};
use crate::types::machine::Machine;


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

    let ehdr = match (class, byte_order) {
        (ElfClass::Elf32, ByteOrder::LittleEndian) => parse_ehdr32::<LittleEndian>(bytes)?,
        (ElfClass::Elf32, ByteOrder::BigEndian) => parse_ehdr32::<BigEndian>(bytes)?,
        (ElfClass::Elf64, ByteOrder::LittleEndian) => parse_ehdr64::<LittleEndian>(bytes)?,
        (ElfClass::Elf64, ByteOrder::BigEndian) => parse_ehdr64::<BigEndian>(bytes)?,
    };

    Ok(ElfFile {
        buf: bytes,
        class,
        data,
        byte_order,
        ehdr,
    })
}

fn parse_ehdr32<O: zerocopy::ByteOrder>(bytes: &[u8]) -> Result<ElfHeader> {
    let raw = Ehdr32::<O>::parse(bytes)?;
    raw.validate()?;

    Ok(ElfHeader {
        file_type: raw.file_type(),
        machine: Machine::from(raw.e_machine.get()),
        version: raw.e_version.get(),
        entry: u64::from(raw.e_entry.get()),
        phoff: u64::from(raw.e_phoff.get()),
        shoff: u64::from(raw.e_shoff.get()),
        flags: raw.e_flags.get(),
        ehsize: raw.e_ehsize.get(),
        phentsize: raw.e_phentsize.get(),
        phnum: raw.e_phnum.get(),
        shentsize: raw.e_shentsize.get(),
        shnum: raw.e_shnum.get(),
        shstrndx: raw.e_shstrndx.get(),
    })
}

fn parse_ehdr64<O: zerocopy::ByteOrder>(bytes: &[u8]) -> Result<ElfHeader> {
    let raw = Ehdr64::<O>::parse(bytes)?;
    raw.validate()?;

    Ok(ElfHeader {
        file_type: raw.file_type(),
        machine: Machine::from(raw.e_machine.get()),
        version: raw.e_version.get(),
        entry: raw.e_entry.get(),
        phoff: raw.e_phoff.get(),
        shoff: raw.e_shoff.get(),
        flags: raw.e_flags.get(),
        ehsize: raw.e_ehsize.get(),
        phentsize: raw.e_phentsize.get(),
        phnum: raw.e_phnum.get(),
        shentsize: raw.e_shentsize.get(),
        shnum: raw.e_shnum.get(),
        shstrndx: raw.e_shstrndx.get(),
    })
}

