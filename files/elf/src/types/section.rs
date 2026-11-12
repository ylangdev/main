use shared::byte_order::ByteOrder;
use shared::structs::IStaticStruct;

use crate::parser::shared::{u32_at, u64_at};
use crate::types::flags::SectionFlags;

// section types (sh_type)
pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_DYNSYM: u32 = 11;

// ranges reserved for the OS and processor
pub const SHT_LOOS: u32 = 0x6000_0000;
pub const SHT_HIOS: u32 = 0x6fff_ffff;
pub const SHT_LOPROC: u32 = 0x7000_0000;
pub const SHT_HIPROC: u32 = 0x7fff_ffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionType {
    Null,
    ProgBits,
    SymTab,
    StrTab,
    Rela,
    Hash,
    Dynamic,
    Note,
    NoBits,
    Rel,
    DynSym,
    OsSpecific(u32),
    ProcSpecific(u32),
    // anything outside the groups above, raw value is kept
    Unknown(u32),
}

// u32 -> SectionType
impl From<u32> for SectionType {
    fn from(value: u32) -> Self {
        match value {
            SHT_NULL => Self::Null,
            SHT_PROGBITS => Self::ProgBits,
            SHT_SYMTAB => Self::SymTab,
            SHT_STRTAB => Self::StrTab,
            SHT_RELA => Self::Rela,
            SHT_HASH => Self::Hash,
            SHT_DYNAMIC => Self::Dynamic,
            SHT_NOTE => Self::Note,
            SHT_NOBITS => Self::NoBits,
            SHT_REL => Self::Rel,
            SHT_DYNSYM => Self::DynSym,
            SHT_LOOS..=SHT_HIOS => Self::OsSpecific(value),
            SHT_LOPROC..=SHT_HIPROC => Self::ProcSpecific(value),
            other => Self::Unknown(other),
        }
    }
}

// SectionType -> u32, used when writing header
impl From<SectionType> for u32 {
    fn from(value: SectionType) -> Self {
        match value {
            SectionType::Null => SHT_NULL,
            SectionType::ProgBits => SHT_PROGBITS,
            SectionType::SymTab => SHT_SYMTAB,
            SectionType::StrTab => SHT_STRTAB,
            SectionType::Rela => SHT_RELA,
            SectionType::Hash => SHT_HASH,
            SectionType::Dynamic => SHT_DYNAMIC,
            SectionType::Note => SHT_NOTE,
            SectionType::NoBits => SHT_NOBITS,
            SectionType::Rel => SHT_REL,
            SectionType::DynSym => SHT_DYNSYM,
            SectionType::OsSpecific(v)
            | SectionType::ProcSpecific(v)
            | SectionType::Unknown(v) => v,
        }
    }
}

pub const SHDR64_SIZE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shdr64 {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

impl<'b> IStaticStruct<'b, SHDR64_SIZE> for Shdr64 {
    fn new(o: ByteOrder, buffer: &'b [u8; SHDR64_SIZE]) -> Self {
        Self {
            sh_name: u32_at(o, buffer, 0),
            sh_type: u32_at(o, buffer, 4),
            sh_flags: u64_at(o, buffer, 8),
            sh_addr: u64_at(o, buffer, 16),
            sh_offset: u64_at(o, buffer, 24),
            sh_size: u64_at(o, buffer, 32),
            sh_link: u32_at(o, buffer, 40),
            sh_info: u32_at(o, buffer, 44),
            sh_addralign: u64_at(o, buffer, 48),
            sh_entsize: u64_at(o, buffer, 56),
        }
    }
}

impl Shdr64 {
    pub fn section_type(&self) -> SectionType {
        SectionType::from(self.sh_type)
    }

    pub fn flags(&self) -> SectionFlags {
        SectionFlags(self.sh_flags)
    }
}
