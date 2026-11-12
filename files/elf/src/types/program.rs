use shared::byte_order::ByteOrder;
use shared::structs::IStaticStruct;

use crate::parser::shared::{u32_at, u64_at};
use crate::types::flags::SegmentFlags;

// segment types
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;

// range
pub const PT_LOOS: u32 = 0x6000_0000;
pub const PT_HIOS: u32 = 0x6fff_ffff;
pub const PT_LOPROC: u32 = 0x7000_0000;
pub const PT_HIPROC: u32 = 0x7fff_ffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SegmentType {
    Null,
    Load,
    Dynamic,
    Interp,
    Note,
    Shlib,
    Phdr,
    Tls,
    OsSpecific(u32),
    ProcSpecific(u32),
    Unknown(u32),
}

impl From<u32> for SegmentType {
    fn from(value: u32) -> Self {
        match value {
            PT_NULL => Self::Null,
            PT_LOAD => Self::Load,
            PT_DYNAMIC => Self::Dynamic,
            PT_INTERP => Self::Interp,
            PT_NOTE => Self::Note,
            PT_SHLIB => Self::Shlib,
            PT_PHDR => Self::Phdr,
            PT_TLS => Self::Tls,
            PT_LOOS..=PT_HIOS => Self::OsSpecific(value),
            PT_LOPROC..=PT_HIPROC => Self::ProcSpecific(value),
            other => Self::Unknown(other),
        }
    }
}

impl From<SegmentType> for u32 {
    fn from(value: SegmentType) -> Self {
        match value {
            SegmentType::Null => PT_NULL,
            SegmentType::Load => PT_LOAD,
            SegmentType::Dynamic => PT_DYNAMIC,
            SegmentType::Interp => PT_INTERP,
            SegmentType::Note => PT_NOTE,
            SegmentType::Shlib => PT_SHLIB,
            SegmentType::Phdr => PT_PHDR,
            SegmentType::Tls => PT_TLS,
            SegmentType::OsSpecific(v)
            | SegmentType::ProcSpecific(v)
            | SegmentType::Unknown(v) => v,
        }
    }
}

pub const PHDR64_SIZE: usize = 56;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phdr64 {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl<'b> IStaticStruct<'b, PHDR64_SIZE> for Phdr64 {
    fn new(o: ByteOrder, buffer: &'b [u8; PHDR64_SIZE]) -> Self {
        Self {
            p_type: u32_at(o, buffer, 0),
            p_flags: u32_at(o, buffer, 4),
            p_offset: u64_at(o, buffer, 8),
            p_vaddr: u64_at(o, buffer, 16),
            p_paddr: u64_at(o, buffer, 24),
            p_filesz: u64_at(o, buffer, 32),
            p_memsz: u64_at(o, buffer, 40),
            p_align: u64_at(o, buffer, 48),
        }
    }
}

impl Phdr64 {
    pub fn segment_type(&self) -> SegmentType {
        SegmentType::from(self.p_type)
    }

    pub fn flags(&self) -> SegmentFlags {
        SegmentFlags(self.p_flags)
    }
}
