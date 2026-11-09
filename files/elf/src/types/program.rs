use shared::byte_order::ByteOrder;
use shared::structs::IStaticStruct;

use crate::parser::shared::{u32_at, u64_at};
use crate::types::flags::SegmentFlags;

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
