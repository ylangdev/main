use shared::byte_order::ByteOrder;
use shared::structs::IStaticStruct;

use crate::parser::shared::{u32_at, u64_at};
use crate::types::flags::SectionFlags;

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
