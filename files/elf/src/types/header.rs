use core::mem::size_of;
use ::shared::byte_order::ByteOrder;
use ::shared::structs::{parse_static_struct, IStaticStruct};
use crate::parser::shared::{slice_at, u16_at, u32_at, u64_at};
use crate::{ElfError, Result};

pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const EI_NIDENT: usize = 16;
pub const EV_CURRENT: u8 = 1;

pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;

pub const ELFDATA2LSB: u8 = 1; // little-endian
pub const ELFDATA2MSB: u8 = 2; // big-endian

pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;
pub const ET_LOOS: u16 = 0xfe00;
pub const ET_HIOS: u16 = 0xfeff;
pub const ET_LOPROC: u16 = 0xff00;
pub const ET_HIPROC: u16 = 0xffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

impl TryFrom<u8> for ElfClass {
    type Error = ElfError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            ELFCLASS32 => Ok(Self::Elf32),
            ELFCLASS64 => Ok(Self::Elf64),
            other => Err(ElfError::UnsupportedClass(other)),
        }
    }
}

impl From<ElfClass> for u8 {
    fn from(value: ElfClass) -> Self {
        match value {
            ElfClass::Elf32 => ELFCLASS32,
            ElfClass::Elf64 => ELFCLASS64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfData {
    Little,
    Big,
}

impl TryFrom<u8> for ElfData {
    type Error = ElfError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            ELFDATA2LSB => Ok(Self::Little),
            ELFDATA2MSB => Ok(Self::Big),
            other => Err(ElfError::UnsupportedData(other)),
        }
    }
}

impl From<ElfData> for u8 {
    fn from(value: ElfData) -> Self {
        match value {
            ElfData::Little => ELFDATA2LSB,
            ElfData::Big => ELFDATA2MSB,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfType {
    None,
    Rel,
    Exec,
    Dyn,
    Core,
    OsSpecific(u16),
    ProcSpecific(u16),
    Unknown(u16),
}

impl From<u16> for ElfType {
    fn from(value: u16) -> Self {
        match value {
            ET_NONE => Self::None,
            ET_REL => Self::Rel,
            ET_EXEC => Self::Exec,
            ET_DYN => Self::Dyn,
            ET_CORE => Self::Core,
            ET_LOOS..=ET_HIOS => Self::OsSpecific(value),
            ET_LOPROC..=ET_HIPROC => Self::ProcSpecific(value),
            other => Self::Unknown(other),
        }
    }
}

impl From<ElfType> for u16 {
    fn from(value: ElfType) -> Self {
        match value {
            ElfType::None => ET_NONE,
            ElfType::Rel => ET_REL,
            ElfType::Exec => ET_EXEC,
            ElfType::Dyn => ET_DYN,
            ElfType::Core => ET_CORE,
            ElfType::OsSpecific(v) | ElfType::ProcSpecific(v) | ElfType::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ident {
    pub magic: [u8; 4],
    pub class: u8,
    pub data: u8,
    pub version: u8,
    pub os_abi: u8,
    pub abi_version: u8,
    pub pad: [u8; 7],
}

impl<'b> IStaticStruct<'b, EI_NIDENT> for Ident {
    fn new(_o: ByteOrder, buffer: &'b [u8; EI_NIDENT]) -> Self {
        Self {
            magic: [buffer[0], buffer[1], buffer[2], buffer[3]],
            class: buffer[4],
            data: buffer[5],
            version: buffer[6],
            os_abi: buffer[7],
            abi_version: buffer[8],
            pad: [
                buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14], buffer[15],
            ],
        }
    }
}

impl Ident {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let raw_slice = slice_at(bytes, "ELF ident", 0, EI_NIDENT as u64).map_err(|_| {
            ElfError::UnexpectedEof {
                offset: 0,
                needed: EI_NIDENT,
                available: bytes.len(),
            }
        })?;

        let ident = parse_static_struct::<EI_NIDENT, Self>(ByteOrder::LittleEndian, raw_slice)
            .ok_or(ElfError::UnexpectedEof {
                offset: 0,
                needed: EI_NIDENT,
                available: bytes.len(),
            })?;

        ident.check_magic()?;
        Ok(ident)
    }

    pub fn check_magic(&self) -> Result<()> {
        if self.magic == ELFMAG {
            Ok(())
        } else {
            Err(ElfError::BadMagic { found: self.magic })
        }
    }

    pub fn class(&self) -> Result<ElfClass> {
        ElfClass::try_from(self.class)
    }

    pub fn data(&self) -> Result<ElfData> {
        ElfData::try_from(self.data)
    }
}

const _: [(); EI_NIDENT] = [(); size_of::<Ident>()];

pub const EHDR32_SIZE: usize = 52;
pub const EHDR64_SIZE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ehdr32 {
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u32,
    pub e_phoff: u32,
    pub e_shoff: u32,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl<'b> IStaticStruct<'b, 36> for Ehdr32 {
    fn new(o: ByteOrder, buffer: &'b [u8; 36]) -> Self {
        Self {
            e_type: u16_at(o, buffer, 0),
            e_machine: u16_at(o, buffer, 2),
            e_version: u32_at(o, buffer, 4),
            e_entry: u32_at(o, buffer, 8),
            e_phoff: u32_at(o, buffer, 12),
            e_shoff: u32_at(o, buffer, 16),
            e_flags: u32_at(o, buffer, 20),
            e_ehsize: u16_at(o, buffer, 24),
            e_phentsize: u16_at(o, buffer, 26),
            e_phnum: u16_at(o, buffer, 28),
            e_shentsize: u16_at(o, buffer, 30),
            e_shnum: u16_at(o, buffer, 32),
            e_shstrndx: u16_at(o, buffer, 34),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ehdr64 {
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl<'b> IStaticStruct<'b, 48> for Ehdr64 {
    fn new(o: ByteOrder, buffer: &'b [u8; 48]) -> Self {
        Self {
            e_type: u16_at(o, buffer, 0),
            e_machine: u16_at(o, buffer, 2),
            e_version: u32_at(o, buffer, 4),
            e_entry: u64_at(o, buffer, 8),
            e_phoff: u64_at(o, buffer, 16),
            e_shoff: u64_at(o, buffer, 24),
            e_flags: u32_at(o, buffer, 32),
            e_ehsize: u16_at(o, buffer, 36),
            e_phentsize: u16_at(o, buffer, 38),
            e_phnum: u16_at(o, buffer, 40),
            e_shentsize: u16_at(o, buffer, 42),
            e_shnum: u16_at(o, buffer, 44),
            e_shstrndx: u16_at(o, buffer, 46),
        }
    }
}
