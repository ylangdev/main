#![allow(dead_code)]

use std::path::Path;

use elf::parser::b64::sections::{section_headers, section_name};
use elf::parser::b64::symbols::{name_at, strtab_for, symbols};
use elf::parser::ElfFile;
use elf::types::flags::{PF_R, PF_X};
use elf::types::header::{ELFDATA2LSB, ELFDATA2MSB, ELFMAG, ET_EXEC};
use elf::types::machine::{EM_386, EM_X86_64};
use elf::types::program::PT_LOAD;
use elf::types::section::{Shdr64, SHT_NULL, SHT_STRTAB, SHT_SYMTAB};
use elf::types::symbol::{Sym64, STB_GLOBAL, STB_LOCAL, STT_FUNC, STT_OBJECT, STV_HIDDEN};
use shared::byte_order::ByteOrder;

pub const ORDERS: [ByteOrder; 2] = [ByteOrder::LittleEndian, ByteOrder::BigEndian];

pub const SHSTRTAB: &[u8] = b"\0.shstrtab\0.strtab\0.symtab\0";
pub const STRTAB: &[u8] = b"\0main\0counter\0";

pub const PHOFF: usize = 64;
pub const SHSTRTAB_OFF: usize = 120;
pub const STRTAB_OFF: usize = 147;
pub const SYMTAB_OFF: usize = 168;
pub const SYMTAB_SIZE: usize = 72;
pub const SHOFF: usize = 240;

pub const OFF_E_SHOFF: usize = 40;
pub const OFF_E_PHENTSIZE: usize = 54;
pub const OFF_E_SHENTSIZE: usize = 58;
pub const OFF_SYMTAB_ENTSIZE: usize = SHOFF + 3 * 64 + 56;

fn push_u16(order: ByteOrder, buf: &mut Vec<u8>, val: u16) {
    let bytes = match order {
        ByteOrder::BigEndian => val.to_be_bytes(),
        ByteOrder::LittleEndian => val.to_le_bytes(),
    };
    buf.extend_from_slice(&bytes);
}

fn push_u32(order: ByteOrder, buf: &mut Vec<u8>, val: u32) {
    let bytes = match order {
        ByteOrder::BigEndian => val.to_be_bytes(),
        ByteOrder::LittleEndian => val.to_le_bytes(),
    };
    buf.extend_from_slice(&bytes);
}

fn push_u64(order: ByteOrder, buf: &mut Vec<u8>, val: u64) {
    let bytes = match order {
        ByteOrder::BigEndian => val.to_be_bytes(),
        ByteOrder::LittleEndian => val.to_le_bytes(),
    };
    buf.extend_from_slice(&bytes);
}

fn make_ident(order: ByteOrder, class: u8) -> Vec<u8> {
    let endian = match order {
        ByteOrder::LittleEndian => ELFDATA2LSB,
        ByteOrder::BigEndian => ELFDATA2MSB,
    };
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(&ELFMAG);
    buf.extend_from_slice(&[class, endian, 1]);
    buf.resize(16, 0);
    buf
}

struct SectionSpec {
    name: u32,
    sh_type: u32,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
}

fn write_shdr(order: ByteOrder, buf: &mut Vec<u8>, s: &SectionSpec) {
    push_u32(order, buf, s.name);
    push_u32(order, buf, s.sh_type);
    push_u64(order, buf, 0);
    push_u64(order, buf, 0);
    push_u64(order, buf, s.offset);
    push_u64(order, buf, s.size);
    push_u32(order, buf, s.link);
    push_u32(order, buf, s.info);
    push_u64(order, buf, s.align);
    push_u64(order, buf, s.entsize);
}

struct SymbolSpec {
    name: u32,
    info: u8,
    other: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

fn write_sym(order: ByteOrder, buf: &mut Vec<u8>, s: &SymbolSpec) {
    push_u32(order, buf, s.name);
    buf.push(s.info);
    buf.push(s.other);
    push_u16(order, buf, s.shndx);
    push_u64(order, buf, s.value);
    push_u64(order, buf, s.size);
}

pub fn build_elf64(o: ByteOrder) -> Vec<u8> {
    let mut buf = make_ident(o, 2);

    push_u16(o, &mut buf, ET_EXEC);
    push_u16(o, &mut buf, EM_X86_64);
    push_u32(o, &mut buf, 1);
    push_u64(o, &mut buf, 0x40_1000);
    push_u64(o, &mut buf, PHOFF as u64);
    push_u64(o, &mut buf, SHOFF as u64);
    push_u32(o, &mut buf, 0);
    push_u16(o, &mut buf, 64);
    push_u16(o, &mut buf, 56);
    push_u16(o, &mut buf, 1);
    push_u16(o, &mut buf, 64);
    push_u16(o, &mut buf, 4);
    push_u16(o, &mut buf, 1);

    // PT_LOAD
    push_u32(o, &mut buf, PT_LOAD);
    push_u32(o, &mut buf, PF_R | PF_X);
    push_u64(o, &mut buf, 0);
    push_u64(o, &mut buf, 0x40_0000);
    push_u64(o, &mut buf, 0x40_0000);
    push_u64(o, &mut buf, 0x100);
    push_u64(o, &mut buf, 0x100);
    push_u64(o, &mut buf, 0x1000);

    buf.extend_from_slice(SHSTRTAB);
    buf.extend_from_slice(STRTAB);
    let rem = buf.len() % 8;
    if rem != 0 {
        buf.resize(buf.len() + (8 - rem), 0);
    }

    let syms = [
        SymbolSpec { name: 0, info: 0, other: 0, shndx: 0, value: 0, size: 0 },
        SymbolSpec {
            name: 1,
            info: (STB_GLOBAL << 4) | STT_FUNC,
            other: 0,
            shndx: 3,
            value: 0x1000,
            size: 0x20,
        },
        SymbolSpec {
            name: 6,
            info: (STB_LOCAL << 4) | STT_OBJECT,
            other: STV_HIDDEN,
            shndx: 2,
            value: 0x2000,
            size: 8,
        },
    ];
    for sym in &syms {
        write_sym(o, &mut buf, sym);
    }

    let sections = [
        SectionSpec { name: 0, sh_type: SHT_NULL, offset: 0, size: 0, link: 0, info: 0, align: 0, entsize: 0 },
        SectionSpec {
            name: 1,
            sh_type: SHT_STRTAB,
            offset: SHSTRTAB_OFF as u64,
            size: SHSTRTAB.len() as u64,
            link: 0,
            info: 0,
            align: 1,
            entsize: 0,
        },
        SectionSpec {
            name: 11,
            sh_type: SHT_STRTAB,
            offset: STRTAB_OFF as u64,
            size: STRTAB.len() as u64,
            link: 0,
            info: 0,
            align: 1,
            entsize: 0,
        },
        SectionSpec {
            name: 19,
            sh_type: SHT_SYMTAB,
            offset: SYMTAB_OFF as u64,
            size: SYMTAB_SIZE as u64,
            link: 2,
            info: 1,
            align: 8,
            entsize: 24,
        },
    ];
    for sec in &sections {
        write_shdr(o, &mut buf, sec);
    }

    buf
}

pub fn build_elf32_header(o: ByteOrder) -> Vec<u8> {
    let mut buf = make_ident(o, 1);
    push_u16(o, &mut buf, ET_EXEC);
    push_u16(o, &mut buf, EM_386);
    push_u32(o, &mut buf, 1);
    push_u32(o, &mut buf, 0x804_8000);
    push_u32(o, &mut buf, 0);
    push_u32(o, &mut buf, 0);
    push_u32(o, &mut buf, 0);
    push_u16(o, &mut buf, 52);
    push_u16(o, &mut buf, 32);
    push_u16(o, &mut buf, 0);
    push_u16(o, &mut buf, 40);
    push_u16(o, &mut buf, 0);
    push_u16(o, &mut buf, 0);
    buf
}

pub fn patch16(o: ByteOrder, bytes: &mut [u8], off: usize, n: u16) {
    let raw = match o {
        ByteOrder::BigEndian => n.to_be_bytes(),
        ByteOrder::LittleEndian => n.to_le_bytes(),
    };
    bytes[off..off + 2].copy_from_slice(&raw);
}

pub fn patch64(o: ByteOrder, bytes: &mut [u8], off: usize, n: u64) {
    let raw = match o {
        ByteOrder::BigEndian => n.to_be_bytes(),
        ByteOrder::LittleEndian => n.to_le_bytes(),
    };
    bytes[off..off + 8].copy_from_slice(&raw);
}

pub fn sample(name: &str) -> Vec<u8> {
    let mut path = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    path.push("tests");
    path.push("samples");
    path.push(name);
    std::fs::read(&path).expect("failed to read sample binary")
}

pub fn find_section(file: &ElfFile<'_>, wanted: &str) -> Option<Shdr64> {
    let iter = section_headers(file).ok()?;
    for hdr in iter.flatten() {
        if let Ok(Some(name)) = section_name(file, &hdr) {
            if name.to_bytes() == wanted.as_bytes() {
                return Some(hdr);
            }
        }
    }
    None
}

pub fn find_symbol(file: &ElfFile<'_>, wanted: &str) -> Option<Sym64> {
    let symtab = find_section(file, ".symtab")?;
    let strtab = strtab_for(file, &symtab).ok()?;
    let iter = symbols(file, &symtab).ok()?;
    for sym in iter.flatten() {
        if let Some(name) = name_at(strtab, sym.st_name) {
            if name.to_bytes() == wanted.as_bytes() {
                return Some(sym);
            }
        }
    }
    None
}
