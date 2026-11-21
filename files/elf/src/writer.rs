use shared::byte_order::ByteOrder;

use crate::types::flags::{PF_R, PF_X, SHF_ALLOC, SHF_EXECINSTR};
use crate::types::header::{
    Ehdr64, EHDR64_SIZE, ELFCLASS64, ELFDATA2LSB, ELFDATA2MSB, ELFMAG, ET_EXEC, EV_CURRENT,
};
use crate::types::machine::Machine;
use crate::types::program::{Phdr64, PHDR64_SIZE, PT_LOAD};
use crate::types::section::{Shdr64, SHDR64_SIZE, SHT_NULL, SHT_PROGBITS, SHT_STRTAB};
use crate::{ElfError, Result};

const SHSTRTAB: &[u8] = b"\0.text\0.shstrtab\0";
const NAME_TEXT: u32 = 1;
const NAME_SHSTRTAB: u32 = 7;
const TEXT_OFF: u64 = (EHDR64_SIZE + PHDR64_SIZE) as u64;

struct Out {
    order: ByteOrder,
    buf: Vec<u8>,
}

impl Out {
    fn u16(&mut self, n: u16) {
        self.buf.extend_from_slice(&match self.order {
            ByteOrder::BigEndian => n.to_be_bytes(),
            ByteOrder::LittleEndian => n.to_le_bytes(),
        });
    }

    fn u32(&mut self, n: u32) {
        self.buf.extend_from_slice(&match self.order {
            ByteOrder::BigEndian => n.to_be_bytes(),
            ByteOrder::LittleEndian => n.to_le_bytes(),
        });
    }

    fn u64(&mut self, n: u64) {
        self.buf.extend_from_slice(&match self.order {
            ByteOrder::BigEndian => n.to_be_bytes(),
            ByteOrder::LittleEndian => n.to_le_bytes(),
        });
    }

    fn ident(&mut self) {
        let data = match self.order {
            ByteOrder::LittleEndian => ELFDATA2LSB,
            ByteOrder::BigEndian => ELFDATA2MSB,
        };
        self.buf.extend_from_slice(&ELFMAG);
        self.buf.extend_from_slice(&[ELFCLASS64, data, EV_CURRENT]);
        self.buf.resize(16, 0);
    }

    fn ehdr(&mut self, h: &Ehdr64) {
        self.u16(h.e_type);
        self.u16(h.e_machine);
        self.u32(h.e_version);
        self.u64(h.e_entry);
        self.u64(h.e_phoff);
        self.u64(h.e_shoff);
        self.u32(h.e_flags);
        for n in [h.e_ehsize, h.e_phentsize, h.e_phnum, h.e_shentsize, h.e_shnum, h.e_shstrndx] {
            self.u16(n);
        }
    }

    fn phdr(&mut self, p: &Phdr64) {
        self.u32(p.p_type);
        self.u32(p.p_flags);
        for n in [p.p_offset, p.p_vaddr, p.p_paddr, p.p_filesz, p.p_memsz, p.p_align] {
            self.u64(n);
        }
    }

    fn shdr(&mut self, s: &Shdr64) {
        self.u32(s.sh_name);
        self.u32(s.sh_type);
        for n in [s.sh_flags, s.sh_addr, s.sh_offset, s.sh_size] {
            self.u64(n);
        }
        self.u32(s.sh_link);
        self.u32(s.sh_info);
        self.u64(s.sh_addralign);
        self.u64(s.sh_entsize);
    }
}

pub fn write_exec(
    order: ByteOrder,
    machine: Machine,
    entry: u64,
    load_vaddr: u64,
    text: &[u8],
) -> Result<Vec<u8>> {
    let overflow = |what: &'static str| ElfError::Overflow { what };

    let text_len = u64::try_from(text.len()).map_err(|_| overflow("text size"))?;
    let strtab_len = SHSTRTAB.len() as u64;
    let strtab_off = TEXT_OFF.checked_add(text_len).ok_or(overflow("shstrtab offset"))?;
    let end = strtab_off.checked_add(strtab_len).ok_or(overflow("section data end"))?;
    let shoff = end.checked_add(7).ok_or(overflow("section table offset"))? & !7;
    let text_addr = load_vaddr.checked_add(TEXT_OFF).ok_or(overflow("text address"))?;
    let shoff_pos = usize::try_from(shoff).map_err(|_| overflow("section table offset"))?;

    let ehdr = Ehdr64 {
        e_type: ET_EXEC,
        e_machine: u16::from(machine),
        e_version: u32::from(EV_CURRENT),
        e_entry: entry,
        e_phoff: EHDR64_SIZE as u64,
        e_shoff: shoff,
        e_flags: 0,
        e_ehsize: EHDR64_SIZE as u16,
        e_phentsize: PHDR64_SIZE as u16,
        e_phnum: 1,
        e_shentsize: SHDR64_SIZE as u16,
        e_shnum: 3,
        e_shstrndx: 2,
    };
    let phdr = Phdr64 {
        p_type: PT_LOAD,
        p_flags: PF_R | PF_X,
        p_offset: 0,
        p_vaddr: load_vaddr,
        p_paddr: load_vaddr,
        p_filesz: strtab_off,
        p_memsz: strtab_off,
        p_align: 0x1000,
    };
    let shdrs = [
        Shdr64 {
            sh_name: 0,
            sh_type: SHT_NULL,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: 0,
            sh_size: 0,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        },
        Shdr64 {
            sh_name: NAME_TEXT,
            sh_type: SHT_PROGBITS,
            sh_flags: SHF_ALLOC | SHF_EXECINSTR,
            sh_addr: text_addr,
            sh_offset: TEXT_OFF,
            sh_size: text_len,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 16,
            sh_entsize: 0,
        },
        Shdr64 {
            sh_name: NAME_SHSTRTAB,
            sh_type: SHT_STRTAB,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: strtab_off,
            sh_size: strtab_len,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        },
    ];

    let mut out = Out { order, buf: Vec::with_capacity(shoff_pos) };
    out.ident();
    out.ehdr(&ehdr);
    out.phdr(&phdr);
    out.buf.extend_from_slice(text);
    out.buf.extend_from_slice(SHSTRTAB);
    out.buf.resize(shoff_pos, 0);
    for s in &shdrs {
        out.shdr(s);
    }
    Ok(out.buf)
}
