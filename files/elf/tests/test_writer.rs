mod common;

use common::{find_section, ORDERS};
use elf::parser::b64::segments::program_headers;
use elf::parser::b64::sections::{section_headers, section_name, shstrtab};
use elf::parser::parse_elf;
use elf::types::flags::{PF_R, PF_X};
use elf::types::header::{ElfClass, ElfType};
use elf::types::machine::{Machine, EM_X86_64};
use elf::types::program::SegmentType;
use elf::types::section::SectionType;
use elf::writer::write_exec;
use elf::ElfError;

const TEXT: &[u8] = &[0x90, 0x90, 0xc3];
const LOAD: u64 = 0x40_0000;
const ENTRY: u64 = 0x40_0078;

fn build(o: shared::byte_order::ByteOrder) -> Vec<u8> {
    write_exec(o, Machine::from(EM_X86_64), ENTRY, LOAD, TEXT).unwrap()
}

#[test]
fn round_trip_header() {
    for o in ORDERS {
        let bytes = build(o);
        let file = parse_elf(&bytes).unwrap();

        assert_eq!(file.class, ElfClass::Elf64);
        assert_eq!(file.byte_order, o);
        assert_eq!(file.ehdr.file_type, ElfType::Exec);
        assert_eq!(file.ehdr.machine, Machine::from(EM_X86_64));
        assert_eq!(file.ehdr.entry, ENTRY);
        assert_eq!(file.ehdr.phoff, 64);
        assert_eq!(file.ehdr.phnum, 1);
        assert_eq!(file.ehdr.shnum, 3);
        assert_eq!(file.ehdr.shstrndx, 2);
        assert_eq!(file.ehdr.shoff % 8, 0);
    }
}

#[test]
fn round_trip_segment() {
    for o in ORDERS {
        let bytes = build(o);
        let file = parse_elf(&bytes).unwrap();
        let phdrs = program_headers(&file)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(phdrs.len(), 1);
        let p = &phdrs[0];
        assert_eq!(p.segment_type(), SegmentType::Load);
        assert_eq!(p.p_flags, PF_R | PF_X);
        assert_eq!((p.p_offset, p.p_vaddr, p.p_paddr), (0, LOAD, LOAD));
        assert_eq!(p.p_filesz, 120 + TEXT.len() as u64);
        assert_eq!(p.p_memsz, p.p_filesz);
        assert_eq!(p.p_align, 0x1000);
    }
}

#[test]
fn round_trip_sections() {
    for o in ORDERS {
        let bytes = build(o);
        let file = parse_elf(&bytes).unwrap();
        let hdrs = section_headers(&file)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let types: Vec<_> = hdrs.iter().map(|h| h.section_type()).collect();
        assert_eq!(types, [SectionType::Null, SectionType::ProgBits, SectionType::StrTab]);

        let names: Vec<&str> = hdrs
            .iter()
            .map(|h| section_name(&file, h).unwrap().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, ["", ".text", ".shstrtab"]);

        let text = find_section(&file, ".text").unwrap();
        assert_eq!(text.sh_addr, ENTRY);
        let start = usize::try_from(text.sh_offset).unwrap();
        assert_eq!(&bytes[start..start + TEXT.len()], TEXT);

        assert_eq!(shstrtab(&file).unwrap(), b"\0.text\0.shstrtab\0");
    }
}

#[test]
fn empty_text() {
    for o in ORDERS {
        let bytes = write_exec(o, Machine::from(EM_X86_64), ENTRY, LOAD, &[]).unwrap();
        let file = parse_elf(&bytes).unwrap();
        assert_eq!(find_section(&file, ".text").unwrap().sh_size, 0);
    }
}

#[test]
fn load_address_overflow() {
    for o in ORDERS {
        let err = write_exec(o, Machine::from(EM_X86_64), 0, u64::MAX, TEXT).unwrap_err();
        assert!(matches!(err, ElfError::Overflow { .. }));
    }
}
