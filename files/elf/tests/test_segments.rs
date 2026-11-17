mod common;

use common::{build_elf32_header, build_elf64, patch16, OFF_E_PHENTSIZE, ORDERS};
use elf::parser::b64::sections::section_headers;
use elf::parser::b64::segments::program_headers;
use elf::parser::parse_elf;
use elf::types::header::ElfClass;
use elf::types::program::SegmentType;
use elf::ElfError;

#[test]
fn read_program_headers() {
    for order in ORDERS {
        let raw = build_elf64(order);
        let file = parse_elf(&raw).expect("valid elf64");

        let mut iter = program_headers(&file).expect("program headers");
        let seg = iter.next().expect("missing PT_LOAD").expect("bad phdr");
        assert!(iter.next().is_none());

        let flags = seg.flags();
        assert_eq!(seg.segment_type(), SegmentType::Load);
        assert!(flags.is_readable() && flags.is_executable());
        assert!(!flags.is_writable());
        assert_eq!(seg.p_vaddr, 0x40_0000);
        assert_eq!(seg.p_filesz, 0x100);
        assert_eq!(seg.p_align, 0x1000);
    }
}

#[test]
fn elf32_class_mismatch() {
    for order in ORDERS {
        let raw = build_elf32_header(order);
        let file = parse_elf(&raw).expect("valid elf32 header");
        assert_eq!(file.class, ElfClass::Elf32);

        let phdr_err = program_headers(&file).err().unwrap();
        assert_eq!(
            phdr_err,
            ElfError::ClassMismatch {
                expected: ElfClass::Elf64,
                found: ElfClass::Elf32,
            }
        );

        let shdr_err = section_headers(&file).err().unwrap();
        assert_eq!(
            shdr_err,
            ElfError::ClassMismatch {
                expected: ElfClass::Elf64,
                found: ElfClass::Elf32,
            }
        );
    }
}

#[test]
fn invalid_phentsize() {
    for order in ORDERS {
        let mut raw = build_elf64(order);
        patch16(order, &mut raw, OFF_E_PHENTSIZE, 57);

        let file = parse_elf(&raw).expect("header still parses");
        let err = program_headers(&file).err().unwrap();
        assert_eq!(
            err,
            ElfError::InvalidEntrySize {
                table: "program header",
                expected: 56,
                found: 57,
            }
        );
    }
}
