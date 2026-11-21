mod common;

use common::{build_elf32, build_elf64, patch16, ORDERS};
use elf::parser::b32::segments::program_headers;
use elf::parser::parse_elf;
use elf::types::header::ElfClass;
use elf::types::program::SegmentType;
use elf::ElfError;

#[test]
fn parses_32bit_header_and_segments() {
    for o in ORDERS {
        let buf = build_elf32(o);
        let file = parse_elf(&buf).unwrap();
        assert_eq!(file.class, ElfClass::Elf32);
        assert_eq!(file.ehdr.entry, 0x0804_8000);

        let phdrs = program_headers(&file)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(phdrs.len(), 1);
        assert_eq!(phdrs[0].segment_type(), SegmentType::Load);
        assert!(phdrs[0].flags().is_readable());
        assert!(phdrs[0].flags().is_executable());
        assert_eq!(phdrs[0].p_align, 0x1000);
    }
}

#[test]
fn rejects_wrong_class_and_phentsize() {
    for o in ORDERS {
        let buf64 = build_elf64(o);
        let elf64 = parse_elf(&buf64).unwrap();
        assert!(matches!(
            program_headers(&elf64).err(),
            Some(ElfError::ClassMismatch { .. })
        ));

        let mut bad = build_elf32(o);
        patch16(o, &mut bad, 42, 33); // e_phentsize at offset 42 in Ehdr32
        let file = parse_elf(&bad).unwrap();
        assert!(matches!(
            program_headers(&file).err(),
            Some(ElfError::InvalidEntrySize { .. })
        ));
    }
}
