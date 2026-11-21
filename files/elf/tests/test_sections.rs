mod common;

use common::{
    build_elf32_header, build_elf64, find_section, patch16, patch64, sample, OFF_E_SHENTSIZE,
    OFF_E_SHOFF, ORDERS, SHSTRTAB, SHSTRTAB_OFF, STRTAB, STRTAB_OFF, SYMTAB_OFF, SYMTAB_SIZE,
};
use elf::parser::b64::sections::{section_by_index, section_headers, section_name, shstrtab};
use elf::parser::parse_elf;
use elf::types::section::SectionType;
use elf::ElfError;

const OFF_E_SHNUM: usize = 60;

#[test]
fn headers_and_names() {
    for o in ORDERS {
        let bytes = build_elf64(o);
        let file = parse_elf(&bytes).unwrap();
        let hdrs = section_headers(&file)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(hdrs.len(), 4);
        let types: Vec<_> = hdrs.iter().map(|h| h.section_type()).collect();
        assert_eq!(
            types,
            [SectionType::Null, SectionType::StrTab, SectionType::StrTab, SectionType::SymTab]
        );

        assert_eq!(hdrs[1].sh_offset, SHSTRTAB_OFF as u64);
        assert_eq!(hdrs[1].sh_size, SHSTRTAB.len() as u64);
        assert_eq!(hdrs[2].sh_offset, STRTAB_OFF as u64);
        assert_eq!(hdrs[2].sh_size, STRTAB.len() as u64);
        assert_eq!(hdrs[3].sh_offset, SYMTAB_OFF as u64);
        assert_eq!(hdrs[3].sh_size, SYMTAB_SIZE as u64);
        assert_eq!((hdrs[3].sh_link, hdrs[3].sh_info, hdrs[3].sh_entsize), (2, 1, 24));

        let names: Vec<&str> = hdrs
            .iter()
            .map(|h| section_name(&file, h).unwrap().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, ["", ".shstrtab", ".strtab", ".symtab"]);
    }
}

#[test]
fn section_data() {
    for o in ORDERS {
        let bytes = build_elf64(o);
        let file = parse_elf(&bytes).unwrap();
        assert_eq!(shstrtab(&file).unwrap(), SHSTRTAB);

        let strtab = find_section(&file, ".strtab").unwrap();
        let start = usize::try_from(strtab.sh_offset).unwrap();
        assert_eq!(&bytes[start..start + STRTAB.len()], STRTAB);
    }
}

#[test]
fn section_by_index_bounds() {
    for o in ORDERS {
        let bytes = build_elf64(o);
        let file = parse_elf(&bytes).unwrap();
        let hdrs = section_headers(&file)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(section_by_index(&file, 3).unwrap(), hdrs[3]);
        for index in [4, u32::MAX] {
            assert!(matches!(
                section_by_index(&file, index),
                Err(ElfError::OutOfBounds { .. })
            ));
        }
    }
}

#[test]
fn zero_sections_give_empty_iterator() {
    for o in ORDERS {
        let mut bytes = build_elf64(o);
        patch16(o, &mut bytes, OFF_E_SHNUM, 0);
        let file = parse_elf(&bytes).unwrap();
        assert_eq!(section_headers(&file).unwrap().count(), 0);
    }
}

#[test]
fn nobits_section_in_real_binary() {
    let bytes = sample("64_little_endian_exec");
    let file = parse_elf(&bytes).unwrap();
    let bss = find_section(&file, ".bss").unwrap();
    assert_eq!(bss.section_type(), SectionType::NoBits);
}

#[test]
fn class_mismatch_on_elf32() {
    for o in ORDERS {
        let bytes = build_elf32_header(o);
        let file = parse_elf(&bytes).unwrap();
        assert!(matches!(
            section_headers(&file).err(),
            Some(ElfError::ClassMismatch { .. })
        ));
        assert!(matches!(
            section_by_index(&file, 0),
            Err(ElfError::ClassMismatch { .. })
        ));
    }
}

#[test]
fn invalid_shentsize() {
    for o in ORDERS {
        let mut bytes = build_elf64(o);
        patch16(o, &mut bytes, OFF_E_SHENTSIZE, 63);
        let file = parse_elf(&bytes).unwrap();
        assert!(matches!(
            section_headers(&file).err(),
            Some(ElfError::InvalidEntrySize { .. })
        ));
    }
}

#[test]
fn shoff_out_of_bounds() {
    for o in ORDERS {
        let mut bytes = build_elf64(o);
        let len = bytes.len() as u64;
        patch64(o, &mut bytes, OFF_E_SHOFF, len);
        let file = parse_elf(&bytes).unwrap();
        assert!(matches!(
            section_headers(&file).err(),
            Some(ElfError::OutOfBounds { .. })
        ));
    }
}
