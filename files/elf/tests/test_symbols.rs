mod common;

use common::{
    build_elf32_header, build_elf64, find_section, find_symbol, patch64, OFF_SYMTAB_ENTSIZE,
    ORDERS,
};
use elf::parser::b64::sections::section_by_index;
use elf::parser::b64::symbols::{name_at, strtab_for, symbols};
use elf::parser::parse_elf;
use elf::types::symbol::{SymbolBinding, SymbolType, SymbolVisibility};
use elf::ElfError;

#[test]
fn records_and_names() {
    for o in ORDERS {
        let bytes = build_elf64(o);
        let file = parse_elf(&bytes).unwrap();
        let symtab = find_section(&file, ".symtab").unwrap();
        let syms = symbols(&file, &symtab)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let strtab = strtab_for(&file, &symtab).unwrap();
        let name = |i: usize| name_at(strtab, syms[i].st_name).unwrap().to_str().unwrap();

        assert_eq!(syms.len(), 3);
        assert_eq!(name(0), "");
        assert_eq!(name(1), "main");
        assert_eq!(name(2), "counter");

        assert_eq!(syms[0].sym_type(), SymbolType::NoType);
        assert_eq!(syms[0].binding(), SymbolBinding::Local);

        assert_eq!(syms[1].sym_type(), SymbolType::Func);
        assert_eq!(syms[1].binding(), SymbolBinding::Global);
        assert_eq!(syms[1].visibility(), SymbolVisibility::Default);
        assert_eq!((syms[1].st_shndx, syms[1].st_value, syms[1].st_size), (3, 0x1000, 0x20));

        assert_eq!(syms[2].sym_type(), SymbolType::Object);
        assert_eq!(syms[2].binding(), SymbolBinding::Local);
        assert_eq!(syms[2].visibility(), SymbolVisibility::Hidden);
        assert_eq!((syms[2].st_shndx, syms[2].st_value, syms[2].st_size), (2, 0x2000, 8));
    }
}

#[test]
fn lookup_by_name() {
    for o in ORDERS {
        let bytes = build_elf64(o);
        let file = parse_elf(&bytes).unwrap();
        assert_eq!(find_symbol(&file, "main").unwrap().st_value, 0x1000);
        assert_eq!(find_symbol(&file, "counter").unwrap().st_value, 0x2000);
        assert!(find_symbol(&file, "missing").is_none());
    }
}

#[test]
fn rejects_non_symtab_section() {
    for o in ORDERS {
        let bytes = build_elf64(o);
        let file = parse_elf(&bytes).unwrap();
        let strtab = find_section(&file, ".strtab").unwrap();
        assert!(matches!(
            symbols(&file, &strtab).err(),
            Some(ElfError::InvalidSectionType { .. })
        ));
    }
}

#[test]
fn invalid_sym_entsize() {
    for o in ORDERS {
        let mut bytes = build_elf64(o);
        patch64(o, &mut bytes, OFF_SYMTAB_ENTSIZE, 16);
        let file = parse_elf(&bytes).unwrap();
        let symtab = section_by_index(&file, 3).unwrap();
        assert!(matches!(
            symbols(&file, &symtab).err(),
            Some(ElfError::InvalidEntrySize { .. })
        ));
    }
}

#[test]
fn strtab_link_out_of_range() {
    for o in ORDERS {
        let bytes = build_elf64(o);
        let file = parse_elf(&bytes).unwrap();
        let mut symtab = find_section(&file, ".symtab").unwrap();
        symtab.sh_link = 99;
        assert!(matches!(
            strtab_for(&file, &symtab),
            Err(ElfError::OutOfBounds { .. })
        ));
    }
}

#[test]
fn class_mismatch_on_elf32() {
    for o in ORDERS {
        let bytes64 = build_elf64(o);
        let file64 = parse_elf(&bytes64).unwrap();
        let symtab = find_section(&file64, ".symtab").unwrap();

        let bytes32 = build_elf32_header(o);
        let file32 = parse_elf(&bytes32).unwrap();
        assert!(matches!(
            symbols(&file32, &symtab).err(),
            Some(ElfError::ClassMismatch { .. })
        ));
    }
}
