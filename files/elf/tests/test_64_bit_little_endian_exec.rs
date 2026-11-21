mod common;

use common::{find_section, find_symbol, sample};
use elf::parser::b64::segments::program_headers;
use elf::parser::parse_elf;
use elf::types::header::{ElfClass, ElfData, ElfType};
use elf::types::program::{PT_INTERP, PT_LOAD};
use elf::types::symbol::SymbolType;

#[test]
fn header() {
    let bytes = sample("64_little_endian_exec");
    let file = parse_elf(&bytes).unwrap();

    assert_eq!(file.class, ElfClass::Elf64);
    assert_eq!(file.data, ElfData::Little);
    assert!(matches!(file.ehdr.file_type, ElfType::Dyn | ElfType::Exec));
}

#[test]
fn segments() {
    let bytes = sample("64_little_endian_exec");
    let file = parse_elf(&bytes).unwrap();

    let types: Vec<u32> = program_headers(&file)
        .unwrap()
        .flatten()
        .map(|p| p.p_type)
        .collect();
    assert_eq!(types.len(), usize::from(file.ehdr.phnum));
    assert!(types.contains(&PT_LOAD));
    assert!(types.contains(&PT_INTERP));
}

#[test]
fn sections_and_symbols() {
    let bytes = sample("64_little_endian_exec");
    let file = parse_elf(&bytes).unwrap();

    for name in [".text", ".rodata", ".data", ".bss", ".symtab"] {
        assert!(find_section(&file, name).is_some(), "missing {name}");
    }
    for name in ["main", "add_numbers"] {
        let sym = find_symbol(&file, name).unwrap_or_else(|| panic!("missing {name}"));
        assert_eq!(sym.sym_type(), SymbolType::Func, "{name}");
    }
}
