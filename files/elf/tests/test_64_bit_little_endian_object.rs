mod common;

use common::{find_section, find_symbol, sample};
use elf::parser::b64::segments::program_headers;
use elf::parser::parse_elf;
use elf::types::header::{ElfClass, ElfData, ElfType};
use elf::types::symbol::SymbolType;

#[test]
fn header() {
    let bytes = sample("64_little_endian_object.o");
    let file = parse_elf(&bytes).unwrap();

    assert_eq!(file.class, ElfClass::Elf64);
    assert_eq!(file.data, ElfData::Little);
    assert_eq!(file.ehdr.file_type, ElfType::Rel);
    assert_eq!(file.ehdr.phnum, 0);
    assert_eq!(program_headers(&file).unwrap().count(), 0);
}

#[test]
fn sections() {
    let bytes = sample("64_little_endian_object.o");
    let file = parse_elf(&bytes).unwrap();

    for name in [".text", ".rodata", ".data", ".bss", ".symtab", ".strtab", ".rela.text"] {
        assert!(find_section(&file, name).is_some(), "missing {name}");
    }
}

#[test]
fn symbols() {
    let bytes = sample("64_little_endian_object.o");
    let file = parse_elf(&bytes).unwrap();

    let expected = [
        ("main", SymbolType::Func),
        ("add_numbers", SymbolType::Func),
        ("magic_const", SymbolType::Object),
        ("initialized_var", SymbolType::Object),
        ("uninitialized_var", SymbolType::Object),
    ];
    for (name, ty) in expected {
        let sym = find_symbol(&file, name).unwrap_or_else(|| panic!("missing {name}"));
        assert_eq!(sym.sym_type(), ty, "{name}");
    }
}
