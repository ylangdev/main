mod common;

use common::{build_elf32, ORDERS};
use elf::parser::b32::sections::section_by_index;
use elf::parser::b32::symbols::{name_at, strtab_for, symbols};
use elf::parser::parse_elf;
use elf::types::symbol::{SymbolBinding, SymbolType};
use elf::ElfError;

#[test]
fn parses_32bit_symbols_and_rejects_wrong_section() {
    for o in ORDERS {
        let bytes = build_elf32(o);
        let file = parse_elf(&bytes).unwrap();
        let symtab = section_by_index(&file, 3).unwrap();
        let syms = symbols(&file, &symtab)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(syms.len(), 3);
        let strtab = strtab_for(&file, &symtab).unwrap();
        assert_eq!(name_at(strtab, syms[1].st_name).unwrap().to_str().unwrap(), "g");
        assert_eq!(name_at(strtab, syms[2].st_name).unwrap().to_str().unwrap(), "main");
        assert_eq!(syms[1].sym_type(), SymbolType::Object);
        assert_eq!(syms[1].binding(), SymbolBinding::Global);
        assert_eq!(syms[2].sym_type(), SymbolType::Func);

        let non_symtab = section_by_index(&file, 2).unwrap();
        assert!(matches!(
            symbols(&file, &non_symtab).err(),
            Some(ElfError::InvalidSectionType { .. })
        ));
    }
}
