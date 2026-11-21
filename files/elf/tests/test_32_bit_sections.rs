mod common;

use common::{build_elf32, ORDERS};
use elf::parser::b32::sections::{section_by_index, section_headers, section_name};
use elf::parser::parse_elf;
use elf::types::section::SectionType;
use elf::ElfError;

#[test]
fn parses_32bit_sections_and_names() {
    for o in ORDERS {
        let bytes = build_elf32(o);
        let file = parse_elf(&bytes).unwrap();
        let hdrs = section_headers(&file)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(hdrs.len(), 4);
        assert_eq!(hdrs[3].section_type(), SectionType::SymTab);

        let names: Vec<&str> = hdrs
            .iter()
            .map(|h| section_name(&file, h).unwrap().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, ["", ".shstrtab", ".strtab", ".symtab"]);

        assert_eq!(section_by_index(&file, 3).unwrap(), hdrs[3]);
        assert!(matches!(
            section_by_index(&file, 4),
            Err(ElfError::OutOfBounds { .. })
        ));
    }
}
