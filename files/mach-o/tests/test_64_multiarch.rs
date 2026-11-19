use macho::parser::{self, ByteOrder, variants::multiarch::b64::EntryHeader};

#[test]
pub fn test_64_multiarch_file() {
    let path = std::path::PathBuf::from(file!())
        .parent()
        .unwrap()
        .join("samples/64_multiarch");
    let buffer: Vec<u8> = std::fs::read(path).unwrap();
    let general_file = parser::MachOFile::parse(&buffer).unwrap();
    assert_eq!(general_file.get_byte_order(), ByteOrder::BigEndian);
    let parser::MachOFile::MultiArch(parser::variants::multiarch::File::B64(
        file,
    )) = general_file
    else {
        panic!("Expected 64-bit multiarch file");
    };
    assert_eq!(file.header.binaries_count, 2);

    let entries: Vec<EntryHeader> =
        file.get_entry_headers().map(|e| e.unwrap()).collect();
    assert_eq!(
        entries,
        vec![
            EntryHeader {
                cpu_type: 0x0100_0007, // CPU_TYPE_X86_64
                cpu_subtype: 3,        // CPU_SUBTYPE_X86_64_ALL
                file_offset: 0x1000,
                size: 0x10b0,
                section_alignment: 12,
                _reserved: 0,
            },
            EntryHeader {
                cpu_type: 0x0100_000c, // CPU_TYPE_ARM64
                cpu_subtype: 0,        // CPU_SUBTYPE_ARM64_ALL
                file_offset: 0x4000,
                size: 0x41c8,
                section_alignment: 14,
                _reserved: 0,
            },
        ]
    );

    for entry in &entries {
        let start = entry.file_offset as usize;
        let end = start + entry.size as usize;
        let slice = &buffer[start..end];
        let inner = parser::MachOFile::parse(slice).unwrap();
        let parser::MachOFile::Singlearch(_) = inner else {
            panic!("Expected singlearch slice at offset {start:#x}");
        };
        assert_eq!(inner.get_byte_order(), ByteOrder::LittleEndian);
    }
}
