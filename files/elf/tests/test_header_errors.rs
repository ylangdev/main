mod common;

use common::{build_elf64, ORDERS};
use elf::parser::parse_elf;
use elf::types::header::{ElfClass, ElfData, ElfType};
use elf::types::machine::Machine;
use elf::ElfError;
use shared::byte_order::ByteOrder;

#[test]
fn test_elf64_header() {
    for order in ORDERS {
        let raw = build_elf64(order);
        let file = parse_elf(&raw).expect("valid elf64 header");

        let expected_data = if order == ByteOrder::LittleEndian {
            ElfData::Little
        } else {
            ElfData::Big
        };

        assert_eq!(file.class, ElfClass::Elf64);
        assert_eq!(file.byte_order, order);
        assert_eq!(file.data, expected_data);
        assert_eq!(file.ehdr.file_type, ElfType::Exec);
        assert_eq!(file.ehdr.machine, Machine::X86_64);
        assert_eq!(file.ehdr.entry, 0x40_1000);
        assert_eq!(file.ehdr.phnum, 1);
        assert_eq!(file.ehdr.shnum, 4);
        assert_eq!(file.ehdr.shstrndx, 1);
    }
}

#[test]
fn invalid_magic() {
    for order in ORDERS {
        let mut raw = build_elf64(order);
        raw[0] = 0x00;

        let err = parse_elf(&raw).unwrap_err();
        assert_eq!(
            err,
            ElfError::BadMagic {
                found: [0, b'E', b'L', b'F']
            }
        );
    }
}

#[test]
fn truncated_header() {
    for order in ORDERS {
        let raw = build_elf64(order);

        let err_ident = parse_elf(&raw[..10]).unwrap_err();
        assert_eq!(
            err_ident,
            ElfError::UnexpectedEof {
                offset: 0,
                needed: 16,
                available: 10,
            }
        );

        let err_ehdr = parse_elf(&raw[..40]).unwrap_err();
        assert_eq!(
            err_ehdr,
            ElfError::UnexpectedEof {
                offset: 0,
                needed: 64,
                available: 40,
            }
        );
    }
}
