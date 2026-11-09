use shared::byte_order::ByteOrder;
use shared::iterators::FixedSizeStructIterator;

use crate::parser::shared::slice_at;
use crate::parser::ElfFile;
use crate::types::header::ElfClass;
use crate::types::section::{Shdr64, SHDR64_SIZE};
use crate::{ElfError, Result};

const SHDR64_ENTRY: u64 = SHDR64_SIZE as u64;

pub fn shdr64_iter<'b>(
    table: &'b [u8],
    byte_order: ByteOrder,
) -> FixedSizeStructIterator<'b, SHDR64_SIZE, Shdr64> {
    FixedSizeStructIterator::new(byte_order, table, table.len() / SHDR64_SIZE)
}

pub fn section_headers<'a>(
    file: &ElfFile<'a>,
) -> Result<FixedSizeStructIterator<'a, SHDR64_SIZE, Shdr64>> {
    if file.class != ElfClass::Elf64 {
        return Err(ElfError::ClassMismatch {
            expected: ElfClass::Elf64,
            found: file.class,
        });
    }

    let count = u64::from(file.ehdr.shnum);
    if count == 0 {
        return Ok(shdr64_iter(&[], file.byte_order));
    }

    if usize::from(file.ehdr.shentsize) != SHDR64_SIZE {
        return Err(ElfError::InvalidEntrySize {
            table: "section header",
            expected: 64,
            found: file.ehdr.shentsize,
        });
    }

    let table = slice_at(
        file.buf(),
        "section headers",
        file.ehdr.shoff,
        count * SHDR64_ENTRY,
    )?;
    Ok(shdr64_iter(table, file.byte_order))
}
