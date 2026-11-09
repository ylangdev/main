use shared::byte_order::ByteOrder;
use shared::iterators::FixedSizeStructIterator;

use crate::parser::shared::slice_at;
use crate::parser::ElfFile;
use crate::types::header::ElfClass;
use crate::types::program::{Phdr64, PHDR64_SIZE};
use crate::{ElfError, Result};

const PHDR64_ENTRY: u64 = PHDR64_SIZE as u64;

pub fn phdr64_iter<'b>(
    table: &'b [u8],
    byte_order: ByteOrder,
) -> FixedSizeStructIterator<'b, PHDR64_SIZE, Phdr64> {
    FixedSizeStructIterator::new(byte_order, table, table.len() / PHDR64_SIZE)
}

pub fn program_headers<'a>(
    file: &ElfFile<'a>,
) -> Result<FixedSizeStructIterator<'a, PHDR64_SIZE, Phdr64>> {
    if file.class != ElfClass::Elf64 {
        return Err(ElfError::ClassMismatch {
            expected: ElfClass::Elf64,
            found: file.class,
        });
    }

    let count = u64::from(file.ehdr.phnum);
    if count == 0 {
        return Ok(phdr64_iter(&[], file.byte_order));
    }

    if usize::from(file.ehdr.phentsize) != PHDR64_SIZE {
        return Err(ElfError::InvalidEntrySize {
            table: "program header",
            expected: 56,
            found: file.ehdr.phentsize,
        });
    }

    let table = slice_at(
        file.buf(),
        "program headers",
        file.ehdr.phoff,
        count * PHDR64_ENTRY,
    )?;
    Ok(phdr64_iter(table, file.byte_order))
}
