use shared::byte_order::ByteOrder;
use shared::iterators::FixedSizeStructIterator;

use crate::parser::shared::slice_at;
use crate::parser::ElfFile;
use crate::types::header::ElfClass;
use crate::types::program::{Phdr32, PHDR32_SIZE};
use crate::{ElfError, Result};

const ENTRY_SIZE: u64 = PHDR32_SIZE as u64;

pub fn phdr32_iter<'b>(
    table: &'b [u8],
    byte_order: ByteOrder,
) -> FixedSizeStructIterator<'b, PHDR32_SIZE, Phdr32> {
    FixedSizeStructIterator::new(byte_order, table, table.len() / PHDR32_SIZE)
}



pub fn program_headers<'a>(
    file: &ElfFile<'a>,
) -> Result<FixedSizeStructIterator<'a, PHDR32_SIZE, Phdr32>> {
    if file.class != ElfClass::Elf32 {
        return Err(ElfError::ClassMismatch {
            expected: ElfClass::Elf32,
            found: file.class,
        });
    }
    let h = &file.ehdr;

    if h.phnum == 0 {
        return Ok(phdr32_iter(&[], file.byte_order));
    }
    if usize::from(h.phentsize) != PHDR32_SIZE {
        return Err(ElfError::InvalidEntrySize {
            table: "program headers",
            expected: PHDR32_SIZE as u16, 
            found: h.phentsize,
        });
    }

         let size = u64::from(h.phnum)
        .checked_mul(ENTRY_SIZE)
        .ok_or(ElfError::Overflow { what: "program header table" })?;
    let table = slice_at(file.buf(), "program header table", h.phoff, size)?;
    Ok(phdr32_iter(table, file.byte_order))
}
