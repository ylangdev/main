use std::ffi::CStr;

use shared::byte_order::ByteOrder;
use shared::iterators::FixedSizeStructIterator;

use crate::parser::shared::{name_at, slice_at};
use crate::parser::ElfFile;
use crate::types::header::ElfClass;
use crate::types::section::{Shdr32, SHDR32_SIZE};
use crate::{ElfError, Result};

const SHDR32_ENTRY: u64 = SHDR32_SIZE as u64;

pub fn shdr32_iter<'b>(
    table: &'b [u8],
    byte_order: ByteOrder,
) -> FixedSizeStructIterator<'b, SHDR32_SIZE, Shdr32> {
    FixedSizeStructIterator::new(byte_order, table, table.len() / SHDR32_SIZE)
}

pub fn section_headers<'a>(
    file: &ElfFile<'a>,
) -> Result<FixedSizeStructIterator<'a, SHDR32_SIZE, Shdr32>> {
    if file.class != ElfClass::Elf32 {
        return Err(ElfError::ClassMismatch {
            expected: ElfClass::Elf32,
            found: file.class,
        });
    }

    let count = u64::from(file.ehdr.shnum);
    if count == 0 {
        return Ok(shdr32_iter(&[], file.byte_order));
    }

    if usize::from(file.ehdr.shentsize) != SHDR32_SIZE {
        return Err(ElfError::InvalidEntrySize {
            table: "section header",
            expected: 40,
            found: file.ehdr.shentsize,
        });
    }

    let table = slice_at(
        file.buf(),
        "section headers",
        file.ehdr.shoff,
        count * SHDR32_ENTRY,
    )?;
    Ok(shdr32_iter(table, file.byte_order))
}

pub fn section_by_index(file: &ElfFile<'_>, index: u32) -> Result<Shdr32> {
    let pos = usize::try_from(index).unwrap_or(usize::MAX);
    match section_headers(file)?.nth(pos) {
        Some(Ok(section)) => Ok(section),
        _ => Err(ElfError::OutOfBounds {
            what: "section index",
            offset: u64::from(index),
            size: 1,
            buffer_len: file.buf().len(),
        }),
    }
}

pub fn shstrtab<'a>(file: &ElfFile<'a>) -> Result<&'a [u8]> {
    let section = section_by_index(file, u32::from(file.ehdr.shstrndx))?;
    slice_at(
        file.buf(),
        "section name table",
        section.sh_offset.into(),
        section.sh_size.into(),
    )
}

pub fn section_name<'a>(file: &ElfFile<'a>, shdr: &Shdr32) -> Result<Option<&'a CStr>> {
    let table = shstrtab(file)?;
    Ok(name_at(table, shdr.sh_name))
}
