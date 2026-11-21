use shared::byte_order::ByteOrder;
use shared::iterators::FixedSizeStructIterator;

use crate::parser::b64::sections::section_headers;
use crate::parser::shared::slice_at;
use crate::parser::ElfFile;
use crate::types::header::ElfClass;
use crate::types::symbol::{Sym64, SYM64_SIZE};
use crate::{ElfError, Result};
use crate::types::section::{SectionType, Shdr64};



const SYM64_ENTRY: u64 = SYM64_SIZE as u64;

pub fn sym64_iter<'b>(
    table: &'b [u8],
    byte_order: ByteOrder,
) -> FixedSizeStructIterator<'b, SYM64_SIZE, Sym64> {
    FixedSizeStructIterator::new(byte_order, table, table.len() / SYM64_SIZE)
}

pub fn symbols<'a>(
    file: &ElfFile<'a>,
    symtab: &Shdr64,
) -> Result<FixedSizeStructIterator<'a, SYM64_SIZE, Sym64>> {
    if file.class != ElfClass::Elf64 {
        return Err(ElfError::ClassMismatch {
            expected: ElfClass::Elf64,
            found: file.class,
        });
    }
    if !matches!(
        symtab.section_type(),
        SectionType::SymTab | SectionType::DynSym
    ) {
        return Err(ElfError::InvalidSectionType {
            expected: "SHT_SYMTAB or SHT_DYNSYM",
            found: symtab.sh_type,
        });
    }

    if symtab.sh_entsize != SYM64_ENTRY {
        return Err(ElfError::InvalidEntrySize {
            table: "symbol",
            expected: 24,
            found: u16::try_from(symtab.sh_entsize).unwrap_or(u16::MAX),
        });
    }

    let count = symtab.sh_size / SYM64_ENTRY;
    let table = slice_at(
        file.buf(),
        "symbol table",
        symtab.sh_offset,
        count * SYM64_ENTRY,
    )?;
    Ok(sym64_iter(table, file.byte_order))
}

pub fn strtab_for<'a>(file: &ElfFile<'a>, symtab: &Shdr64) -> Result<&'a [u8]> {
    let index = usize::try_from(symtab.sh_link).unwrap_or(usize::MAX);
    let Some(Ok(strtab)) = section_headers(file)?.nth(index) else {
        return Err(ElfError::OutOfBounds {
            what: "string table section",
            offset: u64::from(symtab.sh_link),
            size: 1,
            buffer_len: file.buf().len(),
        });
    };
    slice_at(file.buf(), "string table", strtab.sh_offset, strtab.sh_size)
}
pub fn name_at(strtab: &[u8], offset: u32) -> Option<&std::ffi::CStr> {
    let start = usize::try_from(offset).ok()?;
    std::ffi::CStr::from_bytes_until_nul(strtab.get(start..)?).ok()
}


