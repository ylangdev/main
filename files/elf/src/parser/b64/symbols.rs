use shared::byte_order::ByteOrder;
use shared::iterators::FixedSizeStructIterator;

use crate::parser::b64::sections::section_headers;
use crate::parser::shared::slice_at;
use crate::parser::ElfFile;
use crate::types::header::ElfClass;
use crate::types::section::Shdr64;
use crate::types::symbol::{Sym64, SYM64_SIZE};
use crate::{ElfError, Result};

use crate::parser::b64::sections::section_by_index;
pub use crate::parser::shared::name_at;


const SYM64_ENTRY: u64 = SYM64_SIZE as u64;

pub fn sym64_iter<'b>(
    table: &'b [u8],
    byte_order: ByteOrder,
) -> FixedSizeStructIterator<'b, SYM64_SIZE, Sym64> {
    FixedSizeStructIterator::new(byte_order, table, table.len() / SYM64_SIZE)
}

// symbols of one sht_symtab / sht_dynsym section
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

    if symtab.sh_entsize != SYM64_ENTRY {
        return Err(ElfError::InvalidEntrySize {
            table: "symbol",
            expected: 24,
            found: u16::try_from(symtab.sh_entsize).unwrap_or(u16::MAX),
        });
    }

    // whole entries only, so the multiplication below can't exceed sh_size
    let count = symtab.sh_size / SYM64_ENTRY;
    let table = slice_at(
        file.buf(),
        "symbol table",
        symtab.sh_offset,
        count * SYM64_ENTRY,
    )?;
    Ok(sym64_iter(table, file.byte_order))
}

// string table that holds the names for this symbol table (sh_link)
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

// st_name is a byte offset into the string table, not an index
pub fn name_at(strtab: &[u8], offset: u32) -> Option<&std::ffi::CStr> {
    let start = usize::try_from(offset).ok()?;
    std::ffi::CStr::from_bytes_until_nul(strtab.get(start..)?).ok()
}

pub fn strtab_for<'a>(file: &ElfFile<'a>, symtab: &Shdr64) -> Result<&'a [u8]> {
    let strtab = section_by_index(file, symtab.sh_link)?;
    slice_at(file.buf(), "string table", strtab.sh_offset, strtab.sh_size)
}
