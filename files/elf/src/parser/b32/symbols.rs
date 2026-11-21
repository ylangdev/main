use shared::byte_order::ByteOrder;
use shared::iterators::FixedSizeStructIterator;

use crate::parser::b32::sections::section_by_index;
pub use crate::parser::shared::name_at;
use crate::parser::shared::slice_at;
use crate::parser::ElfFile;
use crate::types::header::ElfClass;
use crate::types::symbol::{Sym32, SYM32_SIZE};
use crate::{ElfError, Result};

use crate::types::section::{SectionType, Shdr32};


pub fn sym32_iter<'b>(
    table: &'b [u8],
    byte_order: ByteOrder,
) -> FixedSizeStructIterator<'b, SYM32_SIZE, Sym32> {
    let count = table.len() / SYM32_SIZE;
    FixedSizeStructIterator::new(byte_order, table, count)
}

pub fn symbols<'a>(
    file: &ElfFile<'a>,
    symtab: &Shdr32,
) -> Result<FixedSizeStructIterator<'a, SYM32_SIZE, Sym32>> {
    match file.class {
        ElfClass::Elf32 => {}
        other => {
            return Err(ElfError::ClassMismatch {
                expected: ElfClass::Elf32,
                found: other,
            });
        }
    } if !matches!(
        symtab.section_type(),
        SectionType::SymTab | SectionType::DynSym
    ) {
        return Err(ElfError::InvalidSectionType {
            expected: "SHT_SYMTAB or SHT_DYNSYM",
            found: symtab.sh_type,
        });
    }

    if symtab.sh_entsize != SYM32_SIZE as u32 {
        return Err(ElfError::InvalidEntrySize {
            table: "symbol table",
            expected: SYM32_SIZE as u16,
            found: u16::try_from(symtab.sh_entsize).unwrap_or(u16::MAX),
        });    }

    let offset = u64::from(symtab.sh_offset);
    let size = u64::from(symtab.sh_size);
    let table = slice_at(file.buf(), "symbol table", offset, size)?;

    Ok(sym32_iter(table, file.byte_order))
}

pub fn strtab_for<'a>(file: &ElfFile<'a>, symtab: &Shdr32) -> Result<&'a [u8]> {
    let strtab = section_by_index(file, symtab.sh_link)?;
    let offset = u64::from(strtab.sh_offset);
    let size = u64::from(strtab.sh_size);

    slice_at(file.buf(), "symbol string table", offset, size)
}
