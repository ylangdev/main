#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::indexing_slicing
)]

pub mod parser;
pub mod types;

use thiserror::Error;
use crate::types::header::ElfClass;

pub type Result<T> = core::result::Result<T, ElfError>;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ElfError {
    // Неверная магия \x7fELF
    #[error("invalid ELF magic: expected 7f 45 4c 46, found {found:02x?}")]
    BadMagic { found: [u8; 4] },

    #[error("unexpected end of buffer: need {needed} bytes at offset {offset:#x}, but only {available} available")]
    UnexpectedEof {
        offset: usize,
        needed: usize,
        available: usize,
    },

    #[error("unsupported ELF class: {0}")]
    UnsupportedClass(u8),

    #[error("unsupported data encoding: {0}")]
    UnsupportedData(u8),

    #[error("unsupported ELF version: {0}")]
    UnsupportedVersion(u32),

    #[error("ELF class mismatch: expected {expected:?}, found {found:?}")]
    ClassMismatch {
        expected: ElfClass,
        found: ElfClass,
    },

    #[error("invalid ELF header size: expected {expected}, found {found}")]
    InvalidHeaderSize {
        expected: u16,
        found: u16,
    },

    #[error("invalid {table} entry size: expected {expected}, found {found}")]
    InvalidEntrySize {
        table: &'static str,
        expected: u16,
        found: u16,
    },

    #[error("misaligned {what} at offset {offset:#x}: requires alignment {align}")]
    Misaligned {
        what: &'static str,
        offset: u64,
        align: u64,
    },

    #[error("{what} out of bounds: offset {offset:#x} + size {size:#x} exceeds buffer length {buffer_len:#x}")]
    OutOfBounds {
        what: &'static str,
        offset: u64,
        size: u64,
        buffer_len: usize,
    },

    #[error("arithmetic overflow while computing {what}")]
    Overflow { what: &'static str },
}
   
