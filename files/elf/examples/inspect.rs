use std::env;
use std::fs;

use elf::parser::b64::sections::{section_headers, section_name};
use elf::parser::b64::segments::program_headers;
use elf::parser::b64::symbols::{name_at, strtab_for, symbols};
use elf::parser::parse_elf;

fn main() {
    let path = env::args()
        .nth(1)
        .expect("usage: cargo run --example inspect -- <elf-file>");
    let bytes = fs::read(&path).expect("failed to read file");
    let file = parse_elf(&bytes).expect("failed to parse ELF");

    println!("File: {path}");
    println!(
        "Header: {:?}, {:?}, type={:?}, machine={:?}, entry={:#x}",
        file.class, file.data, file.ehdr.file_type, file.ehdr.machine, file.ehdr.entry
    );

    println!("\nSegments ({}):", file.ehdr.phnum);
    for seg in program_headers(&file).unwrap().flatten() {
        println!(
            "  type={:?} flags={:#x} offset={:#x} vaddr={:#x} filesz={:#x}",
            seg.segment_type(),
            seg.p_flags,
            seg.p_offset,
            seg.p_vaddr,
            seg.p_filesz
        );
    }

    println!("\nSections ({}):", file.ehdr.shnum);
    let mut symtab_hdr = None;
    let mut text_hdr = None;

    for sec in section_headers(&file).unwrap().flatten() {
        let name = section_name(&file, &sec)
            .ok()
            .flatten()
            .and_then(|s| s.to_str().ok())
            .unwrap_or("");
        if name == ".symtab" {
            symtab_hdr = Some(sec);
        }
        if name == ".text" {
            text_hdr = Some(sec);
        }
        println!(
            "  {:18} type={:?} offset={:#x} size={:#x}",
            name,
            sec.section_type(),
            sec.sh_offset,
            sec.sh_size
        );
    }

    if let Some(symtab) = symtab_hdr {
        let strtab = strtab_for(&file, &symtab).unwrap();
        println!("\nSymbols:");
        for sym in symbols(&file, &symtab).unwrap().flatten() {
            let name = name_at(strtab, sym.st_name)
                .and_then(|s| s.to_str().ok())
                .unwrap_or("");
            if !name.is_empty() {
                println!(
                    "  {:20} type={:?} bind={:?} value={:#x} size={}",
                    name,
                    sym.sym_type(),
                    sym.binding(),
                    sym.st_value,
                    sym.st_size
                );
            }
        }
    }

    if let Some(text) = text_hdr {
        let start = usize::try_from(text.sh_offset).unwrap();
        let end = start + usize::try_from(text.sh_size).unwrap();
        let code = &file.buf()[start..end];
        println!("\n.text machine code ({} bytes):", code.len());
        for b in code {
            print!("{b:02x} ");
        }
        println!();
    }
}
