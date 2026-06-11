use std::path::Path;

use xdb::dwarf::constants::{attr_name, form_name, tag_name};
use xdb::dwarf::die::DieRef;
use xdb::{Dwarf, Elf};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(path) = args.get(1) else {
        eprintln!("Usage: dwarf_dump <elf-file>");
        std::process::exit(1);
    };

    let elf = match Elf::new(Path::new(path)) {
        Ok(elf) => elf,
        Err(e) => {
            eprintln!("dwarf_dump: {e}");
            std::process::exit(1);
        }
    };
    let dwarf = match Dwarf::new(&elf) {
        Ok(dwarf) => dwarf,
        Err(e) => {
            eprintln!("dwarf_dump: {e}");
            std::process::exit(1);
        }
    };

    for unit in dwarf.units() {
        println!(
            "compile unit {} (offset {:#x}, version {})",
            unit.id().0,
            unit.offset(),
            unit.version()
        );
        dump_die(&dwarf.root(unit.id()), 1);
    }
}

fn dump_die(die: &DieRef<'_>, depth: usize) {
    let indent = "  ".repeat(depth);
    let tag = tag_name(die.tag()).map_or_else(|| format!("{:#x}", die.tag()), str::to_owned);
    print!("{indent}{tag}");
    if let Some(name) = die.name() {
        print!(" \"{name}\"");
    }
    println!();

    for attr in die.attrs() {
        let name =
            attr_name(attr.name()).map_or_else(|| format!("{:#x}", attr.name()), str::to_owned);
        let form =
            form_name(attr.form()).map_or_else(|| format!("{:#x}", attr.form()), str::to_owned);
        println!("{indent}  {name} [{form}]");
    }

    for child in die.children() {
        dump_die(&child, depth + 1);
    }
}
