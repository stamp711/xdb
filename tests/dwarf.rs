mod common;

use common::target_path;
use xdb::dwarf::constants::{DW_AT_language, DW_LANG_C_plus_plus_14};
use xdb::{Dwarf, Elf};

fn load(name: &str) -> (Elf, Dwarf) {
    let elf = Elf::new(&target_path(name)).unwrap();
    let dwarf = Dwarf::new(&elf).unwrap();
    (elf, dwarf)
}

#[test]
fn language_is_correct() {
    let (_elf, dwarf) = load("hello");
    assert_eq!(dwarf.units().len(), 1);

    let root = dwarf.root(dwarf.units()[0].id());
    let language = root.attr(DW_AT_language).unwrap().as_int().unwrap();
    assert_eq!(language, DW_LANG_C_plus_plus_14);
}

#[test]
fn die_iteration() {
    let (_elf, dwarf) = load("hello");
    assert_eq!(dwarf.units().len(), 1);

    let mut count = 0;
    for die in dwarf.root(dwarf.units()[0].id()).children() {
        assert_ne!(die.tag(), 0);
        count += 1;
    }
    assert!(count > 0);
}

#[test]
fn find_main_in_multiple_cus() {
    let (_elf, dwarf) = load("multi_cu");
    assert_eq!(dwarf.units().len(), 2);

    let results = dwarf.find_functions("main");
    assert_eq!(results.len(), 1);
    assert_eq!(dwarf.die(results[0]).name(), Some("main"));
}
