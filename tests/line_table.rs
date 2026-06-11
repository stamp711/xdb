mod common;

use common::target_path;
use xdb::{Dwarf, Elf};

#[test]
fn line_table() {
    let elf = Elf::new(&target_path("hello")).unwrap();
    let dwarf = Dwarf::new(&elf).unwrap();
    assert_eq!(dwarf.units().len(), 1);

    let unit = dwarf.units()[0].id();
    let table = dwarf.line_table(unit).expect("hello has a line table");
    assert!(!table.files().is_empty());

    let mut rows = table.rows(&dwarf);
    let first = rows.next().expect("line table has rows");
    assert_eq!(
        table.file(first.file_index).path.file_name().unwrap(),
        "hello.cpp"
    );

    let stmt_lines: Vec<u64> = table
        .rows(&dwarf)
        .filter(|row| {
            row.is_stmt
                && !row.end_sequence
                && table.file(row.file_index).path.file_name().unwrap() == "hello.cpp"
        })
        .map(|row| row.line)
        .collect();
    // Statements live on lines 3-5 (the body of main). Some toolchains also emit a
    // statement for the closing brace on line 6 (the function epilogue at -O0), so
    // tolerate a trailing 6.
    assert!(stmt_lines == vec![3, 4, 5] || stmt_lines == vec![3, 4, 5, 6]);
}
