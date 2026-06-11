mod common;

use common::target_path;
use xdb::{Elf, FileAddr, VirtAddr};

const SHT_PROGBITS: u32 = 1;

#[test]
fn elf_parser_works() {
    let path = target_path("hello");
    let mut elf = Elf::new(&path).unwrap();

    assert_eq!(elf.path(), path);

    let header = elf.header();
    assert_eq!(&header.e_ident[..4], b"\x7fELF");
    assert_eq!(header.e_ident[libc::EI_CLASS], libc::ELFCLASS64);
    assert_eq!(header.e_type, libc::ET_DYN);
    assert_eq!(header.e_machine, libc::EM_X86_64);

    let text = elf
        .get_section_header(".text")
        .expect(".text section missing");
    assert_eq!(text.sh_type, SHT_PROGBITS);
    assert!(!elf.get_section_contents(".text").is_empty());

    let symbols = elf.get_symbols_by_name("main");
    if let Some(main) = symbols.first() {
        assert_eq!(elf.get_string(main.st_name as usize), "main");
    }

    let load_bias = 0x5555_5555_4000;
    elf.notify_load_bias(VirtAddr(load_bias));
    assert_eq!(elf.load_bias(), VirtAddr(load_bias));

    let text_file = elf.get_section_start_file_addr(".text").unwrap();
    let text_virt = elf.get_section_start_virt_addr(".text").unwrap();
    assert_eq!(text_virt.addr() - text_file.addr(), load_bias);

    let entry_file = FileAddr(elf.header().e_entry);
    let entry_virt = VirtAddr(load_bias + elf.header().e_entry);

    let by_file = elf
        .get_symbol_at_file_addr(entry_file)
        .expect("no symbol at entry");
    assert_eq!(elf.get_string(by_file.st_name as usize), "_start");

    let by_virt = elf
        .get_symbol_at_virt_addr(entry_virt)
        .expect("no symbol at entry virt");
    assert_eq!(elf.get_string(by_virt.st_name as usize), "_start");

    assert_eq!(by_file.st_value, by_virt.st_value);
}
