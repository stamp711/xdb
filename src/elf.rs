use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use memmap2::Mmap;

use crate::bit::from_bytes;
use crate::error::{Error, Result};
use crate::types::{FileAddr, VirtAddr};

pub struct Elf {
    path: PathBuf,
    data: Arc<Mmap>,
    header: libc::Elf64_Ehdr,
    section_headers: Vec<libc::Elf64_Shdr>,
    section_indices: HashMap<String, usize>, // name -> section header
    symbols: Vec<libc::Elf64_Sym>,
    symbol_name_indices: HashMap<String, Vec<usize>>, // name (raw,demangled) -> symbol
    symbol_address_ranges: BTreeMap<u64, (u64, usize)>, // addr range -> symbol
    load_bias: VirtAddr,
}

impl Elf {
    pub fn new(path: &Path) -> Result<Self> {
        let file =
            File::open(path).map_err(|e| Error::new(format!("Could not open ELF file: {e}")))?;
        // SAFETY: the file must not be truncated while mapped, the standard
        // debugger trade-off.
        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| Error::new(format!("Could not mmap ELF file: {e}")))?;
        let data = Arc::new(mmap);

        if data.len() < size_of::<libc::Elf64_Ehdr>() {
            return Err(Error::new("ELF file is too small"));
        }
        let header: libc::Elf64_Ehdr = from_bytes(&data);

        let mut elf = Self {
            path: path.to_path_buf(),
            data,
            header,
            section_headers: Vec::new(),
            section_indices: HashMap::new(),
            symbols: Vec::new(),
            symbol_name_indices: HashMap::new(),
            symbol_address_ranges: BTreeMap::new(),
            load_bias: VirtAddr(0),
        };

        elf.parse_section_headers()?;
        elf.build_section_map();
        elf.parse_symbol_table()?;
        elf.build_symbol_maps();
        Ok(elf)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn header(&self) -> &libc::Elf64_Ehdr {
        &self.header
    }

    pub fn data(&self) -> &Arc<Mmap> {
        &self.data
    }

    pub fn load_bias(&self) -> VirtAddr {
        self.load_bias
    }

    pub fn notify_load_bias(&mut self, bias: VirtAddr) {
        self.load_bias = bias;
    }

    pub fn get_section_header(&self, name: &str) -> Option<&libc::Elf64_Shdr> {
        self.section_indices
            .get(name)
            .map(|&i| &self.section_headers[i])
    }

    pub fn get_section_contents(&self, name: &str) -> &[u8] {
        match self.get_section_header(name) {
            Some(shdr) => {
                let start = shdr.sh_offset as usize;
                &self.data[start..start + shdr.sh_size as usize]
            }
            None => &[],
        }
    }

    pub fn get_section_start_file_addr(&self, name: &str) -> Option<FileAddr> {
        self.get_section_header(name)
            .map(|shdr| FileAddr(shdr.sh_addr))
    }

    pub fn get_section_start_virt_addr(&self, name: &str) -> Option<VirtAddr> {
        self.get_section_header(name)
            .map(|shdr| VirtAddr(self.load_bias.addr() + shdr.sh_addr))
    }

    pub fn section_containing_file_addr(&self, address: FileAddr) -> Option<&libc::Elf64_Shdr> {
        self.section_headers.iter().find(|shdr| {
            shdr.sh_addr <= address.addr() && address.addr() < shdr.sh_addr + shdr.sh_size
        })
    }

    pub fn section_containing_virt_addr(&self, address: VirtAddr) -> Option<&libc::Elf64_Shdr> {
        let bias = self.load_bias.addr();
        self.section_headers.iter().find(|shdr| {
            bias + shdr.sh_addr <= address.addr()
                && address.addr() < bias + shdr.sh_addr + shdr.sh_size
        })
    }

    pub fn file_addr_to_virt(&self, address: FileAddr) -> Option<VirtAddr> {
        self.section_containing_file_addr(address)?;
        Some(VirtAddr(self.load_bias.addr() + address.addr()))
    }

    pub fn virt_addr_to_file(&self, address: VirtAddr) -> Option<FileAddr> {
        self.section_containing_virt_addr(address)?;
        Some(FileAddr(address.addr() - self.load_bias.addr()))
    }

    /// Read a string from `.strtab` (or `.dynstr`) at the given byte index.
    pub fn get_string(&self, index: usize) -> &str {
        // NOTE: Although most ELF files have a general string table, in some cases they may
        // allocate different string tables to different sections.
        //
        // The more robust way to handle string tables is to read the sh_link field of the section
        // header to which the string table index belongs, which provides the section index of the
        // string table for that section.
        //
        // We've opted to assume there's a general string table for simplicity.
        let mut table = self.get_section_contents(".strtab");
        if table.is_empty() {
            table = self.get_section_contents(".dynstr");
        }
        read_c_str(table, index)
    }

    pub fn get_symbols_by_name(&self, name: &str) -> Vec<&libc::Elf64_Sym> {
        self.symbol_name_indices
            .get(name)
            .into_iter()
            .flatten()
            .map(|&i| &self.symbols[i])
            .collect()
    }

    pub fn get_symbol_containing_file_addr(&self, address: FileAddr) -> Option<&libc::Elf64_Sym> {
        let (_, &(end, index)) = self
            .symbol_address_ranges
            .range(..=address.addr())
            .next_back()?;
        (address.addr() < end).then(|| &self.symbols[index])
    }

    pub fn get_symbol_at_file_addr(&self, address: FileAddr) -> Option<&libc::Elf64_Sym> {
        self.get_symbol_containing_file_addr(address)
    }

    pub fn get_symbol_at_virt_addr(&self, address: VirtAddr) -> Option<&libc::Elf64_Sym> {
        let file_addr = self.virt_addr_to_file(address)?;
        self.get_symbol_containing_file_addr(file_addr)
    }

    fn parse_section_headers(&mut self) -> Result<()> {
        if self.header.e_shoff == 0 || self.header.e_shentsize == 0 {
            return Ok(()); // No section headers to parse
        }

        // Verify section header size
        if self.header.e_shentsize as usize != size_of::<libc::Elf64_Shdr>() {
            return Err(Error::new("Unexpected section header size"));
        }

        let mut count = self.header.e_shnum as u64;
        let first: libc::Elf64_Shdr = from_bytes(&self.data[self.header.e_shoff as usize..]);
        // Ref: https://refspecs.linuxbase.org/elf/gabi4+/ch4.sheader.html
        //
        // If the number of sections is greater than or equal to SHN_LORESERVE (0xff00), e_shnum
        // has the value SHN_UNDEF (0) and the actual number of section header table entries is
        // contained in the sh_size field of the section header at index 0 (otherwise, the sh_size
        // member of the initial entry contains 0).
        if count == 0 {
            count = first.sh_size;
        }

        let start = self.header.e_shoff as usize;
        let entry_size = size_of::<libc::Elf64_Shdr>();
        self.section_headers = (0..count as usize)
            .map(|i| from_bytes(&self.data[start + i * entry_size..]))
            .collect();
        Ok(())
    }

    fn build_section_map(&mut self) {
        let name_table_index = self.header.e_shstrndx as usize;
        let name_table = {
            let shdr = &self.section_headers[name_table_index];
            let start = shdr.sh_offset as usize;
            self.data[start..start + shdr.sh_size as usize].to_vec()
        };
        for (index, shdr) in self.section_headers.iter().enumerate() {
            let name = read_c_str(&name_table, shdr.sh_name as usize).to_owned();
            self.section_indices.insert(name, index);
        }
    }

    fn parse_symbol_table(&mut self) -> Result<()> {
        let symtab = self
            .get_section_header(".symtab")
            .or_else(|| self.get_section_header(".dynsym"));
        let Some(symtab) = symtab else {
            return Ok(());
        };
        // Verify section entry size
        if symtab.sh_entsize as usize != size_of::<libc::Elf64_Sym>() {
            return Err(Error::new("Unexpected symbol table entry size"));
        }

        let count = (symtab.sh_size / symtab.sh_entsize) as usize;
        let start = symtab.sh_offset as usize;
        let entry_size = size_of::<libc::Elf64_Sym>();
        self.symbols = (0..count)
            .map(|i| from_bytes(&self.data[start + i * entry_size..]))
            .collect();
        Ok(())
    }

    fn build_symbol_maps(&mut self) {
        const STT_TLS: u8 = 6;

        let string_table = self.string_table().to_vec();
        for (index, symbol) in self.symbols.iter().enumerate() {
            let raw_name = read_c_str(&string_table, symbol.st_name as usize).to_owned();
            if !raw_name.is_empty() {
                // Insert raw name -> symbol map
                self.symbol_name_indices
                    .entry(raw_name.clone())
                    .or_default()
                    .push(index);
                // Insert demangled name -> symbol map
                if let Some(demangled) = demangle(&raw_name) {
                    self.symbol_name_indices
                        .entry(demangled)
                        .or_default()
                        .push(index);
                }
            }

            // Insert addr range -> symbol map
            if symbol.st_value != 0 && symbol.st_name != 0 && symbol.st_info & 0xf != STT_TLS {
                self.symbol_address_ranges
                    .insert(symbol.st_value, (symbol.st_value + symbol.st_size, index));
            }
        }
    }

    fn string_table(&self) -> &[u8] {
        let table = self.get_section_contents(".strtab");
        if table.is_empty() {
            self.get_section_contents(".dynstr")
        } else {
            table
        }
    }
}

fn read_c_str(table: &[u8], index: usize) -> &str {
    if index >= table.len() {
        return "";
    }
    CStr::from_bytes_until_nul(&table[index..])
        .ok()
        .and_then(|s| s.to_str().ok())
        .unwrap_or("")
}

fn demangle(name: &str) -> Option<String> {
    let symbol = cpp_demangle::Symbol::new(name).ok()?;
    symbol.demangle().ok()
}
