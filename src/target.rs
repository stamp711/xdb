use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};

use nix::unistd::Pid;

use crate::breakpoint::{Breakpoint, BreakpointId, BreakpointKind};
use crate::disassembler::Disassembler;
use crate::dwarf::Dwarf;
use crate::dwarf::constants::{DW_AT_low_pc, DW_AT_ranges, DW_TAG_inlined_subroutine};
use crate::dwarf::die::DieHandle;
use crate::dwarf::line_table::SourceLocation;
use crate::elf::Elf;
use crate::error::{Error, Result};
use crate::process::{Process, ProcessState, StopReason};
use crate::register_info::RegisterId;
use crate::stack::Stack;
use crate::stoppoint::Stoppoint;
use crate::types::{FileAddr, VirtAddr};

const STT_FUNC: u8 = 2;

/// Owns a running process together with the static ELF and DWARF of the
/// program it is executing, and coordinates between the two for source-level
/// breakpoints and stepping.
pub struct Target {
    process: Process,
    elf: Elf,
    dwarf: Dwarf,
    stack: Stack,
    breakpoints: Vec<Breakpoint>,
    next_breakpoint_id: BreakpointId,
}

/// The function name and source position of the frame currently in focus: the
/// inlined frame if execution is virtually inside one, otherwise the physical
/// frame at the program counter.
pub struct CurrentLocation {
    pub function: Option<String>,
    pub source: Option<SourceLocation>,
}

// -- construction & accessors --
impl Target {
    pub fn launch(path: &Path, stdout_replacement: Option<BorrowedFd<'_>>) -> Result<Self> {
        let process = Process::launch(path, true, stdout_replacement)?;
        let elf = load_elf(&process, path)?;
        let dwarf = Dwarf::new(&elf)?;
        let mut target = Self::new(process, elf, dwarf);
        target.notify_stop()?;
        Ok(target)
    }

    pub fn attach(pid: Pid) -> Result<Self> {
        let process = Process::attach(pid)?;
        let exe = PathBuf::from(format!("/proc/{pid}/exe"));
        let elf = load_elf(&process, &exe)?;
        let dwarf = Dwarf::new(&elf)?;
        let mut target = Self::new(process, elf, dwarf);
        target.notify_stop()?;
        Ok(target)
    }

    fn new(process: Process, elf: Elf, dwarf: Dwarf) -> Self {
        Self {
            process,
            elf,
            dwarf,
            stack: Stack::default(),
            breakpoints: Vec::new(),
            next_breakpoint_id: 1,
        }
    }

    pub fn process(&self) -> &Process {
        &self.process
    }

    pub fn process_mut(&mut self) -> &mut Process {
        &mut self.process
    }

    pub fn elf(&self) -> &Elf {
        &self.elf
    }

    pub fn dwarf(&self) -> &Dwarf {
        &self.dwarf
    }

    pub fn stack(&self) -> &Stack {
        &self.stack
    }
}

// -- process control that keeps the inline stack in sync --
impl Target {
    pub fn resume(&mut self) -> Result<()> {
        self.process.resume()
    }

    pub fn wait_on_signal(&mut self) -> Result<StopReason> {
        let reason = self.process.wait_on_signal()?;
        self.notify_stop()?;
        Ok(reason)
    }

    pub fn step_instruction(&mut self) -> Result<StopReason> {
        let reason = self.process.step_instruction()?;
        self.notify_stop()?;
        Ok(reason)
    }

    fn run_until_address(&mut self, address: VirtAddr) -> Result<StopReason> {
        let reason = self.process.run_until_address(address)?;
        self.notify_stop()?;
        Ok(reason)
    }

    /// Called after the inferior stops; refreshes the per-stop debugger state.
    ///
    /// TODO: We need to augment the inline stack information if the reason is a breakpoint on an inline function.
    fn notify_stop(&mut self) -> Result<()> {
        self.reset_inline_height()
    }
}

// -- address and source lookups --
impl Target {
    pub fn get_pc_file_addr(&self) -> Option<FileAddr> {
        self.virt_addr_to_file(self.process.get_pc().ok()?)
    }

    // TODO(future): dispatch to the appropriate ELF
    fn virt_addr_to_file(&self, virt: VirtAddr) -> Option<FileAddr> {
        self.elf.virt_addr_to_file(virt)
    }

    fn file_addr_to_virt(&self, file_address: FileAddr) -> Result<VirtAddr> {
        self.elf
            .file_addr_to_virt(file_address)
            .ok_or_else(|| Error::new("Address is not in a loaded section"))
    }

    pub fn line_entry_at_pc(&self) -> Option<crate::dwarf::line_table::LineEntry> {
        let fpc = self.get_pc_file_addr()?;
        let cu = self.dwarf.unit_containing_address(fpc)?;
        self.dwarf
            .line_table(cu)?
            .entry_at_address(&self.dwarf, fpc)
    }

    fn source_location_at_pc(&self) -> Option<SourceLocation> {
        let fpc = self.get_pc_file_addr()?;
        let cu = self.dwarf.unit_containing_address(fpc)?;
        let table = self.dwarf.line_table(cu)?;
        let entry = table.entry_at_address(&self.dwarf, fpc)?;
        Some(SourceLocation {
            file: table.file(entry.file_index).clone(),
            line: entry.line,
        })
    }

    pub fn source_file_at_pc(&self) -> Option<PathBuf> {
        Some(self.source_location_at_pc()?.file.path)
    }

    pub fn function_name_at_address(&self, address: VirtAddr) -> String {
        let Some(fa) = self.elf.virt_addr_to_file(address) else {
            return String::new();
        };
        if let Some(handle) = self.dwarf.function_containing_address(fa)
            && let Some(name) = self.dwarf.die(handle).name()
        {
            return name.to_owned();
        }
        if let Some(sym) = self.elf.get_symbol_containing_file_addr(fa)
            && sym.st_info & 0xf == STT_FUNC
        {
            return self.elf.get_string(sym.st_name as usize).to_owned();
        }
        String::new()
    }

    /// Resolve the current frame's function name and source position, hiding the
    /// inline-vs-physical distinction (see [`CurrentLocation`]).
    pub fn current_location(&self) -> CurrentLocation {
        let inline = self.inline_stack_at_pc();
        if inline.is_empty() {
            // No DWARF frame here: name from the ELF symbol table, source from the line table.
            return CurrentLocation {
                function: self
                    .process
                    .get_pc()
                    .ok()
                    .map(|pc| self.function_name_at_address(pc)),
                source: self.source_location_at_pc(),
            };
        }
        // The focused frame's name comes from its own DIE. Its source line lives on its
        // inlined callee's `DW_AT_call_*` (one frame inward); the innermost frame has no
        // inlined callee, so fall back to the line table, which maps the pc to that same
        // innermost body line.
        let i = self.stack.current_inline_index();
        CurrentLocation {
            function: inline
                .get(i)
                .and_then(|h| self.dwarf.die(*h).name().map(str::to_owned)),
            source: inline
                .get(i + 1)
                .and_then(|h| self.dwarf.die(*h).location().ok())
                .or_else(|| self.source_location_at_pc()),
        }
    }
}

// -- breakpoints --
impl Target {
    pub fn breakpoint(&self, id: BreakpointId) -> Result<&Breakpoint> {
        self.breakpoints
            .iter()
            .find(|bp| bp.id() == id)
            .ok_or_else(|| not_found(id))
    }

    fn breakpoint_mut(&mut self, id: BreakpointId) -> Result<&mut Breakpoint> {
        self.breakpoints
            .iter_mut()
            .find(|bp| bp.id() == id)
            .ok_or_else(|| not_found(id))
    }

    pub fn breakpoints(&self) -> &[Breakpoint] {
        &self.breakpoints
    }

    pub fn create_function_breakpoint(
        &mut self,
        name: String,
        hardware: bool,
        internal: bool,
    ) -> Result<BreakpointId> {
        self.create_breakpoint(BreakpointKind::Function(name), hardware, internal)
    }

    pub fn create_line_breakpoint(
        &mut self,
        file: PathBuf,
        line: u64,
        hardware: bool,
        internal: bool,
    ) -> Result<BreakpointId> {
        self.create_breakpoint(BreakpointKind::Line(file, line), hardware, internal)
    }

    pub fn create_address_breakpoint(
        &mut self,
        address: VirtAddr,
        hardware: bool,
        internal: bool,
    ) -> Result<BreakpointId> {
        self.create_breakpoint(BreakpointKind::Address(address), hardware, internal)
    }

    fn create_breakpoint(
        &mut self,
        kind: BreakpointKind,
        hardware: bool,
        internal: bool,
    ) -> Result<BreakpointId> {
        let id = self.next_breakpoint_id;
        self.next_breakpoint_id += 1;
        self.breakpoints.push(Breakpoint {
            id,
            kind,
            enabled: false,
            hardware,
            internal,
            site_ids: Vec::new(),
        });
        self.resolve_breakpoint(id)?;
        Ok(id)
    }

    pub fn enable_breakpoint(&mut self, id: BreakpointId) -> Result<()> {
        self.breakpoint_mut(id)?.enabled = true;
        for site_id in self.breakpoint(id)?.site_ids.clone() {
            self.process.enable_breakpoint_site(site_id)?;
        }
        Ok(())
    }

    pub fn disable_breakpoint(&mut self, id: BreakpointId) -> Result<()> {
        self.breakpoint_mut(id)?.enabled = false;
        for site_id in self.breakpoint(id)?.site_ids.clone() {
            self.process.disable_breakpoint_site(site_id)?;
        }
        Ok(())
    }

    pub fn remove_breakpoint(&mut self, id: BreakpointId) -> Result<()> {
        self.disable_breakpoint(id)?;
        for site_id in self.breakpoint(id)?.site_ids.clone() {
            let _ = self.process.remove_breakpoint_site_by_id(site_id);
        }
        self.breakpoints.retain(|bp| bp.id() != id);
        Ok(())
    }

    /// Resolve the breakpoint by creating breakpoint sites.
    /// When new shared library is loaded, make sure to resolve the breakpoint again.
    ///
    /// TODO: Correctly handle when multiple breakpoints has same resolved breakpoint site address
    fn resolve_breakpoint(&mut self, id: BreakpointId) -> Result<()> {
        let bp = self.breakpoint(id)?;
        let (hardware, internal, enabled) = (bp.hardware, bp.internal, bp.enabled);
        let addresses = match bp.kind.clone() {
            BreakpointKind::Function(name) => self.resolve_function_addresses(&name)?,
            BreakpointKind::Line(file, line) => self.resolve_line_addresses(&file, line)?,
            BreakpointKind::Address(address) => vec![address],
        };

        for address in addresses {
            let existing = self
                .process
                .breakpoint_sites()
                .get_by_address(address)
                .map(|site| site.id())
                .ok();
            let site_id = match existing {
                Some(site_id) => site_id,
                None => self
                    .process
                    .create_breakpoint_site(address, hardware, internal)?,
            };

            let already_listed = {
                let bp = self.breakpoint_mut(id)?;
                if bp.site_ids.contains(&site_id) {
                    true
                } else {
                    bp.site_ids.push(site_id);
                    false
                }
            };
            if !already_listed && enabled {
                self.process.enable_breakpoint_site(site_id)?;
            }
        }
        Ok(())
    }

    fn resolve_function_addresses(&self, name: &str) -> Result<Vec<VirtAddr>> {
        // try to find functions in DWARF debug info first
        let functions = self.dwarf.find_functions(name);
        // if not found, find in ELF symbols
        if functions.is_empty() {
            return Ok(self
                .elf
                .get_symbols_by_name(name)
                .iter()
                .filter_map(|sym| self.elf.file_addr_to_virt(FileAddr(sym.st_value)))
                .collect());
        }

        let mut addresses = Vec::new();
        for handle in functions {
            let die = self.dwarf.die(handle);
            if !die.contains(DW_AT_low_pc) && !die.contains(DW_AT_ranges) {
                continue;
            }
            let file_address = if die.tag() == DW_TAG_inlined_subroutine {
                // inlined function has no prologue, so we use low_pc as breakpoint address
                die.low_pc()?
            } else {
                // not a inlined function, we use the second line entry address to skip the prologue
                let low = die.low_pc()?;
                let table = self
                    .dwarf
                    .line_table(handle.cu)
                    .ok_or_else(|| Error::new("Function CU has no line table"))?;
                let entry = table
                    .entry_at_address(&self.dwarf, low)
                    .ok_or_else(no_line_entry)?;
                table
                    .entry_after(&self.dwarf, &entry)
                    .ok_or_else(no_line_entry)?
                    .address
            };
            if let Some(address) = self.elf.file_addr_to_virt(file_address) {
                addresses.push(address);
            }
        }
        Ok(addresses)
    }

    fn resolve_line_addresses(&self, file: &Path, line: u64) -> Result<Vec<VirtAddr>> {
        let mut addresses = Vec::new();
        for unit in self.dwarf.units() {
            let Some(table) = self.dwarf.line_table(unit.id()) else {
                continue;
            };
            for entry in table.entries_by_line(&self.dwarf, file, line) {
                let inline_stack = self.dwarf.inline_stack_at_address(entry.address);
                let mut address = entry.address;
                if inline_stack.len() == 1
                    && self.dwarf.die(inline_stack[0]).low_pc()? == entry.address
                    && let Some(next) = table.entry_after(&self.dwarf, &entry)
                {
                    // skip the prologue
                    address = next.address;
                }
                if let Some(virt) = self.elf.file_addr_to_virt(address) {
                    addresses.push(virt);
                }
            }
        }
        Ok(addresses)
    }
}

// -- inline stack --
impl Target {
    /// Get the inline stack at the current pc.
    ///
    /// Returns the DIEs of the inline stack at the current pc, with the outermost function (which
    /// itself is not inlined) at the beginning. Contains (max_inline_height + 1) frames.
    pub fn inline_stack_at_pc(&self) -> Vec<DieHandle> {
        match self.get_pc_file_addr() {
            Some(fpc) => self.dwarf.inline_stack_at_address(fpc),
            None => Vec::new(),
        }
    }

    /// Calculate and set the inline height to the max possible inline height on current pc.
    fn reset_inline_height(&mut self) -> Result<()> {
        if self.process.state() != ProcessState::Stopped {
            self.stack.reset_inline_stack(0, 0);
            return Ok(());
        }

        let inline_stack = self.inline_stack_at_pc();

        if let Some(fpc) = self.get_pc_file_addr() {
            // Increment the inline height for each function beginning at the current PC
            // TODO: should we count the DW_TAG_subprogram? Remember to check this when implementing bt.
            let height = inline_stack
                .iter()
                .rev()
                .take_while(|handle| {
                    let die = self.dwarf.die(**handle);
                    die.tag() == DW_TAG_inlined_subroutine && die.low_pc().ok() == Some(fpc)
                })
                .count();
            self.stack.reset_inline_stack(inline_stack.len(), height);
        } else {
            self.stack.reset_inline_stack(inline_stack.len(), 0);
        };

        Ok(())
    }
}

// -- source-level stepping --
impl Target {
    pub fn step_in(&mut self) -> Result<StopReason> {
        // Simulate step if we are currently in an inlined function
        if self.stack.inline_height() > 0 {
            self.stack.simulate_inline_step_in();
            return Ok(StopReason::new_for_single_step());
        }

        // Step until we reach a different line table entry
        let original = self.line_entry_at_pc();
        loop {
            let reason = self.step_instruction()?; // at least step a single instruction
            if !reason.is_step() {
                return Ok(reason); // if stopped not because of step, return early
            }
            let current = self.line_entry_at_pc();
            match &current {
                None => break, // no line table entry for current pc
                // line entry changed && not end-of-sequence entry
                Some(line) if current != original && !line.end_sequence => break,
                _ => {}
            }
        }

        // Step over function prologue if needed: if we are at the start of a function (prologue),
        // step to the next line table entry. GCC: the first line table entry for a function marks
        // the start of the prologue.
        if let Some(fpc) = self.get_pc_file_addr()
            && let Some(handle) = self.dwarf.function_containing_address(fpc)
            && self.dwarf.die(handle).low_pc().ok() == Some(fpc)
            && let Some(entry) = self.line_entry_at_pc()
            && let Some(table) = self.dwarf.line_table(handle.cu)
            && let Some(next) = table.entry_after(&self.dwarf, &entry)
            && let Some(address) = self.elf.file_addr_to_virt(next.address)
        {
            return self.run_until_address(address);
        }
        Ok(StopReason::new_for_single_step())
    }

    pub fn step_over(&mut self) -> Result<StopReason> {
        // Same as step_in, but:
        // - If we are above an inlined function, step over it
        // - If we are at a call instruction, step to the instruction immediately after the call
        // TODO: which takes priority?
        let original = self.line_entry_at_pc();
        let mut reason;
        loop {
            let pc = self.process.get_pc()?;
            if self.stack.has_inline_frames() && self.stack.inline_height() > 0 {
                // We are above an inlined subroutine, run to end of it
                let inline_stack = self.inline_stack_at_pc();
                let die = self
                    .dwarf
                    .die(inline_stack[self.stack.current_inline_index() + 1]);
                let end = self.file_addr_to_virt(die.high_pc()?)?;
                reason = self.run_until_address(end)?;
                if !reason.is_step() || self.process.get_pc()? != end {
                    return Ok(reason);
                }
            } else {
                let instructions = Disassembler::new(&self.process).disassemble(2, Some(pc))?;
                if instructions[0].is_call {
                    // We are at call instruction, run to next instruction
                    // It's also ok if the callee never returns.
                    let return_address = instructions[1].address;
                    reason = self.run_until_address(return_address)?;
                    if !reason.is_step() || self.process.get_pc()? != return_address {
                        return Ok(reason);
                    }
                } else {
                    // In other cases, just step to next instruction
                    reason = self.step_instruction()?;
                    if !reason.is_step() {
                        return Ok(reason);
                    }
                }
            }

            let current = self.line_entry_at_pc();
            match &current {
                None => break, // no line table entry for current pc
                // line entry changed && not end-of-sequence entry
                Some(line) if current != original && !line.end_sequence => break,
                _ => {}
            }
        }
        Ok(reason)
    }

    pub fn step_out(&mut self) -> Result<StopReason> {
        // If we are in inlined subroutine, run to end of it
        if self.stack.has_inline_frames() && self.stack.current_inline_index() != 0 {
            let inline_stack = self.inline_stack_at_pc();
            let die = self
                .dwarf
                .die(inline_stack[self.stack.current_inline_index()]);
            let end = self.file_addr_to_virt(die.high_pc()?)?;
            return self.run_until_address(end);
        }

        // Otherwise, step out of current function
        //
        // Use rbp as frame pointer for now. UB if -fomit-frame-pointer.
        // TODO: do DWARF stack unwinding to determine return addr
        let rbp = self.process.registers().read_as::<u64>(RegisterId::rbp)?;
        let return_address = self.process.read_memory_as::<u64>(VirtAddr(rbp + 8))?;
        self.run_until_address(VirtAddr(return_address))
    }
}

/// Open the ELF and set its load bias from the runtime entry point, found in
/// the auxiliary vector (`AT_ENTRY`).
fn load_elf(process: &Process, path: &Path) -> Result<Elf> {
    let auxv = process.get_auxv()?;
    let mut elf = Elf::new(path)?;
    let entry = auxv
        .get(&(libc::AT_ENTRY))
        .ok_or_else(|| Error::new("AT_ENTRY missing from auxv"))?;
    let load_bias = entry - elf.header().e_entry;
    elf.notify_load_bias(VirtAddr(load_bias));
    Ok(elf)
}

fn not_found(id: BreakpointId) -> Error {
    Error::new(format!("Breakpoint {id} not found"))
}

fn no_line_entry() -> Error {
    Error::new("No line table entry for function")
}
