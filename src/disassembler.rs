use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter};

use crate::error::Result;
use crate::process::Process;
use crate::types::VirtAddr;

const MAX_X86_64_INSTRUCTION_LEN: usize = 15;

#[derive(Clone, Debug)]
pub struct Instruction {
    pub address: VirtAddr,
    pub text: String,
    pub is_call: bool,
}

pub struct Disassembler<'a> {
    process: &'a Process,
}

impl<'a> Disassembler<'a> {
    pub fn new(process: &'a Process) -> Self {
        Self { process }
    }

    pub fn disassemble(&self, count: usize, address: Option<VirtAddr>) -> Result<Vec<Instruction>> {
        // Default address is the current program counter
        let start = match address {
            Some(addr) => addr,
            None => self.process.get_pc()?,
        };

        let code = self
            .process
            .read_memory_without_traps(start, count * MAX_X86_64_INSTRUCTION_LEN)?;
        let mut decoder = Decoder::with_ip(64, &code, start.addr(), DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();

        let mut result = Vec::with_capacity(count);
        let mut text = String::new();
        while result.len() < count && decoder.can_decode() {
            let instruction = decoder.decode();
            text.clear();
            formatter.format(&instruction, &mut text);
            let is_call = matches!(
                instruction.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            );
            result.push(Instruction {
                address: VirtAddr(instruction.ip()),
                text: text.clone(),
                is_call,
            });
        }
        Ok(result)
    }
}
