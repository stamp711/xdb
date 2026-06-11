use crate::stoppoint::Stoppoint;
use crate::types::VirtAddr;

pub type SiteId = i32;

/// A single low-level breakpoint location. Pure data; enabling and disabling
/// (patching the inferior, or programming a debug register) is done by the
/// owning `Process`.
#[derive(Debug)]
pub struct BreakpointSite {
    pub(crate) id: SiteId,
    pub(crate) address: VirtAddr,
    pub(crate) enabled: bool,
    pub(crate) original_byte: u8, // The original byte at the breakpoint address
    pub(crate) hardware: bool,
    pub(crate) internal: bool,
    pub(crate) hardware_register_index: Option<usize>,
}

impl BreakpointSite {
    pub(crate) fn new(id: SiteId, address: VirtAddr, hardware: bool, internal: bool) -> Self {
        Self {
            id,
            address,
            enabled: false,
            original_byte: 0,
            hardware,
            internal,
            hardware_register_index: None,
        }
    }

    pub fn is_hardware(&self) -> bool {
        self.hardware
    }

    pub fn is_internal(&self) -> bool {
        self.internal
    }
}

impl Stoppoint for BreakpointSite {
    type Id = SiteId;

    fn id(&self) -> SiteId {
        self.id
    }

    fn address(&self) -> VirtAddr {
        self.address
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}
