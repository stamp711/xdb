use std::path::PathBuf;

use crate::stoppoint::Stoppoint;
use crate::types::VirtAddr;

pub type SiteId = i32;
pub type BreakpointId = i32;

/// What a source-level breakpoint resolves against.
#[derive(Clone, Debug)]
pub enum BreakpointKind {
    Function(String),
    Line(PathBuf, u64),
    Address(VirtAddr),
}

/// A source-level breakpoint, which may resolve to several low-level sites
/// (e.g. one per overload, or per inlined copy). The sites themselves are owned
/// by the `Process`; this only tracks their ids.
pub struct Breakpoint {
    pub(crate) id: BreakpointId,
    pub(crate) kind: BreakpointKind,
    pub(crate) enabled: bool,
    pub(crate) hardware: bool,
    pub(crate) internal: bool,
    pub(crate) site_ids: Vec<SiteId>,
}

impl Breakpoint {
    pub fn id(&self) -> BreakpointId {
        self.id
    }

    pub fn kind(&self) -> &BreakpointKind {
        &self.kind
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn is_hardware(&self) -> bool {
        self.hardware
    }

    pub fn is_internal(&self) -> bool {
        self.internal
    }

    pub fn site_ids(&self) -> &[SiteId] {
        &self.site_ids
    }
}

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
