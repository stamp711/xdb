use crate::stoppoint::Stoppoint;
use crate::types::{StoppointMode, VirtAddr};

pub type WatchpointId = i32;

/// A hardware watchpoint. Pure data; programming the debug registers and
/// sampling the watched memory is done by the owning `Process`.
#[derive(Debug)]
pub struct Watchpoint {
    pub(crate) id: WatchpointId,
    pub(crate) address: VirtAddr,
    pub(crate) mode: StoppointMode,
    pub(crate) size: usize,
    pub(crate) enabled: bool,
    pub(crate) hardware_register_index: Option<usize>,
    pub(crate) data: u64,
    pub(crate) previous_data: u64,
}

impl Watchpoint {
    pub(crate) fn new(
        id: WatchpointId,
        address: VirtAddr,
        mode: StoppointMode,
        size: usize,
    ) -> Self {
        Self {
            id,
            address,
            mode,
            size,
            enabled: false,
            hardware_register_index: None,
            data: 0,
            previous_data: 0,
        }
    }

    pub fn mode(&self) -> StoppointMode {
        self.mode
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn data(&self) -> u64 {
        self.data
    }

    pub fn previous_data(&self) -> u64 {
        self.previous_data
    }
}

impl Stoppoint for Watchpoint {
    type Id = WatchpointId;

    fn id(&self) -> WatchpointId {
        self.id
    }

    fn address(&self) -> VirtAddr {
        self.address
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}
