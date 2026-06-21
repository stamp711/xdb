use crate::error::{Error, Result};
use crate::types::VirtAddr;

pub trait Stoppoint {
    type Id: Copy + PartialEq + std::fmt::Display;

    fn id(&self) -> Self::Id;
    fn address(&self) -> VirtAddr;
    fn is_enabled(&self) -> bool;
    fn in_range(&self, low: VirtAddr, high: VirtAddr) -> bool {
        self.address() >= low && self.address() < high
    }
}

/// Owns a set of stoppoints (breakpoint sites or watchpoints) and looks them up
/// by id or address. This is pure storage: enabling and disabling is the job of
/// the owner that has access to the inferior.
pub struct StoppointCollection<T: Stoppoint> {
    stoppoints: Vec<T>,
}

impl<T: Stoppoint> Default for StoppointCollection<T> {
    fn default() -> Self {
        Self {
            stoppoints: Vec::new(),
        }
    }
}

impl<T: Stoppoint> StoppointCollection<T> {
    pub fn push(&mut self, stoppoint: T) -> &mut T {
        self.stoppoints.push(stoppoint);
        self.stoppoints.last_mut().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.stoppoints.is_empty()
    }

    pub fn len(&self) -> usize {
        self.stoppoints.len()
    }

    pub fn contains_id(&self, id: T::Id) -> bool {
        self.stoppoints.iter().any(|s| s.id() == id)
    }

    pub fn contains_address(&self, address: VirtAddr) -> bool {
        self.stoppoints.iter().any(|s| s.address() == address)
    }

    pub fn enabled_at_address(&self, address: VirtAddr) -> bool {
        self.stoppoints
            .iter()
            .any(|s| s.address() == address && s.is_enabled())
    }

    pub fn enabled_id_at_address(&self, address: VirtAddr) -> Option<T::Id> {
        self.stoppoints
            .iter()
            .find(|s| s.address() == address && s.is_enabled())
            .map(|s| s.id())
    }

    pub fn get_by_id(&self, id: T::Id) -> Result<&T> {
        self.stoppoints
            .iter()
            .find(|s| s.id() == id)
            .ok_or_else(|| not_found_id(id))
    }

    pub fn get_by_id_mut(&mut self, id: T::Id) -> Result<&mut T> {
        self.stoppoints
            .iter_mut()
            .find(|s| s.id() == id)
            .ok_or_else(|| not_found_id(id))
    }

    pub fn get_by_address(&self, address: VirtAddr) -> Result<&T> {
        self.stoppoints
            .iter()
            .find(|s| s.address() == address)
            .ok_or_else(|| not_found_address(address))
    }

    pub fn get_by_address_mut(&mut self, address: VirtAddr) -> Result<&mut T> {
        self.stoppoints
            .iter_mut()
            .find(|s| s.address() == address)
            .ok_or_else(|| not_found_address(address))
    }

    pub fn get_in_address_range(&self, low: VirtAddr, high: VirtAddr) -> Vec<&T> {
        self.stoppoints
            .iter()
            .filter(|s| s.in_range(low, high))
            .collect()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.stoppoints.iter()
    }

    /// Remove a stoppoint without touching the inferior. The owner is
    /// responsible for disabling it first.
    pub fn remove_by_id(&mut self, id: T::Id) -> Result<T> {
        let index = self
            .stoppoints
            .iter()
            .position(|s| s.id() == id)
            .ok_or_else(|| not_found_id(id))?;
        Ok(self.stoppoints.remove(index))
    }

    pub fn remove_by_address(&mut self, address: VirtAddr) -> Result<T> {
        let index = self
            .stoppoints
            .iter()
            .position(|s| s.address() == address)
            .ok_or_else(|| not_found_address(address))?;
        Ok(self.stoppoints.remove(index))
    }
}

fn not_found_id<Id: std::fmt::Display>(id: Id) -> Error {
    Error::new(format!("Stoppoint with id {id} not found"))
}

fn not_found_address(address: VirtAddr) -> Error {
    Error::new(format!("Stoppoint with address {address} not found"))
}
