use crate::memory::{LinuxPageMap, VirtToPhysResolver};

use super::virt_to_phys::{LinuxPageMapError, PhysAddr};

pub type Result<T> = std::result::Result<T, LinuxPageMapError>;

pub trait PfnResolver {
    fn pfn(&self) -> Result<PhysAddr>;
}

/// implementation for PfnResolver trait for raw pointers
impl<T> PfnResolver for *mut T {
    fn pfn(&self) -> Result<PhysAddr> {
        let mut resolver = LinuxPageMap::new()?;
        resolver.get_phys(*self as u64)
    }
}

/// implementation for PfnResolver trait for raw pointers
impl<T> PfnResolver for *const T {
    fn pfn(&self) -> Result<PhysAddr> {
        let mut resolver = LinuxPageMap::new()?;
        resolver.get_phys(*self as u64)
    }
}
