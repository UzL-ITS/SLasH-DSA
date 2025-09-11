use crate::memory::{ConsecBlocks, GetConsecPfns};
use crate::util::Size;
use crate::util::alloc_util::compact_mem;
use log::warn;

pub trait ConsecAllocator {
    type Error: std::error::Error;
    fn block_size(&self) -> Size;
    fn alloc_consec_blocks(&mut self, size: Size) -> Result<ConsecBlocks, Self::Error>;
}

/// Allocate memory using an allocation strategy.
///
/// This is the main entry point for users who simply want to allocate some consecutive memory.
///
/// # Safety
///
/// This function is unsafe because it involves raw memory allocations
/// that are not managed by Rust's ownership or borrowing rules. The caller
/// must ensure that the memory is correctly deallocated and not accessed
/// concurrently from multiple threads.
///
/// # Arguments
///
/// * `allocator` - A mutable allocator object that implements the `ConsecAllocator` trait.
///   This strategy will be used to allocate the consecutive memory blocks.
/// * `mem_config` - The memory configuration specifying parameters like memory size and
///   alignment requirements.
/// * `mapping` - A reference to a `PatternAddressMapper`, which assists in determining the
///   aggressor sets for the given memory configuration.
///
/// # Errors
///
/// This function returns an `anyhow::Result` which is:
/// - `Ok(ConsecBlocks)` containing the allocated memory blocks.
/// - `Err(Error)` if there is any failure during allocation.
pub fn alloc_memory<E: std::error::Error>(
    allocator: &mut dyn ConsecAllocator<Error = E>,
    size: Size,
) -> Result<ConsecBlocks, E> {
    assert_eq!(
        size.bytes() % allocator.block_size().bytes(),
        0,
        "Size {} must be a multiple of block size {}",
        size,
        allocator.block_size()
    );
    assert!(size.bytes() > 0, "Size must be greater than 0");

    let compacted = compact_mem();
    match compacted {
        Ok(_) => {}
        Err(e) => warn!("Memory compaction failed: {:?}", e),
    }
    let memory = allocator.alloc_consec_blocks(size)?;
    memory.log_pfns(log::Level::Info);
    Ok(memory)
}
