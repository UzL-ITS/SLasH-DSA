use std::{cell::RefCell, ops::Range, ptr::null_mut};

use super::{BytePointer, PfnOffset, PhysAddr, pfn_offset::CachedPfnOffset};
use crate::memory::virt_to_phys::LinuxPageMapError;
use crate::memory::{LinuxPageMap, VirtToPhysResolver};
use crate::util::PAGE_SIZE;
use libc::{MAP_ANONYMOUS, MAP_POPULATE, MAP_SHARED};
use log::{log, trace, warn};
use pagemap::MemoryRegion;

#[derive(Clone, Debug)]
pub struct Memory {
    /// block pointer
    pub ptr: *mut u8,
    /// block length in bytes
    pub len: usize,
    pfn_offset: PfnOffset,
}

unsafe impl Send for Memory {}

impl Memory {
    pub fn new(ptr: *mut u8, len: usize) -> Self {
        Memory {
            ptr,
            len,
            pfn_offset: PfnOffset::Dynamic(Box::new(RefCell::new(None))),
        }
    }
    pub fn new_with_parts(ptr: *mut u8, len: usize, pfn_offset: PfnOffset) -> Self {
        Memory {
            ptr,
            len,
            pfn_offset,
        }
    }
    pub fn mmap(size: usize) -> std::result::Result<Self, std::io::Error> {
        let p = unsafe {
            libc::mmap(
                null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        unsafe { libc::memset(p, 0x00, size) };
        Ok(Memory::new(p as *mut u8, size))
    }

    pub fn dealloc(self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

impl BytePointer for Memory {
    fn addr(&self, offset: usize) -> *mut u8 {
        assert!(
            offset < self.len,
            "Memory::byte_add failed. Offset {} >= {}",
            offset,
            self.len
        );
        unsafe { self.ptr.byte_add(offset) }
    }
    fn ptr(&self) -> *mut u8 {
        self.ptr
    }
    fn len(&self) -> usize {
        self.len
    }
}

impl CachedPfnOffset for Memory {
    fn cached_offset(&self) -> &PfnOffset {
        &self.pfn_offset
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    LinuxPageMapError(#[from] LinuxPageMapError),
    #[error("Empty PFN range")]
    EmptyPfnRange,
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait GetConsecPfns {
    fn consec_pfns(&self) -> Result<ConsecPfns>;

    fn log_pfns(&self, level: log::Level) {
        let pfns = match self.consec_pfns() {
            Ok(pfns) => pfns,
            Err(e) => {
                warn!("Failed to get PFNs: {:?}", e);
                return;
            }
        };
        let pfns = pfns.format_pfns();
        log!(level, "PFNs:\n{}", pfns);
    }
}

impl GetConsecPfns for Memory {
    fn consec_pfns(&self) -> Result<ConsecPfns> {
        (self.ptr, self.len).consec_pfns()
    }
}

impl<T> GetConsecPfns for (*mut T, usize) {
    fn consec_pfns(&self) -> Result<ConsecPfns> {
        trace!("Get consecutive PFNs for vaddr 0x{:x}", self.0 as u64);
        let mut consecs = vec![];
        // optimization: get PFN range
        let mut resolver = LinuxPageMap::new()?;
        let pfns = resolver.get_phys_range(MemoryRegion::from((self.0 as u64, unsafe {
            self.0.byte_add(self.1) as u64
        })))?;
        if pfns.is_empty() {
            return Err(Error::EmptyPfnRange);
        }
        let mut phys_prev = pfns[0];
        let mut range_start = phys_prev;
        for phys in pfns.into_iter().skip(1) {
            if phys != phys_prev + PAGE_SIZE {
                consecs.push(range_start..phys_prev + PAGE_SIZE);
                range_start = phys;
            }
            phys_prev = phys;
        }
        consecs.push(range_start..phys_prev + PAGE_SIZE);
        trace!("PFN check done");
        Ok(consecs)
    }
}

pub trait FormatPfns {
    fn format_pfns(&self) -> String;
}

type ConsecPfns = Vec<Range<PhysAddr>>;

impl FormatPfns for ConsecPfns {
    fn format_pfns(&self) -> String {
        let mut pfns = String::from("");
        for range in self {
            pfns += &format!(
                "{:p}..[{:04} KB]..{:p}\n",
                range.start,
                (range.end - range.start).as_usize() / 1024,
                range.end
            );
        }
        pfns
    }
}

// TODO: we can move this alongside consec_alloc/mmap.rs, but we'll need some more refactoring before (self.pfn_offset is private).
impl Memory {
    #[cfg(false)]
    pub fn pfn_align(mut self) -> Result<Vec<Memory>> {
        let mut blocks = vec![];
        let offset = match self.pfn_offset {
            PfnOffset::Fixed(offset) => offset,
            PfnOffset::Dynamic(ref offset) => {
                let offset = offset.borrow();
                match offset.into() {
                    Some(offset) => offset
                        .expect("PFN offset not determined yet. Call MemBlock::pfn_offset() before MemBlock::pfn_align()")
                        .0
                        .expect("Block is not consecutive"),
                    None => bail!("PFN offset not determined yet. Call MemBlock::pfn_offset() before MemBlock::pfn_align()"),
                }
            }
        };
        if offset == 0 {
            return Ok(vec![self]);
        }
        assert_eq!(self.len, MB(4).bytes());
        let offset = self.len - offset * ROW_SIZE;
        assert!(offset < MB(4).bytes(), "Offset {} >= 4MB", offset);
        let ptr = self.addr(offset);
        let len = self.len - offset;
        let block = Memory::new(ptr, len); // TODO: add new trait for offsetting into MemBlock (byte_add returns *mut u8 now, but we need MemBlock here)
        blocks.push(block);
        self.len = offset;
        blocks.push(self);

        Ok(blocks)
    }
}
