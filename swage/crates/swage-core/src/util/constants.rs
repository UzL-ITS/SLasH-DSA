#[derive(Clone, Copy, Debug)]
pub enum Size {
    B(usize),
    KB(usize),
    MB(usize),
    GB(usize),
}

impl Size {
    pub const fn bytes(&self) -> usize {
        match self {
            Size::B(bytes) => *bytes,
            Size::KB(kb) => *kb * (1 << 10),
            Size::MB(mb) => *mb * (1 << 20),
            Size::GB(gb) => *gb * (1 << 30),
        }
    }
}

impl std::fmt::Display for Size {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Size::B(bytes) => write!(f, "{} B", bytes),
            Size::KB(kb) => write!(f, "{} KB", kb),
            Size::MB(mb) => write!(f, "{} MB", mb),
            Size::GB(gb) => write!(f, "{} GB", gb),
        }
    }
}

pub const PAGE_SHIFT: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
pub const PAGE_MASK: usize = PAGE_SIZE - 1;

pub const ROW_SHIFT: usize = 13;
pub const ROW_SIZE: usize = 1 << ROW_SHIFT;
pub const ROW_MASK: usize = ROW_SIZE - 1;

pub const CL_SIZE: usize = 64;

pub const TIMER_ROUNDS: usize = 100_000;

pub const BASE_MSB: *mut libc::c_void = 0x2000000000 as *mut libc::c_void;
