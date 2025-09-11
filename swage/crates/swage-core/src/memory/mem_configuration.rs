use crate::util::ROW_SHIFT;
use serde::Deserialize;

pub const MTX_SIZE: usize = 30;

#[derive(Deserialize, Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct MemConfiguration {
    pub bk_shift: usize,
    pub bk_mask: usize,
    pub row_shift: usize,
    pub row_mask: usize,
    pub col_shift: usize,
    pub col_mask: usize,
    pub dram_mtx: [usize; MTX_SIZE],
    pub addr_mtx: [usize; MTX_SIZE],
    pub max_bank_bit: u64,
}

impl MemConfiguration {
    /// The periodicity of the bank function in rows, i.e., how many rows have to
    /// be iterated until the bank function repeats.
    pub fn bank_function_period(&self) -> u64 {
        1 << (self.max_bank_bit + 1 - ROW_SHIFT as u64)
    }
}

impl MemConfiguration {
    pub fn get_bank_count(&self) -> usize {
        (1 << self.bk_mask.count_ones()) as usize
    }
    pub fn get_row_count(&self) -> usize {
        1_usize << (self.row_mask.count_ones() as usize)
    }
}
