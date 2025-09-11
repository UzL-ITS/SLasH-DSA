use log::info;
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
};

use swage_core::hammerer::Hammering;
use swage_core::memory::{FlipDirection, PhysAddr};

#[derive(Clone, Copy)]
pub struct Bit(usize);

pub struct DevMem {
    phys_addr: PhysAddr,
    bit: Bit,
    direction: FlipDirection,
}

impl DevMem {
    pub fn new(phys_addr: PhysAddr, bit: Bit, direction: FlipDirection) -> Self {
        assert!(bit.0 < 8);
        Self {
            phys_addr,
            bit,
            direction,
        }
    }
}

// The number of times to flip per "hammering" round.
const NUM_FLIP: usize = 999;

impl Hammering for DevMem {
    type Error = std::io::Error;
    fn hammer(&self) -> Result<(), Self::Error> {
        let mut prev_orig: Option<u8> = None;
        let mut prev_new: Option<u8> = None;
        let mut dev_mem = OpenOptions::new().read(true).write(true).open("/dev/mem")?;
        let mut value = [0u8; 1];
        for _ in 0..NUM_FLIP {
            dev_mem.seek(SeekFrom::Start(self.phys_addr.as_usize() as u64))?;
            dev_mem.read_exact(&mut value)?;
            // only flip if value changed
            if prev_orig.is_none_or(|prev| prev != value[0])
                && prev_new.is_none_or(|prev| prev != value[0])
            {
                let new_value = match self.direction {
                    FlipDirection::ZeroToOne => [value[0] | (1 << self.bit.0)],
                    FlipDirection::OneToZero => [value[0] & !(1 << self.bit.0)],
                    FlipDirection::Any => [value[0] ^ (1 << self.bit.0)],
                    FlipDirection::None | FlipDirection::Multiple(_) => {
                        unimplemented!("FlipDirection not implemented")
                    }
                };
                info!(
                    "Flipping address {:p} from {} to {}",
                    self.phys_addr, value[0], new_value[0],
                );
                dev_mem.seek(SeekFrom::Start(self.phys_addr.as_usize() as u64))?;
                dev_mem.write_all(&new_value)?;
                dev_mem.flush()?;
                prev_orig = Some(value[0]);
                prev_new = Some(new_value[0]);
            }
        }
        Ok(())
    }
}

impl From<usize> for Bit {
    fn from(value: usize) -> Self {
        Bit(value)
    }
}
