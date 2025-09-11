pub mod allocator;
pub mod hammerer;
mod mem_check;
pub mod memory;
pub mod page_inject;
mod swage;
pub mod util;
pub mod victim;

pub use crate::mem_check::HammerVictimTargetCheck;
pub use crate::mem_check::{ExcludeFromInit, MemCheck};

pub use swage::{DataPatternKind, ExperimentData, RoundProfile, Swage, SwageConfig};
