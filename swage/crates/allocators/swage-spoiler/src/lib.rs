mod spoiler;

pub use spoiler::ConflictThreshold;
pub use spoiler::Spoiler;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
