pub use swage_core::*;

pub mod allocator {
    pub use swage_core::allocator::*;
    #[cfg(feature = "hugepage")]
    pub use swage_hugepage::*;
    #[cfg(feature = "pfn")]
    pub use swage_pfn::Pfn;
    #[cfg(feature = "spoiler")]
    pub use swage_spoiler::Spoiler;
    #[cfg(feature = "thp")]
    pub use swage_thp::THP;
}

#[cfg(feature = "blacksmith")]
pub mod blacksmith {
    pub use swage_blacksmith::*;
}
