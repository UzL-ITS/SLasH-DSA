// ============================================================================
// SLH-DSA Parameters
// ============================================================================

// SHA2-128s Parameters
#[cfg(all(feature = "sha2", feature = "128s"))]
mod params {
    pub const SPX_N: usize = 16;
    pub const SIG_BYTES: usize = 7856;
    pub const ALGONAME: &str = "SLH-DSA-SHA2-128s";
}

// SHA2-128f Parameters
#[cfg(all(feature = "sha2", feature = "128f"))]
mod params {
    pub const SPX_N: usize = 16;
    pub const SIG_BYTES: usize = 17088;
    pub const ALGONAME: &str = "SLH-DSA-SHA2-128f";
}

// SHA2-192s Parameters
#[cfg(all(feature = "sha2", feature = "192s"))]
mod params {
    pub const SPX_N: usize = 24;
    pub const SIG_BYTES: usize = 16224;
    pub const ALGONAME: &str = "SLH-DSA-SHA2-192s";
}

// SHA2-192f Parameters
#[cfg(all(feature = "sha2", feature = "192f"))]
mod params {
    pub const SPX_N: usize = 24;
    pub const SIG_BYTES: usize = 35664;
    pub const ALGONAME: &str = "SLH-DSA-SHA2-192f";
}

// SHA2-256s Parameters
#[cfg(all(feature = "sha2", feature = "256s"))]
mod params {
    pub const SPX_N: usize = 32;
    pub const SIG_BYTES: usize = 29792;
    pub const ALGONAME: &str = "SLH-DSA-SHA2-256s";
}

// SHA2-256f Parameters
#[cfg(all(feature = "sha2", feature = "256f"))]
mod params {
    pub const SPX_N: usize = 32;
    pub const SIG_BYTES: usize = 49856;
    pub const ALGONAME: &str = "SLH-DSA-SHA2-256f";
}

// SHAKE-128s Parameters
#[cfg(all(feature = "shake", feature = "128s"))]
mod params {
    pub const SPX_N: usize = 16;
    pub const SIG_BYTES: usize = 7856;
    pub const ALGONAME: &str = "SLH-DSA-SHAKE-128s";
}

// SHAKE-128f Parameters
#[cfg(all(feature = "shake", feature = "128f"))]
mod params {
    pub const SPX_N: usize = 16;
    pub const SIG_BYTES: usize = 17088;
    pub const ALGONAME: &str = "SLH-DSA-SHAKE-128f";
}

// SHAKE-192s Parameters
#[cfg(all(feature = "shake", feature = "192s"))]
mod params {
    pub const SPX_N: usize = 24;
    pub const SIG_BYTES: usize = 16224;
    pub const ALGONAME: &str = "SLH-DSA-SHAKE-192s";
}

// SHAKE-192f Parameters
#[cfg(all(feature = "shake", feature = "192f"))]
mod params {
    pub const SPX_N: usize = 24;
    pub const SIG_BYTES: usize = 35664;
    pub const ALGONAME: &str = "SLH-DSA-SHAKE-192f";
}

// SHAKE-256s Parameters
#[cfg(all(feature = "shake", feature = "256s"))]
mod params {
    pub const SPX_N: usize = 32;
    pub const SIG_BYTES: usize = 29792;
    pub const ALGONAME: &str = "SLH-DSA-SHAKE-256s";
}

// SHAKE-256f Parameters
#[cfg(all(feature = "shake", feature = "256f"))]
mod params {
    pub const SPX_N: usize = 32;
    pub const SIG_BYTES: usize = 49856;
    pub const ALGONAME: &str = "SLH-DSA-SHAKE-256f";
}

#[cfg(feature = "det")]
mod variant_config {
    pub const OSSL_SLH_DSA_VARIANT: &str = "_det";
}

#[cfg(feature = "rnd")]
mod variant_config {
    pub const OSSL_SLH_DSA_VARIANT: &str = "_rnd";
}

// ============================================================================
// Compile-time Feature Validation
// ============================================================================
#[cfg(not(all(
    any(feature = "sha2", feature = "shake"),
    any(
        feature = "128s",
        feature = "128f",
        feature = "192s",
        feature = "192f",
        feature = "256s",
        feature = "256f"
    ),
    any(feature = "det", feature = "rnd")
)))]
compile_error!(
    "You must specify exactly one valid SLH-DSA Parameters set and DET/RND signing. \
Available Parameterss: SHA2-128s, SHA2-128f, SHA2-192s, SHA2-192f, SHA2-256s, SHA2-256f, SHAKE-128s, SHAKE-128f, SHAKE-192s, SHAKE-192f, SHAKE-256s, SHAKE-256f. \
Use both a hash function (sha2 or shake) and \
parameter set (128s, 128f, 192s, 192f, 256s, 256f) \
and det or rnd"
);

pub(crate) const LNODE_BASE: usize = 0xfb0;
pub(crate) const RNODE_BASE: usize = 0xfd0;
pub(crate) const STACK_OFFSET: usize = 31;

pub(crate) use params::{ALGONAME, SIG_BYTES, SPX_N};
pub(crate) use variant_config::OSSL_SLH_DSA_VARIANT;
