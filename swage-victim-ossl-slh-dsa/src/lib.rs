#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

mod config;
mod ossl_slh_dsa;

pub use ossl_slh_dsa::OsslSlhDsa;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
