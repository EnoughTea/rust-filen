#![allow(dead_code)]
#![crate_type = "staticlib"]
#![forbid(unsafe_code)]

pub use {fure, reqwest, retry, secstr};

pub use {
    crate::crypto::{Error as CryptoError, *},
    filen_settings::*,
    retry_settings::*,
};

mod crypto;
mod file_chunk_pos;
mod filen_settings;
mod limited_exponential;
mod queries;
mod retry_settings;
mod utils;
pub mod v1;

#[cfg(test)]
mod test_utils;
