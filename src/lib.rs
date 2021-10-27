#![allow(dead_code)]
#![crate_type = "staticlib"]
#![forbid(unsafe_code)]

pub use {filen_settings::*, retry_settings::*};
pub use {fure, reqwest};
pub use {retry, secstr};

pub mod crypto;
mod file_chunk_pos;
mod filen_settings;
mod limited_exponential;
pub mod queries;
mod retry_settings;
mod utils;
pub mod v1;

#[cfg(test)]
mod test_utils;
