//! This module contains general purpose functions (aka dump).
use anyhow::*;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::fs::File;
use std::io::Read;
use std::num::ParseIntError;
use std::path::Path;

/// Generate random alphanumeric string of the specified length.
pub(crate) fn random_alphanumeric_string(size: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect()
}

/// Converts the specified bytes into corresponding hex-encoded string.
pub(crate) fn byte_vec_to_hex_string(data: &Vec<u8>) -> String {
    data.iter().map(|byte| format!("{:02x}", byte)).collect()
}

/// Converts the specified bytes into corresponding hex-encoded string.
pub(crate) fn byte_slice_to_hex_string(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{:02x}", byte)).collect()
}

/// Converts the specified hex-encoded string into bytes.
pub(crate) fn hex_string_to_bytes(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

/// Treats given bytes as unicode scalar values and builds a string out of them.
pub(crate) fn bytes_to_binary_string(bytes: &[u8]) -> String {
    let mut buffer: String = String::with_capacity(bytes.len());
    for byte in bytes.iter() {
        buffer.push(*byte as char);
    }
    buffer
}

/// TODO: Remove when Result::flatten comes into stable compiler.
pub(crate) fn flatten_result<V, E, F>(result: Result<Result<V, F>, E>) -> Result<V, E>
where
    F: Into<E>,
{
    flatten_result_with(result, |e| e.into())
}

/// TODO: Remove when Result::flatten comes into stable compiler.
pub(crate) fn flatten_result_with<V, F, E, O: FnOnce(F) -> E>(result: Result<Result<V, F>, E>, op: O) -> Result<V, E> {
    match result {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(f)) => Err(op(f)),
        Err(e) => Err(e),
    }
}

pub(crate) fn filen_file_address_to_api_endpoint(
    region: &str,
    bucket: &str,
    file_uuid: &str,
    chunk_index: u32,
) -> String {
    vec![region, bucket, file_uuid, &chunk_index.to_string()]
        .join("/")
        .replace("//", "/")
}

/// Reads file at the specified path to the end.
pub(crate) fn read_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>> {
    let mut f = File::open(&file_path)?;
    let mut buffer = Vec::new();
    let _bytes_read = f.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// This macro generates a simple [std::fmt::Display] implementation using Serde's json! on self.
macro_rules! display_from_json {
    (
        $target_data_type:ty
    ) => {
        impl std::fmt::Display for $target_data_type {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match *self {
                    _ => write!(f, "{}", serde_json::json!(self)),
                }
            }
        }
    };
}
// TODO: Should this be a derive proc macro?
pub(crate) use display_from_json;

#[cfg(test)]
mod tests {
    use crate::utils::*;

    #[test]
    fn byte_vec_to_hex_should_return_hex_codes_for_non_empty_bytes() {
        let expected_hash_hex = "f82a1812080acab7ed5751e7193984565c8b159be00bb6c66eac70ff0c8ad8dd";
        let hash: Vec<u8> = vec![
            248, 42, 24, 18, 8, 10, 202, 183, 237, 87, 81, 231, 25, 57, 132, 86, 92, 139, 21, 155, 224, 11, 182, 198,
            110, 172, 112, 255, 12, 138, 216, 221,
        ];

        let hash_hex = byte_vec_to_hex_string(&hash);

        assert_eq!(expected_hash_hex, hash_hex);
    }

    #[test]
    fn filen_file_address_to_api_endpoint_should_join_parts_correctly() {
        let expected = "de-1/filen-1/b5ec90d2-957c-4481-b211-08a68accd1b2/0";
        let file_url = filen_file_address_to_api_endpoint("de-1", "filen-1", "b5ec90d2-957c-4481-b211-08a68accd1b2", 0);
        assert_eq!(file_url, expected);
    }
}
