//! This module contains general purpose functions (aka dump).
#![doc(hidden)]

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use secstr::SecUtf8;
use serde_json::{json, Value};
use uuid::Uuid;

/// Generate random alphanumeric string of the specified length.
pub fn random_alphanumeric_string(size: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect()
}

/// Converts the specified bytes into corresponding hex-encoded string.
pub fn bytes_to_hex_string(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{:02x}", byte)).collect()
}

/// Treats given bytes as unicode scalar values and builds a string out of them.
pub fn bytes_to_binary_string(bytes: &[u8]) -> String {
    let mut buffer: String = String::with_capacity(bytes.len());
    for byte in bytes.iter() {
        buffer.push(*byte as char);
    }
    buffer
}

/// TODO: Remove when Result::flatten comes into stable compiler.
pub fn flatten_result<V, E, F>(result: Result<Result<V, F>, E>) -> Result<V, E>
where
    F: Into<E>,
{
    flatten_result_with(result, |e| e.into())
}

/// TODO: Remove when Result::flatten comes into stable compiler.
pub fn flatten_result_with<V, F, E, O: FnOnce(F) -> E>(result: Result<Result<V, F>, E>, op: O) -> Result<V, E> {
    match result {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(f)) => Err(op(f)),
        Err(e) => Err(e),
    }
}

pub fn filen_file_location_to_api_endpoint(location: &FileChunkLocation) -> String {
    filen_file_address_to_api_endpoint(
        &location.region,
        &location.bucket,
        &location.file_uuid,
        location.chunk_index,
    )
}

pub fn filen_file_address_to_api_endpoint(region: &str, bucket: &str, file_uuid: &Uuid, chunk_index: u32) -> String {
    vec![
        region,
        bucket,
        &file_uuid.to_hyphenated().to_string(),
        &chunk_index.to_string(),
    ]
    .join("/")
    .replace("//", "/")
}

pub fn api_key_json(api_key: &SecUtf8) -> Value {
    json!({ "apiKey": api_key })
}

/// This macro generates a simple [std::fmt::Display] implementation using Serde's json! on self.
macro_rules! display_from_json {
    (
        $target_data_type:ty
    ) => {
        impl std::fmt::Display for $target_data_type {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match serde_json::to_string(self) {
                    Ok(repr) => write!(f, "{}", repr.trim_matches('"')),
                    Err(serde_err) => write!(f, "{}", serde_err),
                }
            }
        }
    };
}
// TODO: Should this be a derive proc macro?
pub(crate) use display_from_json;

use crate::v1::FileChunkLocation;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_vec_to_hex_should_return_hex_codes_for_non_empty_bytes() {
        let expected_hash_hex = "f82a1812080acab7ed5751e7193984565c8b159be00bb6c66eac70ff0c8ad8dd";
        let hash: Vec<u8> = vec![
            248, 42, 24, 18, 8, 10, 202, 183, 237, 87, 81, 231, 25, 57, 132, 86, 92, 139, 21, 155, 224, 11, 182, 198,
            110, 172, 112, 255, 12, 138, 216, 221,
        ];

        let hash_hex = bytes_to_hex_string(&hash);

        assert_eq!(expected_hash_hex, hash_hex);
    }

    #[test]
    fn filen_file_address_to_api_endpoint_should_join_parts_correctly() {
        let expected = "de-1/filen-1/b5ec90d2-957c-4481-b211-08a68accd1b2/0";
        let file_url = filen_file_address_to_api_endpoint(
            "de-1",
            "filen-1",
            &Uuid::parse_str("b5ec90d2-957c-4481-b211-08a68accd1b2").unwrap(),
            0,
        );
        assert_eq!(file_url, expected);
    }
}
