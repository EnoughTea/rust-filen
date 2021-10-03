//! This module contains general purpose functions (aka dump).
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::num::ParseIntError;

/// Generate random alphanumeric string of the specified length.
pub(crate) fn random_alpha_string(size: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect()
}

/// Converts the specified bytes into corresponding hex-encoded string.
pub(crate) fn byte_vec_to_hex(data: &Vec<u8>) -> String {
    data.iter().map(|byte| format!("{:02x}", byte)).collect()
}

pub(crate) fn byte_arr_to_hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{:02x}", byte)).collect()
}

pub(crate) fn hex_to_bytes(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

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

        let hash_hex = byte_vec_to_hex(&hash);

        assert_eq!(expected_hash_hex, hash_hex);
    }
}
