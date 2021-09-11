//! This module contains crypto functions used by Filen to generate and process its keys.
use easy_hasher::easy_hasher::*;
use ring::{digest, pbkdf2};
use ring::pbkdf2::*;
use std::num::NonZeroU32;
use std::str;


#[derive(Debug)]
pub struct SentPasswordWithMasterKey {
    pub m_key: String,
    pub sent_password: String,
}

/// Calculates login key from the given user password and service-provided salt.
fn derive_key_from_password_generic(password: &[u8], salt: &[u8], iterations: u32, algorith: Algorithm, pbkdf2_hash: &mut [u8]) {
    let iterations_or_default = if iterations <= 0 { 200_000 } else { iterations };
    let actual_iterations = NonZeroU32::new(iterations_or_default).unwrap();
    pbkdf2::derive(
        algorith,
        actual_iterations,
        salt,
        password,
        pbkdf2_hash,
    );
}

/// Calculates login key from the given user password and service-provided salt using SHA512 with 64 bytes output.
pub fn derive_key_from_password_512(password: &[u8], salt: &[u8], iterations: u32) -> [u8; digest::SHA512_OUTPUT_LEN] {
    let mut pbkdf2_hash = [0u8; digest::SHA512_OUTPUT_LEN];
    derive_key_from_password_generic(password, salt, iterations, pbkdf2::PBKDF2_HMAC_SHA512, &mut pbkdf2_hash);
    pbkdf2_hash
}

/// Calculates login key from the given user password and service-provided salt using SHA512 with 32 bytes output.
pub fn derive_key_from_password_256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; digest::SHA512_256_OUTPUT_LEN] {
    let mut pbkdf2_hash = [0u8; digest::SHA512_256_OUTPUT_LEN];
    derive_key_from_password_generic(password, salt, iterations, pbkdf2::PBKDF2_HMAC_SHA512, &mut pbkdf2_hash);
    pbkdf2_hash
}

/// Calculates login key from the given user password. Deprecated.
pub fn hash_password(password: &String) -> String {
    let mut sha512_part_1 = sha512(&sha384(&sha256(&sha1(password).to_hex_string()).to_hex_string()).to_hex_string()).to_hex_string();
    let sha512_part_2 = sha512(&md5(&md4(&md2(password).to_hex_string()).to_hex_string()).to_hex_string()).to_hex_string();
    sha512_part_1.push_str(&sha512_part_2);
    sha512_part_1
}

/// Calculates something similar to pbkdf2 hash from the given string. Deprecated.
pub fn hash_fn(value: &String) -> String {
    sha1(&sha512(value).to_hex_string()).to_hex_string()
}

pub fn derived_key_to_sent_password(derived_key_hex: &str) -> SentPasswordWithMasterKey {
    let m_key = &derived_key_hex[..derived_key_hex.len() / 2];
    let password_part_hex = derived_key_hex[derived_key_hex.len() / 2..].to_string();
    let sent_password_hex = sha512(&password_part_hex).to_hex_string();
    SentPasswordWithMasterKey {
        m_key: m_key.to_string(),
        sent_password: sent_password_hex,
    }
}


#[cfg(test)]
mod tests {
    use crate::{filen::crypto::*, utils};
    
    #[test]
    fn derive_key_from_password_256_should_return_valid_pbkdf2_hash() {
        let password = b"test_pwd";
        let salt = b"test_salt";
        let expected_pbkdf2_hash: [u8; 32] = [
            248, 42, 24, 18, 8, 10, 202, 183, 237, 87, 81, 231, 25, 57, 132, 86, 92, 139, 21, 155, 224,
            11, 182, 198, 110, 172, 112, 255, 12, 138, 216, 221
        ];

        let actual_pbkdf2_hash = derive_key_from_password_256(password, salt, 200_000);

        assert_eq!(expected_pbkdf2_hash, actual_pbkdf2_hash);
    }

    #[test]
    fn derive_key_from_password_512_should_return_valid_pbkdf2_hash() {
        let password = b"test_pwd";
        let salt = b"test_salt";
        let expected_pbkdf2_hash: [u8; 64] = [
            248, 42, 24, 18, 8, 10, 202, 183, 237, 87, 81, 231, 25, 57, 132, 86, 92, 139, 21, 155, 224, 11, 
            182, 198, 110, 172, 112, 255, 12, 138, 216, 221, 58, 253, 102, 41, 117, 40, 216, 13, 51, 181, 109,
            144, 46, 10, 63, 172, 173, 165, 89, 54, 223, 115, 173, 131, 123, 157, 117, 100, 113, 185, 63, 49
        ];

        let actual_pbkdf2_hash = derive_key_from_password_512(password, salt, 200_000);

        assert_eq!(expected_pbkdf2_hash, actual_pbkdf2_hash);
    }

    #[test]
    fn derived_key_to_sent_password_should_return_valid_mkey_and_password() {
        let expected_m_key = "f82a1812080acab7ed5751e7193984565c8b159be00bb6c66eac70ff0c8ad8dd";
        let expected_password = "7a499370cf3f72fd2ce351297916fa8926daf33a01d592c92e3ee9e83c1521c342e60f2ecbde37bfdc00c45923c2568bc6a9c85c8653e19ade89e71ed9deac1d";
        let pbkdf2_hash: [u8; 64] = [
            248, 42, 24, 18, 8, 10, 202, 183, 237, 87, 81, 231, 25, 57, 132, 86, 92, 139, 21, 155, 224, 11, 
            182, 198, 110, 172, 112, 255, 12, 138, 216, 221, 58, 253, 102, 41, 117, 40, 216, 13, 51, 181, 109,
            144, 46, 10, 63, 172, 173, 165, 89, 54, 223, 115, 173, 131, 123, 157, 117, 100, 113, 185, 63, 49
        ];
        let pbkdf2_hash_hex = utils::byte_vec_to_hex(&pbkdf2_hash.to_vec());

        let parts = derived_key_to_sent_password(&pbkdf2_hash_hex);

        assert_eq!(expected_m_key, parts.m_key);
        assert_eq!(expected_password, parts.sent_password);
    }
    
    #[test]
    fn hash_password_should_return_valid_hash() {
        let password = "test_pwd".to_owned();
        let expected_hash =
            "21160f51da2cbbe04a195db31d7da72639d2eb99f9da3b05461123ab39b856cbb981fc9b97e64b36ab897".to_owned() +
            "7c6190117b18fa6d3055ac0b3411ea086fdc71bae0d806ec431c8628905f437276c3f64349683680974a7e" +
            "00ef216b94dbbc711bd4645df3ab46de3ed787828b73fc5c8a5abd959cb0d64591042519ef1b14ad08db7";

        let actual_hash = hash_password(&password);

        assert_eq!(expected_hash, actual_hash);
    }
}
