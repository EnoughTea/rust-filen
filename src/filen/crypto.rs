//! This module contains crypto functions used by Filen to generate and process its keys.
use ::aes::{Aes128, Aes192, Aes256};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::pbkdf2::pbkdf2;
use easy_hasher::easy_hasher::*;
use evpkdf::evpkdf;
use rand::Rng;
use std::str;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type Aes192Cbc = Cbc<Aes192, Pkcs7>;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const OPENSSL_SALT_PREFIX: &[u8] = b"Salted__";
const OPENSSL_SALT_LENGTH: usize = 8;

#[derive(Debug)]
pub struct SentPasswordWithMasterKey {
    pub m_key: String,
    pub sent_password: String,
}

/// Calculates login key from the given user password and service-provided salt.
fn derive_key_from_password_generic<M: Mac>(salt: &[u8], iterations: u32, mac: &mut M, pbkdf2_hash: &mut [u8]) {
    let iterations_or_default = if iterations <= 0 { 200_000 } else { iterations };
    pbkdf2(mac, salt, iterations_or_default, pbkdf2_hash);
}

/// Calculates login key from the given user password and service-provided salt using SHA512 with 64 bytes output.
pub fn derive_key_from_password_512(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    let mut mac = Hmac::new(crypto::sha2::Sha512::new(), password);
    let mut pbkdf2_hash = [0u8; 64];
    derive_key_from_password_generic(salt, iterations, &mut mac, &mut pbkdf2_hash);
    pbkdf2_hash
}

/// Calculates login key from the given user password and service-provided salt using SHA512 with 32 bytes output.
pub fn derive_key_from_password_256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut mac = Hmac::new(crypto::sha2::Sha512::new(), password);
    let mut pbkdf2_hash = [0u8; 32];
    derive_key_from_password_generic(salt, iterations, &mut mac, &mut pbkdf2_hash);
    pbkdf2_hash
}

/// Calculates login key from the given user password. Deprecated.
pub fn hash_password(password: &String) -> String {
    let mut sha512_part_1 =
        sha512(&sha384(&sha256(&sha1(password).to_hex_string()).to_hex_string()).to_hex_string()).to_hex_string();
    let sha512_part_2 =
        sha512(&md5(&md4(&md2(password).to_hex_string()).to_hex_string()).to_hex_string()).to_hex_string();
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

pub fn encrypt_aes_prefixed(data: &[u8], password: &[u8], maybe_salt: Option<&[u8]>) -> Vec<u8> {
    let mut rand = rand::thread_rng();
    let mut salt = [0u8; OPENSSL_SALT_LENGTH];
    match maybe_salt {
        Some(user_salt) if user_salt.len() == OPENSSL_SALT_LENGTH => salt.copy_from_slice(user_salt),
        _ => rand.fill(&mut salt),
    };

    let (key, iv) = generate_aes_key_and_iv(32, 16, 1, Some(&salt), password);
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();

    let mut encrypted = cipher.encrypt_vec(data);
    let mut result = OPENSSL_SALT_PREFIX.to_vec();
    result.extend_from_slice(&salt);
    result.append(&mut encrypted);
    result
}

pub fn decrypt_aes_prefixed(data: &[u8], password: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher_index = OPENSSL_SALT_PREFIX.len() + OPENSSL_SALT_LENGTH;
    if data.len() < cipher_index {
        Err("Encrypted data is too small to contain OpenSSL-compatible salt")
    } else {
        let (salt_with_prefix, ciphered) = data.split_at(cipher_index);
        let (_, salt) = salt_with_prefix.split_at(OPENSSL_SALT_PREFIX.len());

        let (key, iv) = generate_aes_key_and_iv(32, 16, 1, Some(&salt), password);
        let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
        cipher.decrypt_vec(ciphered).map_err(|_| "Cannot decipher data")
    }
}

fn generate_aes_key_and_iv(
    key_length: usize,
    iv_length: usize,
    iterations: usize,
    maybe_salt: Option<&[u8]>,
    password: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut output = vec![0; key_length + iv_length];
    let salt = match maybe_salt {
        Some(salt) => salt,
        None => &[0; 0],
    };
    evpkdf::<md5::Md5>(password, salt, iterations, &mut output);
    let (key, iv) = output.split_at(key_length);
    (Vec::from(key), Vec::from(iv))
}

pub fn decrypt_metadata(data: &str, key: &str) {
    let sliced = &data[..8];
}

#[cfg(test)]
mod tests {
    use crate::{filen::crypto::*, utils};
    use galvanic_assert::matchers::collection::*;
    use galvanic_assert::matchers::*;
    use galvanic_assert::*;

    #[test]
    fn encrypt_aes_should_return_valid_aes_hash_without_explicit_salt() {
        let expected_prefix = b"Salted__".to_vec();
        let actual_aes_hash_bytes = encrypt_aes_prefixed(b"This is Jimmy.", b"test", None);

        assert_that!(&actual_aes_hash_bytes.len(), eq(32));
        assert_that!(&actual_aes_hash_bytes, contains_subset(expected_prefix));
    }

    #[test]
    fn encrypt_aes_should_return_valid_aes_hash_with_explicit_salt() {
        let actual_aes_hash_bytes = encrypt_aes_prefixed(b"This is Jimmy.", b"test", Some(&[0u8, 1, 2, 3, 4, 5, 6, 7]));
        let actual_aes_hash = base64::encode(&actual_aes_hash_bytes);

        assert_that!(
            &actual_aes_hash,
            eq("U2FsdGVkX18AAQIDBAUGBzdjQTWH/ITXhkA7NCAPFOw=".to_string())
        );
    }

    #[test]
    fn decrypt_aes_should_decrypt_previously_encrypted() {
        let key = b"test";
        let expected_data = b"This is Jimmy.";
        let encrypted_data = base64::decode(b"U2FsdGVkX1/Yn4fcMeb/VlvaU8447BMpZgao7xwEM9I=").unwrap();

        let actual_data_result = decrypt_aes_prefixed(&encrypted_data, key);
        let actual_data = actual_data_result.unwrap();

        assert_that!(expected_data, contains_in_order(actual_data));
    }

    #[test]
    fn decrypt_aes_should_decrypt_currently_encrypted() {
        let key = b"test";
        let expected_data = b"This is Jimmy.";
        let encrypted_data = encrypt_aes_prefixed(expected_data, key, Some(&[0u8, 1, 2, 3, 4, 5, 6, 7])); //b"U2FsdGVkX1/Yn4fcMeb/VlvaU8447BMpZgao7xwEM9I=";

        let actual_data_result = decrypt_aes_prefixed(&encrypted_data, key);
        let actual_data = actual_data_result.unwrap();

        assert_that!(expected_data, contains_in_order(actual_data));
    }

    #[test]
    fn derive_key_from_password_256_should_return_valid_pbkdf2_hash() {
        let password = b"test_pwd";
        let salt = b"test_salt";
        let expected_pbkdf2_hash: [u8; 32] = [
            248, 42, 24, 18, 8, 10, 202, 183, 237, 87, 81, 231, 25, 57, 132, 86, 92, 139, 21, 155, 224, 11, 182, 198,
            110, 172, 112, 255, 12, 138, 216, 221,
        ];

        let actual_pbkdf2_hash = derive_key_from_password_256(password, salt, 200_000);

        assert_eq!(expected_pbkdf2_hash, actual_pbkdf2_hash);
    }

    #[test]
    fn derive_key_from_password_512_should_return_valid_pbkdf2_hash() {
        let password = b"test_pwd";
        let salt = b"test_salt";
        let expected_pbkdf2_hash: [u8; 64] = [
            248, 42, 24, 18, 8, 10, 202, 183, 237, 87, 81, 231, 25, 57, 132, 86, 92, 139, 21, 155, 224, 11, 182, 198,
            110, 172, 112, 255, 12, 138, 216, 221, 58, 253, 102, 41, 117, 40, 216, 13, 51, 181, 109, 144, 46, 10, 63,
            172, 173, 165, 89, 54, 223, 115, 173, 131, 123, 157, 117, 100, 113, 185, 63, 49,
        ];

        let actual_pbkdf2_hash = derive_key_from_password_512(password, salt, 200_000);

        assert_eq!(expected_pbkdf2_hash, actual_pbkdf2_hash);
    }

    #[test]
    fn derived_key_to_sent_password_should_return_valid_mkey_and_password() {
        let expected_m_key = "f82a1812080acab7ed5751e7193984565c8b159be00bb6c66eac70ff0c8ad8dd";
        let expected_password = "7a499370cf3f72fd2ce351297916fa8926daf33a01d592c92e3ee9e83c152".to_owned()
            + "1c342e60f2ecbde37bfdc00c45923c2568bc6a9c85c8653e19ade89e71ed9deac1d";
        let pbkdf2_hash: [u8; 64] = [
            248, 42, 24, 18, 8, 10, 202, 183, 237, 87, 81, 231, 25, 57, 132, 86, 92, 139, 21, 155, 224, 11, 182, 198,
            110, 172, 112, 255, 12, 138, 216, 221, 58, 253, 102, 41, 117, 40, 216, 13, 51, 181, 109, 144, 46, 10, 63,
            172, 173, 165, 89, 54, 223, 115, 173, 131, 123, 157, 117, 100, 113, 185, 63, 49,
        ];
        let pbkdf2_hash_hex = utils::byte_vec_to_hex(&pbkdf2_hash.to_vec());

        let parts = derived_key_to_sent_password(&pbkdf2_hash_hex);

        assert_eq!(expected_m_key, parts.m_key);
        assert_eq!(expected_password, parts.sent_password);
    }

    #[test]
    fn hash_password_should_return_valid_hash() {
        let password = "test_pwd".to_owned();
        let expected_hash = "21160f51da2cbbe04a195db31d7da72639d2eb99f9da3b05461123ab39b856cbb981fc9b97e64b36ab897"
            .to_owned()
            + "7c6190117b18fa6d3055ac0b3411ea086fdc71bae0d806ec431c8628905f437276c3f64349683680974a7e"
            + "00ef216b94dbbc711bd4645df3ab46de3ed787828b73fc5c8a5abd959cb0d64591042519ef1b14ad08db7";

        let actual_hash = hash_password(&password);

        assert_eq!(expected_hash, actual_hash);
    }
}
