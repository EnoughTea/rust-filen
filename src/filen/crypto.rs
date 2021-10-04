//! This module contains crypto functions used by Filen to generate and process its keys and metadata.
use ::aes::Aes256;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::pbkdf2::pbkdf2;
use easy_hasher::easy_hasher::*;
use evpkdf::evpkdf;
use rand::Rng;
use std::error::Error;

use crate::utils;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const OPENSSL_SALT_PREFIX: &[u8] = b"Salted__";
const OPENSSL_SALT_PREFIX_BASE64: &[u8] = b"U2FsdGVk";
const OPENSSL_SALT_LENGTH: usize = 8;
const FILEN_VERSION_LENGTH: usize = 3;
const AES_GCM_IV_LENGTH: usize = 12;

#[derive(Debug, PartialEq)]
pub struct SentPasswordWithMasterKey {
    pub m_key: Vec<u8>,
    pub sent_password: Vec<u8>,
}

impl SentPasswordWithMasterKey {
    /// Expects plain text password.
    fn from_password(password: &str) -> Result<SentPasswordWithMasterKey, Box<dyn Error>> {
        if password.len() < 1 {
            Err("Password is too short")?
        }

        let m_key = hash_fn(password);
        let sent_password = hash_password(password);
        Ok(SentPasswordWithMasterKey {
            m_key: m_key.into_bytes(),
            sent_password: sent_password.into_bytes(),
        })
    }

    /// Expects plain text password.
    pub fn from_password_and_salt(password: &str, salt: &str) -> Result<SentPasswordWithMasterKey, Box<dyn Error>> {
        let pbkdf2_hash = derive_key_from_password_512(password.as_bytes(), salt.as_bytes(), 200_000);
        SentPasswordWithMasterKey::from_derived_key(&pbkdf2_hash)
    }

    pub(crate) fn from_derived_key(derived_key: &[u8]) -> Result<SentPasswordWithMasterKey, Box<dyn Error>> {
        if derived_key.len() != 64 {
            Err("Derived key should be 64 bytes long")?
        }

        let m_key = &derived_key[..derived_key.len() / 2];
        let password_part = &derived_key[derived_key.len() / 2..];
        let sent_password = sha512(&utils::byte_slice_to_hex_string(password_part));
        Ok(SentPasswordWithMasterKey {
            m_key: m_key.to_vec(),
            sent_password: sent_password.to_vec(),
        })
    }
    fn m_key_as_hex_string(&self) -> String {
        utils::byte_vec_to_hex_string(&self.m_key)
    }

    fn sent_password_as_hex_string(&self) -> String {
        utils::byte_vec_to_hex_string(&self.sent_password)
    }
}

/// Calculates poor man's alternative to pbkdf2 hash from the given string. Deprecated since August 21.
pub fn hash_fn(value: &str) -> String {
    sha1(&sha512(&value.to_owned()).to_hex_string()).to_hex_string()
}

/// Calculates OpenSSL-compatible AES 256 CBC (Pkcs7 padding) hash with 'Salted__' prefix, then 8 bytes of salt, rest is ciphered.
pub fn encrypt_aes_prefixed(data: &[u8], password: &[u8], maybe_salt: Option<&[u8]>) -> Vec<u8> {
    let mut salt = [0u8; OPENSSL_SALT_LENGTH];
    match maybe_salt {
        Some(user_salt) if user_salt.len() == OPENSSL_SALT_LENGTH => salt.copy_from_slice(user_salt),
        _ => rand::thread_rng().fill(&mut salt),
    };

    let (key, iv) = generate_aes_key_and_iv(32, 16, 1, Some(&salt), password);
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();

    let mut encrypted = cipher.encrypt_vec(data);
    let mut result = OPENSSL_SALT_PREFIX.to_vec();
    result.extend_from_slice(&salt);
    result.append(&mut encrypted);
    result
}

/// Restores data prefiously encrypted with [encrypt_aes_prefixed].
pub fn decrypt_aes_prefixed(data: &[u8], password: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let message_index = OPENSSL_SALT_PREFIX.len() + OPENSSL_SALT_LENGTH;
    if data.len() < message_index {
        Err("Encrypted data is too small to contain OpenSSL-compatible salt")?
    }

    let (salt_with_prefix, message) = data.split_at(message_index);
    let (_, salt) = salt_with_prefix.split_at(OPENSSL_SALT_PREFIX.len());

    let (key, iv) = generate_aes_key_and_iv(32, 16, 1, Some(&salt), password);
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let decrypted_data = cipher
        .decrypt_vec(message)
        .map_err(|_| "Prefixed AES cannot decipher data")?;
    Ok(decrypted_data)
}

/// Calculates AES-GCM hash. Returns IV within [3, 15) range, and encrypted message in base64-encoded part starting at 15 string index.
pub fn encrypt_aes_prefixed_002(data: &[u8], password: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = derive_key_from_password_256(password, password, 1);
    let iv = utils::random_alpha_string(12);
    let cipher = Aes256Gcm::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(iv.as_bytes());
    let encrypted = cipher.encrypt(nonce, data);
    let combined = encrypted
        .map(|e| "002".to_string() + &iv + &base64::encode(e))
        .map_err(|_| "Prefixed AES GCM cannot decipher data")?;
    Ok(combined.into_bytes())
}

/// Restores data prefiously encrypted with [encrypt_aes_prefixed_002].
pub fn decrypt_aes_prefixed_002(data: &[u8], password: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    fn extract_iv_and_message<'a>(data: &'a [u8]) -> Result<&'a [u8], Box<dyn Error>> {
        let message_index = FILEN_VERSION_LENGTH + AES_GCM_IV_LENGTH;
        if data.len() <= message_index {
            Err("Encrypted data is too small to contain Filen API version and AES GCM iv")?
        }

        let (prefix, iv_and_message) = data.split_at(FILEN_VERSION_LENGTH);
        if prefix != b"002" {
            Err("Unsupported Filen API version")?
        }

        Ok(iv_and_message)
    }

    let iv_and_message = extract_iv_and_message(data)?;
    let (iv, encrypted_base64) = iv_and_message.split_at(AES_GCM_IV_LENGTH);
    let decrypted_data = base64::decode(encrypted_base64)
        .map_err(|_| "Encrypted data is not contained within base64")
        .and_then(|encrypted| {
            let key = derive_key_from_password_256(password, password, 1);
            let cipher = Aes256Gcm::new(Key::from_slice(&key));
            let nonce = Nonce::from_slice(iv);
            cipher
                .decrypt(nonce, encrypted.as_ref())
                .map_err(|_| "Prefixed AES GCM cannot decipher data")
        })?;
    Ok(decrypted_data)
}

/// Encrypts file metadata with hashed user's master key. Depending on metadata version, different encryption algos will be used.
pub fn encrypt_metadata(data: &[u8], hashed_m_key: &[u8], metadata_version: u32) -> Result<Vec<u8>, Box<dyn Error>> {
    let encrypted_metadata = match metadata_version {
        1 => encrypt_aes_prefixed(data, hashed_m_key, None), // Deprecated since August 21
        2 => encrypt_aes_prefixed_002(data, hashed_m_key)?,
        version => Err(format!("Unsupported metadata version: {}", version))?,
    };
    Ok(encrypted_metadata)
}

/// Restores file metadata prefiously encrypted with [encrypt_metadata].
pub fn decrypt_metadata(data: &[u8], hashed_m_key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    fn read_metadata_version(data: &[u8]) -> Result<i32, Box<dyn Error>> {
        let possible_salted_mark = &data[..OPENSSL_SALT_PREFIX.len()];
        let possible_version_mark = &data[..FILEN_VERSION_LENGTH];
        let metadata_version = if possible_salted_mark == OPENSSL_SALT_PREFIX {
            1
        } else if possible_salted_mark == OPENSSL_SALT_PREFIX_BASE64 {
            Err("Given data should not be base64-encoded")?
        } else {
            let possible_version_string = String::from_utf8(possible_version_mark.to_vec())?;
            possible_version_string
                .parse::<i32>()
                .map_err(|_| format!("Invalid metadata version: {}", possible_version_string))?
        };
        Ok(metadata_version)
    }

    let metadata_version = read_metadata_version(data)?;
    let decrypted_metadata = match metadata_version {
        1 => decrypt_aes_prefixed(data, hashed_m_key)?, // Deprecated since August 21
        2 => decrypt_aes_prefixed_002(data, hashed_m_key)?,
        version => Err(format!("Unsupported metadata version: {}", version))?,
    };
    Ok(decrypted_metadata)
}

/// Calculates login key from the given user password and service-provided salt.
fn derive_key_from_password_generic<M: Mac>(salt: &[u8], iterations: u32, mac: &mut M, pbkdf2_hash: &mut [u8]) {
    let iterations_or_default = if iterations <= 0 { 200_000 } else { iterations };
    pbkdf2(mac, salt, iterations_or_default, pbkdf2_hash);
}

/// Calculates login key from the given user password and service-provided salt using SHA512 with 64 bytes output.
fn derive_key_from_password_512(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    let mut mac = Hmac::new(crypto::sha2::Sha512::new(), password);
    let mut pbkdf2_hash = [0u8; 64];
    derive_key_from_password_generic(salt, iterations, &mut mac, &mut pbkdf2_hash);
    pbkdf2_hash
}

/// Calculates login key from the given user password and service-provided salt using SHA512 with 32 bytes output.
fn derive_key_from_password_256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut mac = Hmac::new(crypto::sha2::Sha512::new(), password);
    let mut pbkdf2_hash = [0u8; 32];
    derive_key_from_password_generic(salt, iterations, &mut mac, &mut pbkdf2_hash);
    pbkdf2_hash
}

/// OpenSSL-compatible plain AES key and IV.
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

/// Calculates login key from the given user password. Deprecated since August 21.
fn hash_password(password: &str) -> String {
    let mut sha512_part_1 =
        sha512(&sha384(&sha256(&sha1(&password.to_owned()).to_hex_string()).to_hex_string()).to_hex_string())
            .to_hex_string();
    let sha512_part_2 =
        sha512(&md5(&md4(&md2(&password.to_owned()).to_hex_string()).to_hex_string()).to_hex_string()).to_hex_string();
    sha512_part_1.push_str(&sha512_part_2);
    sha512_part_1
}

#[cfg(test)]
mod tests {
    use crate::{filen::crypto::*, utils};

    #[test]
    fn encrypt_metadata_v1_should_use_simple_aes() {
        let m_key = hash_fn("test");
        let metadata = "{\"name\":\"perform.js\",\"size\":156,\"mime\":\"application/javascript\",\"key\":\"tqNrczqVdTCgFzB1b1gyiQBIYmwDBwa9\",\"lastModified\":499162500}";

        let encrypted_metadata = encrypt_metadata(metadata.as_bytes(), m_key.as_bytes(), 1).unwrap();

        assert_eq!(encrypted_metadata.len(), 160);
        assert_eq!(&encrypted_metadata[..8], OPENSSL_SALT_PREFIX);
    }

    #[test]
    fn decrypt_metadata_v1_should_use_simple_aes() {
        let m_key = hash_fn("test");
        let metadata_base64 = "U2FsdGVkX1//gOpv81xPNI3PuT1CryNCVXpcfmISGNR+1g2OPT8SBP2/My7G6o5lSvVtkn2smbYrAo1Mgaq9RIJlCEjcYpMsr+A9RSpkX7zLyXtMPV6q+PRbQj1WkP8ymuh0lmmnFRa+oRy0EvJnw97m3aLTHN4DD5XmJ36tecA2cwSrFskYn9E8+0y+Wj/LcXh1l5n4Q1l5j8TSjS5mIQ==";
        let metadata = base64::decode(&metadata_base64).unwrap();
        let expected_metadata = "{\"name\":\"perform.js\",\"size\":156,\"mime\":\"application/javascript\",\"key\":\"tqNrczqVdTCgFzB1b1gyiQBIYmwDBwa9\",\"lastModified\":499162500}";

        let decrypted_metadata = decrypt_metadata(&metadata, m_key.as_bytes()).unwrap();

        assert_eq!(String::from_utf8(decrypted_metadata).unwrap(), expected_metadata);
    }

    #[test]
    fn encrypt_aes_002_should_return_valid_aes_hash() {
        let expected_prefix = b"002".to_vec();
        let data = b"This is Jimmy.";
        let encrypted_data = encrypt_aes_prefixed_002(data, b"test").unwrap();

        assert_eq!(encrypted_data.len(), 55);
        assert_eq!(encrypted_data[..expected_prefix.len()], expected_prefix);
    }

    #[test]
    fn decrypt_aes_002_should_decrypt_previously_encrypted() {
        let key = b"test";
        let expected_data = "This is Jimmy.".to_string();
        let encrypted_data = b"002N6wfUUJnj9q3NMz0v9RS39ZiZi+AJLAWcHfVfHkZQZQ4J7ZV32qA";

        let decrypted_data = decrypt_aes_prefixed_002(encrypted_data, key).unwrap();

        assert_eq!(String::from_utf8(decrypted_data).unwrap(), expected_data);
    }

    #[test]
    fn encrypt_aes_should_return_valid_aes_hash_without_explicit_salt() {
        let key = b"test";
        let expected_prefix = b"Salted__".to_vec();
        let actual_aes_hash_bytes = encrypt_aes_prefixed(b"This is Jimmy.", key, None);

        assert_eq!(actual_aes_hash_bytes.len(), 32);
        assert_eq!(actual_aes_hash_bytes[..expected_prefix.len()], expected_prefix);
    }

    #[test]
    fn encrypt_aes_should_return_valid_aes_hash_with_explicit_salt() {
        let key = b"test";
        let actual_aes_hash_bytes = encrypt_aes_prefixed(b"This is Jimmy.", key, Some(&[0u8, 1, 2, 3, 4, 5, 6, 7]));
        let actual_aes_hash = base64::encode(&actual_aes_hash_bytes);

        assert_eq!(
            actual_aes_hash,
            "U2FsdGVkX18AAQIDBAUGBzdjQTWH/ITXhkA7NCAPFOw=".to_owned()
        );
    }

    #[test]
    fn decrypt_aes_should_decrypt_previously_encrypted() {
        let key = b"test";
        let expected_data = b"This is Jimmy.";
        let encrypted_data = base64::decode(b"U2FsdGVkX1/Yn4fcMeb/VlvaU8447BMpZgao7xwEM9I=").unwrap();

        let actual_data_result = decrypt_aes_prefixed(&encrypted_data, key);
        let actual_data = actual_data_result.unwrap();

        assert_eq!(actual_data, expected_data);
    }

    #[test]
    fn decrypt_aes_should_decrypt_currently_encrypted() {
        let key = b"test";
        let expected_data = b"This is Jimmy.";
        let encrypted_data = encrypt_aes_prefixed(expected_data, key, Some(&[0u8, 1, 2, 3, 4, 5, 6, 7])); //b"U2FsdGVkX1/Yn4fcMeb/VlvaU8447BMpZgao7xwEM9I=";

        let actual_data_result = decrypt_aes_prefixed(&encrypted_data, key);
        let actual_data = actual_data_result.unwrap();

        assert_eq!(actual_data, expected_data);
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

        assert_eq!(actual_pbkdf2_hash, expected_pbkdf2_hash);
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

        assert_eq!(actual_pbkdf2_hash, expected_pbkdf2_hash);
    }

    #[test]
    fn derived_key_to_sent_password_should_return_valid_mkey_and_password() {
        let expected_m_key = "f82a1812080acab7ed5751e7193984565c8b159be00bb6c66eac70ff0c8ad8dd".to_owned();
        let expected_password = "7a499370cf3f72fd2ce351297916fa8926daf33a01d592c92e3ee9e83c152".to_owned()
            + "1c342e60f2ecbde37bfdc00c45923c2568bc6a9c85c8653e19ade89e71ed9deac1d";
        let pbkdf2_hash: [u8; 64] = [
            248, 42, 24, 18, 8, 10, 202, 183, 237, 87, 81, 231, 25, 57, 132, 86, 92, 139, 21, 155, 224, 11, 182, 198,
            110, 172, 112, 255, 12, 138, 216, 221, 58, 253, 102, 41, 117, 40, 216, 13, 51, 181, 109, 144, 46, 10, 63,
            172, 173, 165, 89, 54, 223, 115, 173, 131, 123, 157, 117, 100, 113, 185, 63, 49,
        ];

        let parts = SentPasswordWithMasterKey::from_derived_key(&pbkdf2_hash).unwrap();

        assert_eq!(parts.m_key, utils::hex_string_to_bytes(&expected_m_key).unwrap());
        assert_eq!(parts.m_key_as_hex_string(), expected_m_key);
        assert_eq!(
            parts.sent_password,
            utils::hex_string_to_bytes(&expected_password).unwrap()
        );
        assert_eq!(parts.sent_password_as_hex_string(), expected_password);
    }

    #[test]
    fn hash_password_should_return_valid_hash() {
        let password = "test_pwd".to_owned();
        let expected_hash = "21160f51da2cbbe04a195db31d7da72639d2eb99f9da3b05461123ab39b856cbb981fc9b97e64b36ab897"
            .to_owned()
            + "7c6190117b18fa6d3055ac0b3411ea086fdc71bae0d806ec431c8628905f437276c3f64349683680974a7e"
            + "00ef216b94dbbc711bd4645df3ab46de3ed787828b73fc5c8a5abd959cb0d64591042519ef1b14ad08db7";

        let actual_hash = hash_password(&password);

        assert_eq!(actual_hash, expected_hash);
    }
}
