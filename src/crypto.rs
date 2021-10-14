//! This module contains crypto functions used by Filen to generate and process its keys and metadata.
use aes::Aes256;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::*;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::pbkdf2::pbkdf2;
use easy_hasher::easy_hasher::*;
use evpkdf::evpkdf;
use md5::Md5;
use rand::{thread_rng, Rng};
use rsa::pkcs8::{FromPrivateKey, FromPublicKey};
use rsa::PublicKey;
use secstr::SecUtf8;

use crate::errors::*;
use crate::utils;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const OPENSSL_SALT_PREFIX: &[u8] = b"Salted__";
const OPENSSL_SALT_PREFIX_BASE64: &[u8] = b"U2FsdGVk";
const OPENSSL_SALT_LENGTH: usize = 8;
const FILEN_VERSION_LENGTH: usize = 3;
const AES_GCM_IV_LENGTH: usize = 12;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FilenPasswordWithMasterKey {
    pub m_key: SecUtf8,
    pub sent_password: SecUtf8,
}

impl FilenPasswordWithMasterKey {
    /// Expects plain text password.
    pub fn from_user_password(password: &SecUtf8) -> FilenPasswordWithMasterKey {
        let m_key = SecUtf8::from(hash_fn(password.unsecure()));
        let sent_password = SecUtf8::from(hash_password(password.unsecure()));
        FilenPasswordWithMasterKey {
            m_key: m_key,
            sent_password: sent_password,
        }
    }

    /// Expects plain text password.
    pub fn from_user_password_and_auth_info_salt(password: &SecUtf8, salt: &SecUtf8) -> FilenPasswordWithMasterKey {
        let (password_bytes, salt_bytes) = (password.unsecure().as_bytes(), salt.unsecure().as_bytes());
        let pbkdf2_hash = derive_key_from_password_512(password_bytes, salt_bytes, 200_000);
        FilenPasswordWithMasterKey::from_derived_key(&pbkdf2_hash)
    }

    fn from_derived_key(derived_key: &[u8; 64]) -> FilenPasswordWithMasterKey {
        let (m_key, password_part) = derived_key.split_at(derived_key.len() / 2);
        let m_key_hex = utils::byte_slice_to_hex_string(m_key);
        let sent_password = sha512(&utils::byte_slice_to_hex_string(password_part)).to_vec();
        let sent_password_hex = utils::byte_slice_to_hex_string(&sent_password);
        FilenPasswordWithMasterKey {
            m_key: SecUtf8::from(m_key_hex),
            sent_password: SecUtf8::from(sent_password_hex),
        }
    }
}

/// Calculates OpenSSL-compatible AES 256 CBC (Pkcs7 padding) hash with 'Salted__' prefix, then 8 bytes of salt, rest is ciphered.
fn encrypt_aes_openssl(data: &[u8], key: &[u8], maybe_salt: Option<&[u8]>) -> Vec<u8> {
    let mut salt = [0u8; OPENSSL_SALT_LENGTH];
    match maybe_salt {
        Some(user_salt) if user_salt.len() == OPENSSL_SALT_LENGTH => salt.copy_from_slice(user_salt),
        _ => rand::thread_rng().fill(&mut salt),
    };

    let (key, iv) = generate_aes_key_and_iv(32, 16, 1, Some(&salt), key);
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();

    let mut encrypted = cipher.encrypt_vec(data);
    let mut result = OPENSSL_SALT_PREFIX.to_vec();
    result.extend_from_slice(&salt);
    result.append(&mut encrypted);
    result
}

/// Restores data prefiously encrypted with [encrypt_aes_001].
fn decrypt_aes_openssl(aes_encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let message_index = OPENSSL_SALT_PREFIX.len() + OPENSSL_SALT_LENGTH;
    if aes_encrypted_data.len() < message_index {
        bail!(bad_argument(
            "Encrypted data is too small to contain OpenSSL-compatible salt"
        ))
    }

    let (salt_with_prefix, message) = aes_encrypted_data.split_at(message_index);
    let (_, salt) = salt_with_prefix.split_at(OPENSSL_SALT_PREFIX.len());

    let (key, iv) = generate_aes_key_and_iv(32, 16, 1, Some(&salt), key);
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let decrypted_data = cipher
        .decrypt_vec(message)
        .map_err(|_| anyhow!(decryption_fail("Prefixed AES cannot decipher data")))?;
    Ok(decrypted_data)
}

/// Calculates AES-GCM hash. Returns IV within [0, [AES_GCM_IV_LENGTH]) range,
/// and encrypted message in base64-encoded part starting at [AES_GCM_IV_LENGTH] string index.
fn encrypt_aes_gcm(data: &[u8], key: &[u8]) -> Vec<u8> {
    let key = derive_key_from_password_256(key, key, 1);
    let iv = utils::random_alpha_string(AES_GCM_IV_LENGTH);
    let cipher = Aes256Gcm::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(iv.as_bytes());
    let encrypted = cipher.encrypt(nonce, data).unwrap(); // Will only panic when data.len() > 1 << 36
    let combined = iv + &base64::encode(encrypted);
    combined.into_bytes()
}

/// Restores data prefiously encrypted with [encrypt_aes_002].
fn decrypt_aes_gcm(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    fn extract_iv_and_message<'a>(data: &'a [u8]) -> Result<(&'a [u8], &'a [u8])> {
        if data.len() <= AES_GCM_IV_LENGTH {
            bail!(bad_argument("Encrypted data is too small to contain AES GCM IV"))
        }

        let (iv, message) = data.split_at(AES_GCM_IV_LENGTH);
        Ok((iv, message))
    }

    let (iv, encrypted_base64) = extract_iv_and_message(data)?;
    let decrypted_data = base64::decode(encrypted_base64)
        .map_err(|_| anyhow!(bad_argument("Given data to decrypt did not contain message in base64")))
        .and_then(|encrypted| {
            let key = derive_key_from_password_256(key, key, 1);
            let cipher = Aes256Gcm::new(Key::from_slice(&key));
            let nonce = Nonce::from_slice(iv);
            cipher
                .decrypt(nonce, encrypted.as_ref())
                .map_err(|_| anyhow!(decryption_fail("Prefixed AES GCM cannot decipher data")))
        })?;
    Ok(decrypted_data)
}

fn encrypt_rsa(data: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let padding = rsa::PaddingScheme::new_oaep::<sha2::Sha512>();
    let key = rsa::RsaPublicKey::from_public_key_der(public_key)?;
    key.encrypt(&mut rng, padding, data).with_context(|| {
        "Cannot encrypt data with given public key, assuming RSA-OAEP with SHA512 hash and PKCS8 format"
    })
}

fn decrypt_rsa(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    let padding = rsa::PaddingScheme::new_oaep::<sha2::Sha512>();
    let private_key = rsa::RsaPrivateKey::from_pkcs8_der(private_key)?;
    private_key.decrypt(padding, data).with_context(|| {
        "Cannot decrypt data with given private key, assuming non-base64 data encrypted by RSA-OAEP with SHA512 hash and PKCS8 format"
    })
}

/// Encrypts file metadata with given key. Depending on metadata version, different encryption algos will be used.
pub fn encrypt_metadata(data: &[u8], key: &[u8], metadata_version: u32) -> Result<Vec<u8>> {
    let encrypted_metadata = match metadata_version {
        1 => encrypt_aes_openssl(data, key, None), // Deprecated since August 2021
        2 => {
            let mut version_mark = format!("{:0>3}", metadata_version).into_bytes();
            version_mark.extend(encrypt_aes_gcm(data, key));
            version_mark
        }
        version => bail!(unsupported(&format!("Unsupported metadata version: {}", version))),
    };
    Ok(encrypted_metadata)
}

/// Restores file metadata prefiously encrypted with [encrypt_metadata] and given key.
pub fn decrypt_metadata(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    fn read_metadata_version(data: &[u8]) -> Result<i32> {
        let possible_salted_mark = &data[..OPENSSL_SALT_PREFIX.len()];
        let possible_version_mark = &data[..FILEN_VERSION_LENGTH];
        let metadata_version = if possible_salted_mark == OPENSSL_SALT_PREFIX {
            1
        } else if possible_salted_mark == OPENSSL_SALT_PREFIX_BASE64 {
            -1 // Means data is base_64 encoded, so we will have to decode later.
        } else {
            let possible_version_string = String::from_utf8_lossy(&possible_version_mark);
            possible_version_string.parse::<i32>().map_err(|_| {
                let message = format!("Invalid metadata version: {}", possible_version_string);
                anyhow!(bad_argument(&message))
            })?
        };
        Ok(metadata_version)
    }

    let metadata_version = read_metadata_version(data)?;
    let decrypted_metadata = match metadata_version {
        -1 => decrypt_aes_openssl(&base64::decode(data)?, key)?, // Deprecated since August 2021
        1 => decrypt_aes_openssl(data, key)?,                    // Deprecated since August 2021
        2 => decrypt_aes_gcm(&data[FILEN_VERSION_LENGTH..], key)?,
        version => bail!(unsupported(&format!("Unsupported metadata version: {}", version))),
    };
    Ok(decrypted_metadata)
}

/// Encrypts file metadata with given key. Depending on metadata version, different encryption algos will be used.
/// Convenience overload for [SecUtf8] params.
pub(crate) fn encrypt_metadata_strings(data: &SecUtf8, m_key: &SecUtf8, metadata_version: u32) -> Result<SecUtf8> {
    encrypt_metadata(
        data.unsecure().as_bytes(),
        m_key.unsecure().as_bytes(),
        metadata_version,
    )
    .map(|bytes| SecUtf8::from(String::from_utf8_lossy(&bytes)))
}

/// Restores file metadata prefiously encrypted with [encrypt_metadata] or [encrypt_metadata_strings].
/// Convenience overload for [SecUtf8] params.
pub(crate) fn decrypt_metadata_strings(data: &SecUtf8, m_key: &SecUtf8) -> Result<SecUtf8> {
    decrypt_metadata(&data.unsecure().as_bytes(), m_key.unsecure().as_bytes())
        .map(|bytes| SecUtf8::from(String::from_utf8_lossy(&bytes)))
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
    evpkdf::<Md5>(password, salt, iterations, &mut output);
    let (key, iv) = output.split_at(key_length);
    (Vec::from(key), Vec::from(iv))
}

/// Calculates login key from the given user password. Deprecated since August 2021.
fn hash_password(password: &str) -> String {
    let mut sha512_part_1 =
        sha512(&sha384(&sha256(&sha1(&password.to_owned()).to_hex_string()).to_hex_string()).to_hex_string())
            .to_hex_string();
    let sha512_part_2 =
        sha512(&md5(&md4(&md2(&password.to_owned()).to_hex_string()).to_hex_string()).to_hex_string()).to_hex_string();
    sha512_part_1.push_str(&sha512_part_2);
    sha512_part_1
}

/// Calculates poor man's alternative to pbkdf2 hash from the given string. Deprecated since August 2021.
fn hash_fn(value: &str) -> String {
    sha1(&sha512(&value.to_owned()).to_hex_string()).to_hex_string()
}

#[cfg(test)]
mod tests {
    use crate::{crypto::*, test_utils};
    use pretty_assertions::{assert_eq, assert_ne};

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

        assert_eq!(String::from_utf8_lossy(&decrypted_metadata), expected_metadata);
    }

    #[test]
    fn encrypt_metadata_v2_should_use_aes_gcm_with_version_mark() {
        let m_key = hash_fn("test");
        let metadata = "{\"name\":\"perform.js\",\"size\":156,\"mime\":\"application/javascript\",".to_owned()
            + "\"key\":\"tqNrczqVdTCgFzB1b1gyiQBIYmwDBwa9\",\"lastModified\":499162500}";

        let encrypted_metadata = encrypt_metadata(metadata.as_bytes(), m_key.as_bytes(), 2).unwrap();

        assert_eq!(encrypted_metadata.len(), 211);
        assert_eq!(&encrypted_metadata[..3], b"002");
    }

    #[test]
    fn decrypt_metadata_v2_should_use_aes_gcm_with_version_mark() {
        let m_key = hash_fn("test");
        let encrypted_metadata = "002CWAZWUt8h5n0Il13bkeirz7uY05vmrO58ZXemzaIGnmy+iLe95hXtwiAWHF4s".to_owned()
            + "9+g7gcj3LmwykWnZzUEZIAu8zIEyqe2J//iKaZOJMSIqGIg05GvVBl9INeqf2ACU7wRE9P7tCI5tKqgEWG/sMqRwPGwbNN"
            + "rn3yI8McEqCBdPWNfi6gl8OwzcqUVnMKZI/DPVSkUZQpaN83zCtA=";
        let expected_metadata = "{\"name\":\"perform.js\",\"size\":156,\"mime\":\"application/javascript\",".to_owned()
            + "\"key\":\"tqNrczqVdTCgFzB1b1gyiQBIYmwDBwa9\",\"lastModified\":499162500}";

        let decrypted_metadata = decrypt_metadata(encrypted_metadata.as_bytes(), m_key.as_bytes()).unwrap();
        let decrypted_metadata_str = String::from_utf8_lossy(&decrypted_metadata);

        assert_eq!(decrypted_metadata_str, expected_metadata);
    }

    #[test]
    fn encrypt_aes_gcm_should_should_work_and_have_same_algorithm() {
        let key = b"test";
        let expected_data = "This is Jimmy.";
        let encrypted_data = encrypt_aes_gcm(expected_data.as_bytes(), key);

        assert_eq!(encrypted_data.len(), 52);
        assert_ne!(&encrypted_data[..3], b"002");

        let decrypted_data = decrypt_aes_gcm(&encrypted_data, key).unwrap();
        assert_eq!(String::from_utf8_lossy(&decrypted_data), expected_data);
    }

    #[test]
    fn encrypt_aes_openssl_should_return_valid_aes_hash_without_explicit_salt() {
        let key = b"test";
        let expected_prefix = b"Salted__".to_vec();
        let actual_aes_hash_bytes = encrypt_aes_openssl(b"This is Jimmy.", key, None);

        assert_eq!(actual_aes_hash_bytes.len(), 32);
        assert_eq!(actual_aes_hash_bytes[..expected_prefix.len()], expected_prefix);
    }

    #[test]
    fn encrypt_aes_openssl_should_return_valid_aes_hash_with_explicit_salt() {
        let key = b"test";
        let actual_aes_hash_bytes = encrypt_aes_openssl(b"This is Jimmy.", key, Some(&[0u8, 1, 2, 3, 4, 5, 6, 7]));
        let actual_aes_hash = base64::encode(&actual_aes_hash_bytes);

        assert_eq!(
            actual_aes_hash,
            "U2FsdGVkX18AAQIDBAUGBzdjQTWH/ITXhkA7NCAPFOw=".to_owned()
        );
    }

    #[test]
    fn decrypt_aes_openssl_should_decrypt_previously_encrypted() {
        let key = b"test";
        let expected_data = b"This is Jimmy.";
        let encrypted_data = base64::decode(b"U2FsdGVkX1/Yn4fcMeb/VlvaU8447BMpZgao7xwEM9I=").unwrap();

        let actual_data_result = decrypt_aes_openssl(&encrypted_data, key);
        let actual_data = actual_data_result.unwrap();

        assert_eq!(actual_data, expected_data);
    }

    #[test]
    fn decrypt_aes_openssl_should_decrypt_currently_encrypted() {
        let key = b"test";
        let expected_data = b"This is Jimmy.";
        let encrypted_data = encrypt_aes_openssl(expected_data, key, Some(&[0u8, 1, 2, 3, 4, 5, 6, 7])); //b"U2FsdGVkX1/Yn4fcMeb/VlvaU8447BMpZgao7xwEM9I=";

        let actual_data_result = decrypt_aes_openssl(&encrypted_data, key);
        let actual_data = actual_data_result.unwrap();

        assert_eq!(actual_data, expected_data);
    }

    #[test]
    fn encrypt_rsa_and_decrypt_rsa_should_work_and_have_same_algorithm() {
        let expected_data = "This is Jimmy.";
        let m_key = SecUtf8::from("ed8d39b6c2d00ece398199a3e83988f1c4942b24");
        let private_key_file_contents = test_utils::read_project_file("tests/resources/filen_private_key.txt");
        let private_key_metadata_encrypted = SecUtf8::from(String::from_utf8_lossy(&private_key_file_contents));
        let private_key_decrypted = decrypt_metadata_strings(&private_key_metadata_encrypted, &m_key)
            .and_then(|str| utils::decode_secutf8_base64(&str))
            .unwrap();
        let public_key_file_contents = test_utils::read_project_file("tests/resources/filen_public_key.txt");
        let public_key_file = base64::decode(public_key_file_contents).unwrap();

        let encrypted_data = encrypt_rsa(expected_data.as_bytes(), &public_key_file).unwrap();
        assert_eq!(encrypted_data.len(), 512);

        let decrypted_data = decrypt_rsa(&encrypted_data, private_key_decrypted.unsecure()).unwrap();
        assert_eq!(String::from_utf8_lossy(&decrypted_data), expected_data);
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

        let parts = FilenPasswordWithMasterKey::from_derived_key(&pbkdf2_hash);

        assert_eq!(parts.m_key.unsecure(), expected_m_key);
        assert_eq!(parts.sent_password.unsecure(), expected_password);
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
