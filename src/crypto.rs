//! This module contains crypto functions used by Filen to generate and process its keys and metadata.
use std::convert::TryInto;

use aes::Aes256;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use easy_hasher::easy_hasher::*;
use evpkdf::evpkdf;
use hmac::{Hmac, Mac, NewMac};
use md5::Md5;
use pbkdf2::pbkdf2;
use rand::{thread_rng, Rng};
use rsa::pkcs8::{FromPrivateKey, FromPublicKey};
use rsa::PublicKey;
use secstr::*;
use snafu::{ensure, Backtrace, ResultExt, Snafu};

use crate::utils;

type Result<T, E = Error> = std::result::Result<T, E>;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;
type HmacSha512 = Hmac<sha2::Sha512>;

const OPENSSL_SALT_PREFIX: &[u8] = b"Salted__";
const OPENSSL_SALT_PREFIX_BASE64: &[u8] = b"U2FsdGVk";
const OPENSSL_SALT_LENGTH: usize = 8;
const AES_CBC_IV_LENGTH: usize = 16;
const AES_CBC_KEY_LENGTH: usize = 32;
const AES_GCM_IV_LENGTH: usize = 12;
const FILEN_VERSION_LENGTH: usize = 3;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("AES CBC failed to decipher raw bytes: {}", source))]
    AesCbcCannotDecipherData { source: block_modes::BlockModeError },

    #[snafu(display("Prefixed AES GCM failed to decipher ciphered message: {}", source))]
    AesGcmCannotDecipherData { source: aes_gcm::Error },

    #[snafu(display("Caller provided invalid argument: {}", message))]
    BadArgument { message: String, backtrace: Backtrace },

    #[snafu(display(r#"Expected data to be base64-encoded, but cannot decode it as such"#))]
    CannotDecodeBase64 { source: base64::DecodeError },

    #[snafu(display("Cannot parse Filen metadata from: {:?}", erroneous_part))]
    CannotParseFilenMetadataVersion {
        erroneous_part: String,
        source: std::num::ParseIntError,
    },

    #[snafu(display(
        "Caller expected decrypted metadata to be a valid UTF-8 string, but it was not. \
         Perhaps decrypt_metadata() should be used instead of decrypt_metadata_str()?"
    ))]
    DecryptedMetadataIsNotUtf8 { source: std::string::FromUtf8Error },

    #[snafu(display(
        "Somehow encrypted metadata was not a valid UTF-8 string. It is probably a bug in encrypt_metadata()"
    ))]
    EncryptedMetadataIsNotUtf8 { source: std::string::FromUtf8Error },

    #[snafu(display(
        "Cannot encrypt data with given public key, assuming RSA-OAEP with SHA512 hash and PKCS8 format: {}",
        source
    ))]
    RsaPkcs8CannotEncryptData { source: rsa::errors::Error },

    #[snafu(display(
        "Cannot decrypt data with given private key, assuming RSA-OAEP with SHA512 hash and PKCS8 format: {}",
        source
    ))]
    RsaPkcs8CannotDecryptData { source: rsa::errors::Error },

    #[snafu(display("Cannot deserialize PKCS#8 private key from ASN.1 DER-encoded data: {}", source))]
    RsaCannotDeserializePrivateKey { source: rsa::pkcs8::Error },

    #[snafu(display("Cannot deserialize public key from ASN.1 DER-encoded data: {}", source))]
    RsaCannotDeserializePublicKey { source: rsa::pkcs8::Error },

    #[snafu(display("Unsupported Filen file version {}", file_version))]
    UnsupportedFilenFileVersion { file_version: i64, backtrace: Backtrace },

    #[snafu(display("Unsupported Filen metadata version {}", metadata_version))]
    UnsupportedFilenMetadataVersion {
        metadata_version: i64,
        backtrace: Backtrace,
    },
}

/// Calculates poor man's alternative to pbkdf2 hash from the given string. Deprecated since August 2021.
pub fn hash_fn(value: &str) -> String {
    sha1(&sha512(&value.to_owned()).to_hex_string()).to_hex_string()
}

/// Calculates login key from the specified user password using chain of hashes. Deprecated since August 2021.
pub fn hash_password(password: &str) -> String {
    let mut sha512_part_1 =
        sha512(&sha384(&sha256(&sha1(&password.to_owned()).to_hex_string()).to_hex_string()).to_hex_string())
            .to_hex_string();
    let sha512_part_2 =
        sha512(&md5(&md4(&md2(&password.to_owned()).to_hex_string()).to_hex_string()).to_hex_string()).to_hex_string();
    sha512_part_1.push_str(&sha512_part_2);
    sha512_part_1
}

/// Calculates login key from the given user password and service-provided salt using SHA512 with 64 bytes output.
pub fn derive_key_from_password_512(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    let mut pbkdf2_hash = [0u8; 64];
    derive_key_from_password_generic::<HmacSha512>(password, salt, iterations, &mut pbkdf2_hash);
    pbkdf2_hash
}

/// Calculates login key from the given user password and service-provided salt using SHA512 with 32 bytes output.
pub fn derive_key_from_password_256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut pbkdf2_hash = [0u8; 32];
    derive_key_from_password_generic::<HmacSha512>(password, salt, iterations, &mut pbkdf2_hash);
    pbkdf2_hash
}

/// Encrypts given data to Filen metadata using given key.
/// Depending on metadata version, different encryption algos will be used.
pub fn encrypt_metadata(data: &[u8], key: &[u8], metadata_version: u32) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(vec![0u8; 0]);
    }

    match metadata_version {
        1 => Ok(base64::encode(encrypt_aes_openssl(data, key, None)).as_bytes().to_vec()), // Deprecated since August 2021
        2 => {
            let mut version_mark = format!("{:0>3}", metadata_version).into_bytes();
            version_mark.extend(encrypt_aes_gcm_base64(data, key));
            Ok(version_mark)
        }
        version => UnsupportedFilenMetadataVersion {
            metadata_version: version,
        }
        .fail(),
    }
}

/// Decrypts Filen metadata prefiously encrypted with [encrypt_metadata]/[encrypt_metadata_str] and one of the
/// given keys. Tries to decrypt using given keys until one of them succeeds.
pub fn decrypt_metadata_any_key(data: &[u8], keys: &[Vec<u8>]) -> Result<Vec<u8>> {
    ensure!(
        keys.len() > 0,
        BadArgument {
            message: "keys for decrypting metadata cannot be empty",
        }
    );

    let mut result = Ok(vec![0u8; 0]);
    for key in keys {
        result = decrypt_metadata(data, key);
        if result.is_ok() {
            break;
        }
    }

    if result.is_ok() {
        result
    } else {
        BadArgument {
            message: "all given keys failed to decrypt metadata",
        }
        .fail()
    }
}

/// Decrypts Filen metadata prefiously encrypted with [encrypt_metadata]/[encrypt_metadata_str] and given key.
pub fn decrypt_metadata(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    fn read_metadata_version(data: &[u8]) -> Result<i32> {
        let possible_salted_mark = &data[..OPENSSL_SALT_PREFIX.len()];
        let possible_version_mark = &data[..FILEN_VERSION_LENGTH];
        if possible_salted_mark == OPENSSL_SALT_PREFIX_BASE64 {
            Ok(1)
        } else if possible_salted_mark == OPENSSL_SALT_PREFIX {
            Ok(-1) // Means data is base_64 decoded already, so we won't have to decode later.
        } else {
            let possible_version_string = String::from_utf8_lossy(possible_version_mark);
            possible_version_string
                .parse::<i32>()
                .context(CannotParseFilenMetadataVersion {
                    erroneous_part: possible_version_string.to_string(),
                })
        }
    }

    if data.is_empty() {
        return Ok(vec![0u8; 0]);
    }

    let metadata_version = read_metadata_version(data)?;
    match metadata_version {
        -1 => decrypt_aes_openssl(data, key), // Deprecated since August 2021
        1 => base64::decode(data)
            .context(CannotDecodeBase64 {})
            .and_then(|decoded| decrypt_aes_openssl(&decoded, key)), // Deprecated since August 2021
        2 => decrypt_aes_gcm_base64(&data[FILEN_VERSION_LENGTH..], key),
        version => UnsupportedFilenMetadataVersion {
            metadata_version: version,
        }
        .fail(),
    }
}

/// Encrypts given data to Filen metadata using given key.
/// Depending on metadata version, different encryption algos will be used.
/// Convenience overload of the [encrypt_metadata] for string params.
pub fn encrypt_metadata_str(data: &str, key: &str, metadata_version: u32) -> Result<String> {
    encrypt_metadata(data.as_bytes(), key.as_bytes(), metadata_version)
        .and_then(|bytes| String::from_utf8(bytes).context(EncryptedMetadataIsNotUtf8 {}))
}

/// Decrypts Filen metadata prefiously encrypted with [encrypt_metadata]/[encrypt_metadata_str].
/// Convenience overload of the [decrypt_metadata] for string params.
pub fn decrypt_metadata_str(data: &str, key: &str) -> Result<String> {
    decrypt_metadata(data.as_bytes(), key.as_bytes())
        .and_then(|bytes| String::from_utf8(bytes).context(DecryptedMetadataIsNotUtf8 {}))
}

/// Decrypts Filen metadata prefiously encrypted with [encrypt_metadata]/[encrypt_metadata_str] and one of the
/// given keys. Tries to decrypt using given keys until one of them succeeds.
pub fn decrypt_metadata_str_any_key(data: &str, keys: &[SecUtf8]) -> Result<String> {
    let keys = keys
        .iter()
        .map(|key| key.unsecure().as_bytes().to_vec())
        .collect::<Vec<Vec<u8>>>();
    decrypt_metadata_any_key(data.as_bytes(), &keys)
        .and_then(|bytes| String::from_utf8(bytes).context(DecryptedMetadataIsNotUtf8 {}))
}

/// Encrypts file chunk for uploading to Filen. Resulting encoded chunk bytes are treated as unicode scalars,
/// hence the resulting type. File key can be fetched from file metadata.
/// Note that [encrypt_file_chunk] and [decrypt_file_chunk] are not symmetric.
/// You are supposed to encrypt your bytes with [encrypt_file_chunk] and send them to Filen,
/// instead of passing them to [decrypt_file_chunk] for some reason.
pub fn encrypt_file_chunk(chunk_data: &[u8], file_key: &[u8; AES_CBC_KEY_LENGTH], version: u32) -> Result<String> {
    if chunk_data.is_empty() {
        Ok(String::new())
    } else {
        match version {
            1 => {
                let iv: &[u8; 16] = &file_key[..16].try_into().unwrap();
                Ok(utils::bytes_to_binary_string(&encrypt_aes_cbc_with_key_and_iv(
                    chunk_data, file_key, iv,
                )))
            }
            2 => Ok(encrypt_aes_gcm_bstr(chunk_data, file_key)),
            _ => UnsupportedFilenFileVersion { file_version: version }.fail(),
        }
    }
}

/// Decrypts file chunk downloaded from Filen. File key can be fetched from file metadata.
/// Note that [encrypt_file_chunk] and [decrypt_file_chunk] are not symmetric.
/// You are supposed to call [decrypt_file_chunk] on file chunks received from Filen, not on strings produced by
/// [encrypt_file_chunk].
pub fn decrypt_file_chunk(
    filen_encrypted_chunk_data: &[u8],
    file_key: &[u8; AES_CBC_KEY_LENGTH],
    version: u32,
) -> Result<Vec<u8>> {
    match version {
        1 => {
            if filen_encrypted_chunk_data.len() < OPENSSL_SALT_PREFIX.len() {
                BadArgument {
                    message: "encrypted data is too short, < 8 bytes",
                }
                .fail()
            } else {
                let possible_prefix = &filen_encrypted_chunk_data[0..OPENSSL_SALT_PREFIX.len()];
                if possible_prefix == OPENSSL_SALT_PREFIX {
                    decrypt_aes_openssl(base64::encode(filen_encrypted_chunk_data).as_bytes(), file_key)
                } else if possible_prefix == OPENSSL_SALT_PREFIX_BASE64 {
                    decrypt_aes_openssl(
                        utils::bytes_to_binary_string(filen_encrypted_chunk_data).as_bytes(),
                        file_key,
                    )
                } else {
                    let iv: &[u8; 16] = &file_key[..16].try_into().unwrap();
                    decrypt_aes_cbc_with_key_and_iv(filen_encrypted_chunk_data, file_key, iv)
                }
            }
        }
        2 => decrypt_aes_gcm(filen_encrypted_chunk_data, file_key),
        _ => UnsupportedFilenFileVersion { file_version: version }.fail(),
    }
}

/// Helper which encrypts master keys stored in a metadata into a list of key strings, using specified master key.
pub fn encrypt_master_keys_metadata(
    master_keys: &[SecUtf8],
    last_master_key: &SecUtf8,
    metadata_version: u32,
) -> Result<String> {
    let master_keys_unsecure = master_keys
        .iter()
        .map(|sec| sec.unsecure())
        .collect::<Vec<&str>>()
        .join("|");

    encrypt_metadata_str(&master_keys_unsecure, last_master_key.unsecure(), metadata_version)
}

/// Helper which decrypts master keys stored in a metadata into a list of key strings,
/// using one of the specified master keys.
pub fn decrypt_master_keys_metadata(master_keys_metadata: &str, master_keys: &[SecUtf8]) -> Result<Vec<SecUtf8>> {
    ensure!(
        !master_keys_metadata.is_empty(),
        BadArgument {
            message: "cannot decrypt master keys metadata, it is empty",
        }
    );

    decrypt_metadata_str_any_key(master_keys_metadata, master_keys)
        .map(|keys| keys.split('|').map(SecUtf8::from).collect())
}

/// Helper which decrypts user's RSA private key stored in a metadata into key bytes,
/// using one of the specified master keys.
pub fn decrypt_private_key_metadata(private_key_metadata: &str, master_keys: &[SecUtf8]) -> Result<SecVec<u8>> {
    fn decode_base64_to_secvec(string: &str) -> Result<SecVec<u8>> {
        base64::decode(string).context(CannotDecodeBase64 {}).map(SecVec::from)
    }

    ensure!(
        !private_key_metadata.is_empty(),
        BadArgument {
            message: "cannot decrypt private key metadata, it is empty",
        }
    );

    decrypt_metadata_str_any_key(private_key_metadata, master_keys).and_then(|str| decode_base64_to_secvec(&str))
}

/// Calculates RSA hash (using SHA512 with OAEP padding) from given data with the specified RSA public key.
pub fn encrypt_rsa(data: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let padding = rsa::PaddingScheme::new_oaep::<sha2::Sha512>();
    let key = rsa::RsaPublicKey::from_public_key_der(public_key).context(RsaCannotDeserializePublicKey {})?;
    key.encrypt(&mut rng, padding, data)
        .context(RsaPkcs8CannotEncryptData {})
}

/// Decrypts data prefiously encrypted with [encrypt_rsa] using PKCS#8 private key in ASN.1 DER-encoded format.
pub fn decrypt_rsa(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    let padding = rsa::PaddingScheme::new_oaep::<sha2::Sha512>();
    let private_key = rsa::RsaPrivateKey::from_pkcs8_der(private_key).context(RsaCannotDeserializePrivateKey {})?;
    private_key.decrypt(padding, data).context(RsaPkcs8CannotDecryptData {})
}

/// Calculates OpenSSL-compatible AES 256 CBC (Pkcs7 padding) hash with 'Salted__' prefix,
/// then 8 bytes of salt, rest is ciphered.
pub fn encrypt_aes_openssl(data: &[u8], key: &[u8], maybe_salt: Option<&[u8]>) -> Vec<u8> {
    let mut salt = [0u8; OPENSSL_SALT_LENGTH];
    match maybe_salt {
        Some(user_salt) if user_salt.len() == OPENSSL_SALT_LENGTH => salt.copy_from_slice(user_salt),
        _ => rand::thread_rng().fill(&mut salt),
    };

    let (key, iv) = generate_aes_key_and_iv(AES_CBC_KEY_LENGTH, AES_CBC_IV_LENGTH, 1, Some(&salt), key);
    let mut encrypted = encrypt_aes_cbc_with_key_and_iv(data, &key.try_into().unwrap(), &iv.try_into().unwrap());
    let mut result = OPENSSL_SALT_PREFIX.to_vec();
    result.extend_from_slice(&salt);
    result.append(&mut encrypted);
    result
}

/// Decrypts data prefiously encrypted with [encrypt_aes_openssl].
pub fn decrypt_aes_openssl(aes_encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let (salt, message) = salt_and_message_from_aes_openssl_encrypted_data(aes_encrypted_data, OPENSSL_SALT_LENGTH)?;
    let (key, iv) = generate_aes_key_and_iv(AES_CBC_KEY_LENGTH, AES_CBC_IV_LENGTH, 1, Some(salt), key);
    decrypt_aes_cbc_with_key_and_iv(message, &key.try_into().unwrap(), &iv.try_into().unwrap())
}

/// Calculates hash of the given data using AES256 with CBC mode and Pkcs7 padding,
/// based on the specified key and IV. Returns raw bytes from cipher.
fn encrypt_aes_cbc_with_key_and_iv(
    data: &[u8],
    key: &[u8; AES_CBC_KEY_LENGTH],
    iv: &[u8; AES_CBC_IV_LENGTH],
) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
    cipher.encrypt_vec(data)
}

/// Decrypts data prefiously encrypted with [encrypt_aes_cbc_with_key_and_iv].
fn decrypt_aes_cbc_with_key_and_iv(
    aes_encrypted_data: &[u8],
    key: &[u8; AES_CBC_KEY_LENGTH],
    iv: &[u8; AES_CBC_IV_LENGTH],
) -> Result<Vec<u8>> {
    let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
    cipher
        .decrypt_vec(aes_encrypted_data)
        .context(AesCbcCannotDecipherData {})
}

/// Calculates AES-GCM hash. Returns IV within [0, [AES_GCM_IV_LENGTH]) range,
/// and encrypted message in base64-encoded part starting at [AES_GCM_IV_LENGTH] string index.
pub fn encrypt_aes_gcm_base64(data: &[u8], key: &[u8]) -> Vec<u8> {
    let (iv, encrypted) = encrypt_aes_gcm(data, key);
    let combined = iv + &base64::encode(encrypted);
    combined.into_bytes()
}

/// Calculates AES-GCM hash. Returns IV within [0, [AES_GCM_IV_LENGTH]) range,
/// and encrypted message in unicode scalars starting at [AES_GCM_IV_LENGTH] string index.
/// Used only in [encrypt_file_chunk].
pub fn encrypt_aes_gcm_bstr(data: &[u8], key: &[u8]) -> String {
    let (iv, encrypted) = encrypt_aes_gcm(data, key);
    iv + &utils::bytes_to_binary_string(&encrypted)
}

/// Calculates AES-GCM hash. Returns IV in the first item,
/// and raw encrypted message in the second item.
pub fn encrypt_aes_gcm(data: &[u8], key: &[u8]) -> (String, Vec<u8>) {
    let key = derive_key_from_password_256(key, key, 1);
    let iv = utils::random_alphanumeric_string(AES_GCM_IV_LENGTH);
    let cipher = Aes256Gcm::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(iv.as_bytes());
    let encrypted = cipher.encrypt(nonce, data).unwrap(); // Will only panic when data.len() > 1 << 36
    (iv, encrypted)
}

/// Decrypts data prefiously encrypted with [encrypt_aes_gcm_base64].
pub fn decrypt_aes_gcm_base64(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let (iv, encrypted_base64) = extract_aes_gcm_iv_and_message(data)?;
    base64::decode(encrypted_base64)
        .context(CannotDecodeBase64 {})
        .and_then(|encrypted| decrypt_aes_gcm_from_iv_and_bytes(key, iv, &encrypted))
}

/// Decrypts data prefiously encrypted with [encrypt_aes_gcm].
pub fn decrypt_aes_gcm(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let (iv, encrypted) = extract_aes_gcm_iv_and_message(data)?;
    decrypt_aes_gcm_from_iv_and_bytes(key, iv, encrypted)
}

fn decrypt_aes_gcm_from_iv_and_bytes(key: &[u8], iv: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
    let key = derive_key_from_password_256(key, key, 1);
    let cipher = Aes256Gcm::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(iv);
    cipher.decrypt(nonce, encrypted).context(AesGcmCannotDecipherData {})
}

fn extract_aes_gcm_iv_and_message(data: &[u8]) -> Result<(&[u8], &[u8])> {
    ensure!(
        data.len() > AES_GCM_IV_LENGTH,
        BadArgument {
            message: "encrypted data is too small to contain AES GCM IV"
        }
    );

    let (iv, message) = data.split_at(AES_GCM_IV_LENGTH);
    Ok((iv, message))
}

fn salt_and_message_from_aes_openssl_encrypted_data(
    aes_encrypted_data: &[u8],
    salt_length: usize,
) -> Result<(&[u8], &[u8])> {
    let message_index = OPENSSL_SALT_PREFIX.len() + salt_length;
    ensure!(
        aes_encrypted_data.len() >= message_index,
        BadArgument {
            message: "encrypted data is too small to contain OpenSSL-compatible salt",
        }
    );

    let (salt_with_prefix, message) = aes_encrypted_data.split_at(message_index);
    ensure!(
        &salt_with_prefix[..8] == OPENSSL_SALT_PREFIX,
        BadArgument {
            message: "encrypted data does not contain OpenSSL salt prefix",
        }
    );

    let salt = &salt_with_prefix[OPENSSL_SALT_PREFIX.len()..];
    Ok((salt, message))
}

/// Calculates login key from the given user password and service-provided salt.
fn derive_key_from_password_generic<M>(password: &[u8], salt: &[u8], iterations: u32, pbkdf2_hash: &mut [u8])
where
    M: Mac + NewMac + Sync,
{
    let iterations_or_default = if iterations == 0 { 200_000 } else { iterations };
    pbkdf2::<M>(password, salt, iterations_or_default, pbkdf2_hash);
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
    let salt = maybe_salt.unwrap_or(&[0; 0]);
    evpkdf::<Md5>(password, salt, iterations, &mut output);
    let (key, iv) = output.split_at(key_length);
    (Vec::from(key), Vec::from(iv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use pretty_assertions::{assert_eq, assert_ne};
    use std::convert::TryInto;

    #[test]
    fn encrypt_metadata_v1_should_use_simple_aes_with_base64() {
        let m_key = hash_fn("test");
        let metadata = "{\"name\":\"perform.js\",\"size\":156,\"mime\":\"application/javascript\",\
        \"key\":\"tqNrczqVdTCgFzB1b1gyiQBIYmwDBwa9\",\"lastModified\":499162500}";

        let encrypted_metadata = encrypt_metadata(metadata.as_bytes(), m_key.as_bytes(), 1).unwrap();

        assert_eq!(encrypted_metadata.len(), 216);
        assert_eq!(&encrypted_metadata[..8], OPENSSL_SALT_PREFIX_BASE64);
    }

    #[test]
    fn decrypt_metadata_v1_should_use_simple_aes() {
        let m_key = hash_fn("test");
        let metadata_base64 = "U2FsdGVkX1//gOpv81xPNI3PuT1CryNCVXpcfmISGNR+1g2OPT8SBP2/My7G6o5lSvVtkn2smbYrAo1\
        Mgaq9RIJlCEjcYpMsr+A9RSpkX7zLyXtMPV6q+PRbQj1WkP8ymuh0lmmnFRa+oRy0EvJnw97m3aLTHN4DD5XmJ36tecA2cwSrFskYn9E8+0\
        y+Wj/LcXh1l5n4Q1l5j8TSjS5mIQ==";
        let expected_metadata = "{\"name\":\"perform.js\",\"size\":156,\"mime\":\"application/javascript\",\
        \"key\":\"tqNrczqVdTCgFzB1b1gyiQBIYmwDBwa9\",\"lastModified\":499162500}";

        let decrypted_metadata = decrypt_metadata(&metadata_base64.as_bytes(), m_key.as_bytes()).unwrap();

        assert_eq!(String::from_utf8_lossy(&decrypted_metadata), expected_metadata);
    }

    #[test]
    fn encrypt_metadata_v2_should_use_aes_gcm_with_version_mark() {
        let m_key = hash_fn("test");
        let metadata = "{\"name\":\"perform.js\",\"size\":156,\"mime\":\"application/javascript\",\
        \"key\":\"tqNrczqVdTCgFzB1b1gyiQBIYmwDBwa9\",\"lastModified\":499162500}";

        let encrypted_metadata = encrypt_metadata(metadata.as_bytes(), m_key.as_bytes(), 2).unwrap();

        assert_eq!(encrypted_metadata.len(), 211);
        assert_eq!(&encrypted_metadata[..3], b"002");
    }

    #[test]
    fn decrypt_metadata_v2_should_use_aes_gcm_with_version_mark() {
        let m_key = hash_fn("test");
        let encrypted_metadata = "002CWAZWUt8h5n0Il13bkeirz7uY05vmrO58ZXemzaIGnmy+iLe95hXtwiAWHF4s\
        9+g7gcj3LmwykWnZzUEZIAu8zIEyqe2J//iKaZOJMSIqGIg05GvVBl9INeqf2ACU7wRE9P7tCI5tKqgEWG/sMqRwPGwbNN\
        rn3yI8McEqCBdPWNfi6gl8OwzcqUVnMKZI/DPVSkUZQpaN83zCtA=";
        let expected_metadata = "{\"name\":\"perform.js\",\"size\":156,\"mime\":\"application/javascript\",\
        \"key\":\"tqNrczqVdTCgFzB1b1gyiQBIYmwDBwa9\",\"lastModified\":499162500}";

        let decrypted_metadata = decrypt_metadata(encrypted_metadata.as_bytes(), m_key.as_bytes()).unwrap();
        let decrypted_metadata_str = String::from_utf8_lossy(&decrypted_metadata);

        assert_eq!(decrypted_metadata_str, expected_metadata);
    }

    #[test]
    fn decrypt_metadata_v2_should_work_with_several_keys() {
        let m_key_1 = hash_fn("invalid key").into_bytes();
        let m_key_2 = hash_fn("test").into_bytes();
        let m_keys = [m_key_1, m_key_2];
        let encrypted_metadata = "002CWAZWUt8h5n0Il13bkeirz7uY05vmrO58ZXemzaIGnmy+iLe95hXtwiAWHF4s\
        9+g7gcj3LmwykWnZzUEZIAu8zIEyqe2J//iKaZOJMSIqGIg05GvVBl9INeqf2ACU7wRE9P7tCI5tKqgEWG/sMqRwPGwbNN\
        rn3yI8McEqCBdPWNfi6gl8OwzcqUVnMKZI/DPVSkUZQpaN83zCtA=";
        let expected_metadata = "{\"name\":\"perform.js\",\"size\":156,\"mime\":\"application/javascript\",\
        \"key\":\"tqNrczqVdTCgFzB1b1gyiQBIYmwDBwa9\",\"lastModified\":499162500}";

        let decrypted_metadata = decrypt_metadata_any_key(encrypted_metadata.as_bytes(), &m_keys).unwrap();
        let decrypted_metadata_str = String::from_utf8_lossy(&decrypted_metadata);

        assert_eq!(decrypted_metadata_str, expected_metadata);
    }

    #[test]
    fn decrypt_metadata_str_v2_should_work_with_several_keys() {
        let m_key_1 = SecUtf8::from(hash_fn("invalid key"));
        let m_key_2 = SecUtf8::from(hash_fn("test"));
        let m_keys = [m_key_1, m_key_2];
        let encrypted_metadata = "002CWAZWUt8h5n0Il13bkeirz7uY05vmrO58ZXemzaIGnmy+iLe95hXtwiAWHF4s\
        9+g7gcj3LmwykWnZzUEZIAu8zIEyqe2J//iKaZOJMSIqGIg05GvVBl9INeqf2ACU7wRE9P7tCI5tKqgEWG/sMqRwPGwbNN\
        rn3yI8McEqCBdPWNfi6gl8OwzcqUVnMKZI/DPVSkUZQpaN83zCtA=";
        let expected_metadata = "{\"name\":\"perform.js\",\"size\":156,\"mime\":\"application/javascript\",\
        \"key\":\"tqNrczqVdTCgFzB1b1gyiQBIYmwDBwa9\",\"lastModified\":499162500}";

        let decrypted_metadata = decrypt_metadata_str_any_key(encrypted_metadata, &m_keys).unwrap();

        assert_eq!(decrypted_metadata, expected_metadata);
    }

    #[test]
    fn encrypt_aes_gcm_should_should_work_and_have_same_algorithm() {
        let key = b"test";
        let expected_data = "This is Jimmy.";
        let encrypted_data = encrypt_aes_gcm_base64(expected_data.as_bytes(), key);

        assert_eq!(encrypted_data.len(), 52);
        assert_ne!(&encrypted_data[..3], b"002");

        let decrypted_data = decrypt_aes_gcm_base64(&encrypted_data, key).unwrap();
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
        let encrypted_data = encrypt_aes_openssl(expected_data, key, Some(&[0u8, 1, 2, 3, 4, 5, 6, 7]));

        let actual_data_result = decrypt_aes_openssl(&encrypted_data, key);
        let actual_data = actual_data_result.unwrap();

        assert_eq!(actual_data, expected_data);
    }

    #[test]
    fn encrypt_rsa_and_decrypt_rsa_should_work_and_have_same_algorithm() {
        let expected_data = "This is Jimmy.";
        let m_key = "ed8d39b6c2d00ece398199a3e83988f1c4942b24";
        let private_key_file_contents = read_project_file("tests/resources/filen_private_key.txt");
        let private_key_metadata_encrypted = String::from_utf8_lossy(&private_key_file_contents);
        let private_key_decrypted = decrypt_metadata_str(&private_key_metadata_encrypted, &m_key)
            .and_then(|str| Ok(SecVec::from(base64::decode(str).unwrap())))
            .unwrap();
        let public_key_file_contents = read_project_file("tests/resources/filen_public_key.txt");
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
    fn hash_password_should_return_valid_hash() {
        let password = "test_pwd".to_owned();
        let expected_hash = "21160f51da2cbbe04a195db31d7da72639d2eb99f9da3b05461123ab39b856cbb981fc9b97e64b36ab897\
        7c6190117b18fa6d3055ac0b3411ea086fdc71bae0d806ec431c8628905f437276c3f64349683680974a7e\
        00ef216b94dbbc711bd4645df3ab46de3ed787828b73fc5c8a5abd959cb0d64591042519ef1b14ad08db7";

        let actual_hash = hash_password(&password);

        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn decrypt_file_data_should_decrypt_raw_aes_cbc() {
        let file_key: &[u8; 32] = "sh1YRHfx22Ij40tQBbt6BgpBlqkzch8Y".as_bytes().try_into().unwrap();
        let file_encrypted_bytes = read_project_file("tests/resources/responses/download_file_aes_cbc_as_is.bin");

        let file_decrypted_bytes_result = decrypt_file_chunk(&file_encrypted_bytes, file_key, 1);
        assert!(file_decrypted_bytes_result.is_ok());
        let file_decrypted_bytes = file_decrypted_bytes_result.unwrap();
        let image_load_result = image::load_from_memory_with_format(&file_decrypted_bytes, image::ImageFormat::Png);
        assert!(image_load_result.is_ok())
    }
}
