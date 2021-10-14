use crate::{crypto, settings::FilenSettings, utils};
use anyhow::*;
use secstr::{SecUtf8, SecVec};
use serde::{Deserialize, Serialize};
use serde_with::*;

use super::filen_api_response_struct;

const KEY_PAIR_INFO_PATH: &str = "/v1/user/keyPair/info";
const MASTER_KEYS_PATH: &str = "/v1/user/masterKeys";

/// Used for requests to [KEY_PAIR_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserKeyPairInfoRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,
}

/// Response data for [KEY_PAIR_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserKeyPairInfoResponseData {
    /// User's public key, base64-encoded. Currently used for encrypting name and metadata of the shared download folders.
    /// Empty when no keys were set (currently before the first login).
    #[serde(rename = "publicKey")]
    pub public_key: Option<String>,

    /// A user's RSA private key stored as Filen metadata encrypted by user's last master key, containing a base64-encoded key bytes.
    /// Private key is currently used for decrypting name and metadata of the shared download folders.
    /// Empty when no keys were set (currently before the first login).
    #[serde(rename = "privateKey")]
    pub private_key_metadata: Option<SecUtf8>,
}

impl UserKeyPairInfoResponseData {
    /// Conveniently decodes base64-encoded public key into bytes.
    pub fn decode_public_key(&self) -> Result<Vec<u8>> {
        match &self.public_key {
            Some(key) => base64::decode(key).with_context(|| "Public key was not a valid base64-encoded string"),
            _ => bail!("Cannot decode public key, it is empty"),
        }
    }

    /// Decrypts [LoginResponseData].private_key_metadata field with given user's last master key
    /// into RSA key bytes.
    pub fn decrypt_private_key(&self, last_master_key: &SecUtf8) -> Result<SecVec<u8>> {
        crypto::decrypt_private_key_metadata(&self.private_key_metadata, last_master_key)
    }
}

filen_api_response_struct!(
    /// Response for [KEY_PAIR_PATH] endpoint.
    UserKeyPairInfoResponsePayload<UserKeyPairInfoResponseData>
);

/// Used for requests to [MASTER_KEYS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MasterKeysUpdateRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// This string is a Filen metadata encrypted by the last master key and base64-encoded.
    /// It contains either a single master key string or multiple master keys strings delimited by '|'.
    #[serde(rename = "masterKeys")]
    pub master_keys_metadata: SecUtf8,
}

/// Response data for [MASTER_KEYS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MasterKeysUpdateResponseData {
    /// New master keys after update. Update current user master keys with this value.
    pub keys: Option<SecUtf8>,
}

filen_api_response_struct!(
    /// Response for [KEY_PAIR_PATH] endpoint.
    MasterKeysUpdateResponsePayload<MasterKeysUpdateResponseData>
);

/// Calls [KEY_PAIR_INFO_PATH] endpoint. Used to get RSA public/private key pair.
pub fn key_pair_info_request(
    payload: &UserKeyPairInfoRequestPayload,
    settings: &FilenSettings,
) -> Result<UserKeyPairInfoResponsePayload> {
    utils::query_filen_api(KEY_PAIR_INFO_PATH, payload, settings)
}

/// Calls [KEY_PAIR_INFO_PATH] endpoint asynchronously. Used to get RSA public/private key pair.
pub async fn key_pair_info_request_async(
    payload: &UserKeyPairInfoRequestPayload,
    settings: &FilenSettings,
) -> Result<UserKeyPairInfoResponsePayload> {
    utils::query_filen_api_async(KEY_PAIR_INFO_PATH, payload, settings).await
}

/// Calls [MASTER_KEYS_PATH] endpoint. Used to get RSA public/private key pair.
pub fn master_keys_update_request(
    payload: &MasterKeysUpdateRequestPayload,
    settings: &FilenSettings,
) -> Result<MasterKeysUpdateResponsePayload> {
    utils::query_filen_api(MASTER_KEYS_PATH, payload, settings)
}

/// Calls [MASTER_KEYS_PATH] endpoint asynchronously. Used to get RSA public/private key pair.
pub async fn master_keys_update_request_async(
    payload: &MasterKeysUpdateRequestPayload,
    settings: &FilenSettings,
) -> Result<MasterKeysUpdateResponsePayload> {
    utils::query_filen_api_async(MASTER_KEYS_PATH, payload, settings).await
}
