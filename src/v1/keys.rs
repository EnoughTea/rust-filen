use crate::{crypto, errors::bad_argument, filen_settings::FilenSettings, queries};
use anyhow::*;
use secstr::{SecUtf8, SecVec};
use serde::{Deserialize, Serialize};
use serde_with::*;

use super::api_response_struct;

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
    pub private_key_metadata: Option<String>,
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

api_response_struct!(
    /// Response for [KEY_PAIR_PATH] endpoint.
    UserKeyPairInfoResponsePayload<Option<UserKeyPairInfoResponseData>>
);

/// Used for requests to [MASTER_KEYS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MasterKeysFetchRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// This string is a Filen metadata encrypted by the last master key and base64-encoded.
    /// It contains either a single master key string or multiple master keys strings delimited by '|'.
    #[serde(rename = "masterKeys")]
    pub master_keys_metadata: String,
}

impl MasterKeysFetchRequestPayload {
    /// Creates [MasterKeysFetchRequestPayload] from user's API key and user's master keys.
    /// Assumes last user's master key is the last element of master keys vec.
    fn new(api_key: SecUtf8, raw_master_keys: Vec<SecUtf8>) -> Result<MasterKeysFetchRequestPayload> {
        if raw_master_keys.is_empty() {
            bail!(bad_argument("Given raw master keys should not be empty"));
        }

        let master_keys_metadata = crypto::encrypt_master_keys_metadata(
            &raw_master_keys,
            raw_master_keys.last().unwrap(),
            super::METADATA_VERSION,
        )?;

        Ok(MasterKeysFetchRequestPayload {
            api_key,
            master_keys_metadata,
        })
    }
}

/// Response data for [MASTER_KEYS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MasterKeysFetchResponseData {
    /// Metadata containing current Filen master keys, split by '|'. Last user key will be at the end. Can be used to update current user master keys.
    #[serde(rename = "keys")]
    pub keys_metadata: Option<String>,
}

impl MasterKeysFetchResponseData {
    /// Decrypts [MasterKeysFetchResponseData].keys_metadata field into a list of key strings,
    /// using specified user's last master key.
    pub fn decrypt_keys(&self, last_master_key: &SecUtf8) -> Result<Vec<SecUtf8>> {
        crypto::decrypt_master_keys_metadata(&self.keys_metadata, last_master_key)
    }
}

api_response_struct!(
    /// Response for [KEY_PAIR_PATH] endpoint.
    MasterKeysFetchResponsePayload<Option<MasterKeysFetchResponseData>>
);

/// Calls [KEY_PAIR_INFO_PATH] endpoint. Used to get RSA public/private key pair.
pub fn key_pair_info_request(
    payload: &UserKeyPairInfoRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserKeyPairInfoResponsePayload> {
    queries::query_filen_api(KEY_PAIR_INFO_PATH, payload, filen_settings)
}

/// Calls [KEY_PAIR_INFO_PATH] endpoint asynchronously. Used to get RSA public/private key pair.
pub async fn key_pair_info_request_async(
    payload: &UserKeyPairInfoRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserKeyPairInfoResponsePayload> {
    queries::query_filen_api_async(KEY_PAIR_INFO_PATH, payload, filen_settings).await
}

/// Calls [MASTER_KEYS_PATH] endpoint. Used to get/update user's master keys.
/// My guess is via that method new user master keys, passed in request payload, get joined with current Filen-known user master keys,
/// and resulting master keys chain returned in response payload.
pub fn master_keys_fetch_request(
    payload: &MasterKeysFetchRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<MasterKeysFetchResponsePayload> {
    queries::query_filen_api(MASTER_KEYS_PATH, payload, filen_settings)
}

/// Calls [MASTER_KEYS_PATH] endpoint asynchronously. Used to get/update user's master keys.
/// My guess is via that method new user master keys, passed in request payload, get joined with current Filen-known user master keys,
/// and resulting master keys chain returned in response payload.
pub async fn master_keys_fetch_request_async(
    payload: &MasterKeysFetchRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<MasterKeysFetchResponsePayload> {
    queries::query_filen_api_async(MASTER_KEYS_PATH, payload, filen_settings).await
}

#[cfg(test)]
mod tests {
    use closure::closure;
    use tokio::task::spawn_blocking;

    use super::*;
    use crate::test_utils::*;

    #[test]
    fn decode_public_key_should_return_decoded_bytes() {
        let public_key_base64 = "MIICIjA";
        let expected_public_key_bytes = base64::decode(public_key_base64).unwrap();
        let user_key_pair = UserKeyPairInfoResponseData {
            public_key: Some(public_key_base64.to_owned()),
            private_key_metadata: None,
        };

        let decoded_public_key_bytes = user_key_pair.decode_public_key().unwrap();

        assert_eq!(decoded_public_key_bytes, expected_public_key_bytes);
    }

    #[test]
    fn decrypt_private_key_should_return_decrypted_and_decoded_key_bytes() {
        let private_key_file_contents = read_project_file("tests/resources/filen_private_key.txt");
        let private_key_metadata_encrypted = String::from_utf8_lossy(&private_key_file_contents).to_string();
        let m_key = "ed8d39b6c2d00ece398199a3e83988f1c4942b24";
        let expected = crypto::decrypt_metadata_str(&private_key_metadata_encrypted, &m_key)
            .and_then(|str| Ok(SecVec::from(base64::decode(str).unwrap())))
            .unwrap();
        let user_key_pair = UserKeyPairInfoResponseData {
            public_key: None,
            private_key_metadata: Some(private_key_metadata_encrypted),
        };

        let decrypted_private_key = user_key_pair.decrypt_private_key(&SecUtf8::from(m_key)).unwrap();

        assert_eq!(decrypted_private_key.unsecure(), expected.unsecure());
    }

    #[tokio::test]
    async fn master_keys_fetch_request_and_async_should_work() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = MasterKeysFetchRequestPayload {
            api_key: SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"),
            master_keys_metadata:
                "U2FsdGVkX1/P4QDMaiaanx8kpL7fY+v/f3dSzC9Ajl58gQg5bffqGUbOIzROwGQn8m5NAZa0tRnVya84aJnf1w==".to_owned(),
        };
        let expected_response: MasterKeysFetchResponsePayload =
            deserialize_from_file("tests/resources/responses/user_masterKeys.json");
        let mock = setup_json_mock(MASTER_KEYS_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { master_keys_fetch_request(&request_payload, &filen_settings) }),
        ).await??;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = master_keys_fetch_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }
}
