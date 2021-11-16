use crate::{
    crypto,
    filen_settings::FilenSettings,
    queries, utils,
    v1::{response_payload, PlainResponsePayload, METADATA_VERSION},
};
use secstr::{SecUtf8, SecVec};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use snafu::{ensure, Backtrace, ResultExt, Snafu};

type Result<T, E = Error> = std::result::Result<T, E>;

const USER_KEY_PAIR_INFO_PATH: &str = "/v1/user/keyPair/info";
const USER_KEY_PAIR_UPDATE_PATH: &str = "/v1/user/keyPair/update";
const USER_MASTER_KEYS_PATH: &str = "/v1/user/masterKeys";
const USER_PUBLIC_KEY_GET_PATH: &str = "/v1/user/publicKey/get";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Caller provided invalid argument: {}", message))]
    BadArgument { message: String, backtrace: Backtrace },

    #[snafu(display("Public key was not a valid base64-encoded string"))]
    DecodePublicKeyFailed { source: base64::DecodeError },

    #[snafu(display("Failed to decrypt master keys: {}", source))]
    DecryptMasterKeysFailed { source: crypto::Error },

    #[snafu(display("Failed to decrypt private key: {}", source))]
    DecryptPrivateKeyFailed { source: crypto::Error },

    #[snafu(display("Failed to encrypt master keys: {}", source))]
    EncryptMasterKeysFailed { source: crypto::Error },

    #[snafu(display("Failed to encrypt private key: {}", source))]
    EncryptPrivateKeyFailed { source: crypto::Error },

    #[snafu(display("{} query failed: {}", USER_KEY_PAIR_INFO_PATH, source))]
    UserKeyPairInfoQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_KEY_PAIR_UPDATE_PATH, source))]
    UserKeyPairUpdateQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_MASTER_KEYS_PATH, source))]
    UserMasterKeysQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_PUBLIC_KEY_GET_PATH, source))]
    UserPublicKeyGetQueryFailed { source: queries::Error },
}

/// Implemented to add decryption of a master keys metadata.
pub trait HasMasterKeys {
    /// Gets a reference to master keys metadata, if present.
    fn master_keys_metadata_ref(&self) -> Option<&str>;

    /// Decrypts `master_keys_metadata_ref` into a list of key strings, using the specified user's last master key.
    fn decrypt_master_keys_metadata(&self, last_master_key: &SecUtf8) -> Result<Vec<SecUtf8>> {
        match self.master_keys_metadata_ref() {
            Some(metadata) => {
                crypto::decrypt_master_keys_metadata(metadata, last_master_key).context(DecryptMasterKeysFailed {})
            }
            None => BadArgument {
                message: "master keys metadata is absent, cannot decrypt None",
            }
            .fail(),
        }
    }
}

/// Implemented to add decryption of a private key metadata.
pub trait HasPrivateKey {
    /// Gets a reference to private key metadata, if present.
    fn private_key_metadata_ref(&self) -> Option<&str>;

    /// Decrypts `private_key_metadata_ref` into RSA key bytes, using the specified user's last master key.
    fn decrypt_private_key(&self, master_keys: &[SecUtf8]) -> Result<SecVec<u8>> {
        match self.private_key_metadata_ref() {
            Some(metadata) => {
                crypto::decrypt_private_key_metadata(metadata, master_keys).context(DecryptPrivateKeyFailed {})
            }
            None => BadArgument {
                message: "private key metadata is absent, cannot decrypt None",
            }
            .fail(),
        }
    }
}

/// Implemented to add conversion of a public key into bytes.
pub trait HasPublicKey {
    /// Gets a reference to private key metadata, if present.
    fn public_key_ref(&self) -> Option<&str>;

    /// Conveniently decodes base64-encoded public key into bytes.
    fn decode_public_key(&self) -> Result<Vec<u8>> {
        match self.public_key_ref() {
            Some(key) => base64::decode(key).context(DecodePublicKeyFailed {}),
            None => BadArgument {
                message: "public key is absent, cannot decode None",
            }
            .fail(),
        }
    }
}

/// Response data for `USER_KEY_PAIR_INFO_PATH` endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserKeyPairInfoResponseData {
    /// User's public key bytes in PKCS#8 ASN.1 DER format, base64-encoded. Currently used for encrypting name and
    /// metadata of the shared download folders.
    ///
    /// Empty when no keys were set (currently before the first login).
    #[serde(rename = "publicKey")]
    pub public_key: Option<String>,

    /// User's RSA private key bytes in PKCS#8 ASN.1 DER format,
    /// base64-encoded and stored as Filen metadata encrypted by user's last master key.
    /// Private key is currently used for decrypting name and metadata of the shared download folders.
    ///
    /// Empty when no keys were set (currently before the first login).
    #[serde(rename = "privateKey")]
    pub private_key_metadata: Option<String>,
}
utils::display_from_json!(UserKeyPairInfoResponseData);

impl HasPrivateKey for UserKeyPairInfoResponseData {
    fn private_key_metadata_ref(&self) -> Option<&str> {
        self.private_key_metadata.as_deref()
    }
}

impl HasPublicKey for UserKeyPairInfoResponseData {
    fn public_key_ref(&self) -> Option<&str> {
        self.public_key.as_deref()
    }
}

response_payload!(
    /// Response for `USER_KEY_PAIR_INFO_PATH` endpoint.
    UserKeyPairInfoResponsePayload<UserKeyPairInfoResponseData>
);

/// Used for requests to `USER_KEY_PAIR_UPDATE_PATH` endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserKeyPairUpdateRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// User's RSA private key bytes in PKCS#8 ASN.1 DER format,
    /// base64-encoded and stored as Filen metadata encrypted by user's last master key.
    #[serde(rename = "privateKey")]
    pub private_key: SecUtf8,

    /// User's public key bytes in PKCS#8 ASN.1 DER format, base64-encoded. Currently used for encrypting name and
    /// metadata of the shared download folders.
    #[serde(rename = "publicKey")]
    pub public_key: String,
}
utils::display_from_json!(UserKeyPairUpdateRequestPayload);

impl UserKeyPairUpdateRequestPayload {
    /// Creates `UserKeyPairUpdateRequestPayload` with Filen-compatible private and public key strings,
    /// given original keys bytes in PKCS#8 ASN.1 DER format.
    pub fn new(
        api_key: SecUtf8,
        private_key_bytes: &SecVec<u8>,
        public_key_bytes: &[u8],
        last_master_key: &SecUtf8,
    ) -> Result<Self> {
        let private_key = crypto::encrypt_metadata_str(
            &base64::encode(private_key_bytes.unsecure()),
            last_master_key,
            METADATA_VERSION,
        )
        .map(SecUtf8::from)
        .context(EncryptPrivateKeyFailed {})?;

        let public_key = base64::encode(public_key_bytes);
        Ok(Self {
            api_key,
            private_key,
            public_key,
        })
    }
}

/// Used for requests to `USER_MASTER_KEYS_PATH` endpoint.
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
utils::display_from_json!(MasterKeysFetchRequestPayload);

impl MasterKeysFetchRequestPayload {
    /// Creates `MasterKeysFetchRequestPayload` from user's API key and user's master keys.
    /// Assumes user's last master key is the last element of given master keys slice.
    pub fn new(api_key: SecUtf8, raw_master_keys: &[SecUtf8]) -> Result<Self> {
        let empty_key = SecUtf8::from("");
        let last_master_key = raw_master_keys.last().unwrap_or(&empty_key);

        ensure!(
            !last_master_key.unsecure().is_empty(),
            BadArgument {
                message: "given raw master keys should not be empty or last master key should not be empty"
            }
        );

        let master_keys_metadata =
            crypto::encrypt_master_keys_metadata(raw_master_keys, last_master_key, super::METADATA_VERSION)
                .context(EncryptMasterKeysFailed {})?;

        Ok(Self {
            api_key,
            master_keys_metadata,
        })
    }
}

/// Response data for `USER_MASTER_KEYS_PATH` endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct MasterKeysFetchResponseData {
    /// Metadata containing current Filen master keys, split by '|'. Last user key will be at the end.
    /// Can be used to update current user master keys.
    #[serde(rename = "keys")]
    pub keys_metadata: Option<String>,
}
utils::display_from_json!(MasterKeysFetchResponseData);

impl HasMasterKeys for MasterKeysFetchResponseData {
    fn master_keys_metadata_ref(&self) -> Option<&str> {
        self.keys_metadata.as_deref()
    }
}

response_payload!(
    /// Response for `USER_MASTER_KEYS_PATH` endpoint.
    MasterKeysFetchResponsePayload<MasterKeysFetchResponseData>
);

/// Used for requests to `USER_PUBLIC_KEY_GET_PATH` endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserPublicKeyGetRequestPayload {
    /// Email of the user whose public key Filen should fetch.
    pub email: String,
}
utils::display_from_json!(UserPublicKeyGetRequestPayload);

/// Response data for `USER_PUBLIC_KEY_GET_PATH` endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserPublicKeyGetResponseData {
    /// User's public key bytes in PKCS#8 ASN.1 DER format, base64-encoded. Currently used for encrypting name and
    /// metadata of the shared download folders.
    ///
    /// Empty when no keys were set (currently before the first login).
    #[serde(rename = "publicKey")]
    pub public_key: Option<String>,
}
utils::display_from_json!(UserPublicKeyGetResponseData);

impl HasPublicKey for UserPublicKeyGetResponseData {
    fn public_key_ref(&self) -> Option<&str> {
        self.public_key.as_deref()
    }
}

response_payload!(
    /// Response for `USER_PUBLIC_KEY_GET_PATH` endpoint.
    UserPublicKeyGetResponsePayload<UserPublicKeyGetResponseData>
);

/// Calls `USER_KEY_PAIR_INFO_PATH` endpoint. Used to get RSA public/private key pair.
pub fn user_key_pair_info_request(
    api_key: &SecUtf8,
    filen_settings: &FilenSettings,
) -> Result<UserKeyPairInfoResponsePayload> {
    queries::query_filen_api(USER_KEY_PAIR_INFO_PATH, &utils::api_key_json(api_key), filen_settings)
        .context(UserKeyPairInfoQueryFailed {})
}

/// Calls `USER_KEY_PAIR_INFO_PATH` endpoint asynchronously. Used to get RSA public/private key pair.
#[cfg(feature = "async")]
pub async fn user_key_pair_info_request_async(
    api_key: &SecUtf8,
    filen_settings: &FilenSettings,
) -> Result<UserKeyPairInfoResponsePayload> {
    queries::query_filen_api_async(USER_KEY_PAIR_INFO_PATH, &utils::api_key_json(api_key), filen_settings)
        .await
        .context(UserKeyPairInfoQueryFailed {})
}

/// Calls `USER_KEY_PAIR_UPDATE_PATH` endpoint. Used to set user's RSA public/private key pair.
pub fn user_key_pair_update_request(
    payload: &UserKeyPairUpdateRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(USER_KEY_PAIR_UPDATE_PATH, payload, filen_settings)
        .context(UserKeyPairUpdateQueryFailed {})
}

/// Calls `USER_KEY_PAIR_UPDATE_PATH` endpoint asynchronously. Used to set user's RSA public/private key pair.
#[cfg(feature = "async")]
pub async fn user_key_pair_update_request_async(
    payload: &UserKeyPairUpdateRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(USER_KEY_PAIR_UPDATE_PATH, payload, filen_settings)
        .await
        .context(UserKeyPairUpdateQueryFailed {})
}

/// Calls `USER_MASTER_KEYS_PATH` endpoint. Used to get/update user's master keys.
/// With that method new user master keys, passed in request payload, get joined with current
/// Filen-known user master keys, and resulting master keys chain is returned in response payload.
pub fn user_master_keys_request(
    payload: &MasterKeysFetchRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<MasterKeysFetchResponsePayload> {
    queries::query_filen_api(USER_MASTER_KEYS_PATH, payload, filen_settings).context(UserMasterKeysQueryFailed {})
}

/// Calls `USER_MASTER_KEYS_PATH` endpoint asynchronously. Used to get/update user's master keys.
/// With that method new user master keys, passed in request payload, get joined with current
/// Filen-known user master keys, and resulting master keys chain is returned in response payload.
#[cfg(feature = "async")]
pub async fn user_master_keys_request_async(
    payload: &MasterKeysFetchRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<MasterKeysFetchResponsePayload> {
    queries::query_filen_api_async(USER_MASTER_KEYS_PATH, payload, filen_settings)
        .await
        .context(UserMasterKeysQueryFailed {})
}

/// Calls `USER_PUBLIC_KEY_GET_PATH` endpoint. Used to get any user's RSA public key.
pub fn user_public_key_get_request(
    payload: &UserPublicKeyGetRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserPublicKeyGetResponsePayload> {
    queries::query_filen_api(USER_PUBLIC_KEY_GET_PATH, payload, filen_settings).context(UserPublicKeyGetQueryFailed {})
}

/// Calls `USER_PUBLIC_KEY_GET_PATH` endpoint asynchronously. Used to get any user's RSA public key.
#[cfg(feature = "async")]
pub async fn user_public_key_get_request_async(
    payload: &UserPublicKeyGetRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserPublicKeyGetResponsePayload> {
    queries::query_filen_api_async(USER_PUBLIC_KEY_GET_PATH, payload, filen_settings)
        .await
        .context(UserPublicKeyGetQueryFailed {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{read_project_file, validate_contract, validate_contract_async};
    use once_cell::sync::Lazy;
    use pretty_assertions::assert_eq;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"));

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
        let m_key = SecUtf8::from("ed8d39b6c2d00ece398199a3e83988f1c4942b24");
        let expected = crypto::decrypt_metadata_str(&private_key_metadata_encrypted, &m_key)
            .map(|str| SecVec::from(base64::decode(str).unwrap()))
            .unwrap();
        let user_key_pair = UserKeyPairInfoResponseData {
            public_key: None,
            private_key_metadata: Some(private_key_metadata_encrypted),
        };

        let decrypted_private_key = user_key_pair.decrypt_private_key(&[m_key]).unwrap();

        assert_eq!(decrypted_private_key.unsecure(), expected.unsecure());
    }

    #[test]
    fn user_key_pair_info_request_should_be_correctly_typed() {
        let request_payload = utils::api_key_json(&API_KEY);
        validate_contract(
            USER_KEY_PAIR_INFO_PATH,
            request_payload,
            "tests/resources/responses/user_keyPair_info.json",
            |_, filen_settings| user_key_pair_info_request(&API_KEY, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn user_key_pair_info_request_async_should_be_correctly_typed() {
        let request_payload = utils::api_key_json(&API_KEY);
        validate_contract_async(
            USER_KEY_PAIR_INFO_PATH,
            request_payload,
            "tests/resources/responses/user_keyPair_info.json",
            |_, filen_settings| async move { user_key_pair_info_request_async(&API_KEY, &filen_settings).await },
        )
        .await;
    }

    #[test]
    fn master_keys_request_should_be_correctly_typed() {
        let request_payload = MasterKeysFetchRequestPayload {
            api_key: SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"),
            master_keys_metadata:
                "U2FsdGVkX1/P4QDMaiaanx8kpL7fY+v/f3dSzC9Ajl58gQg5bffqGUbOIzROwGQn8m5NAZa0tRnVya84aJnf1w==".to_owned(),
        };
        validate_contract(
            USER_MASTER_KEYS_PATH,
            request_payload,
            "tests/resources/responses/user_masterKeys.json",
            |request_payload, filen_settings| user_master_keys_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn master_keys_request_async_should_be_correctly_typed() {
        let request_payload = MasterKeysFetchRequestPayload {
            api_key: SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"),
            master_keys_metadata:
                "U2FsdGVkX1/P4QDMaiaanx8kpL7fY+v/f3dSzC9Ajl58gQg5bffqGUbOIzROwGQn8m5NAZa0tRnVya84aJnf1w==".to_owned(),
        };
        validate_contract_async(
            USER_MASTER_KEYS_PATH,
            request_payload,
            "tests/resources/responses/user_masterKeys.json",
            |request_payload, filen_settings| async move {
                user_master_keys_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn user_public_key_get_request_should_be_correctly_typed() {
        let request_payload = UserPublicKeyGetRequestPayload {
            email: "test@test.com".to_owned(),
        };
        validate_contract(
            USER_PUBLIC_KEY_GET_PATH,
            request_payload,
            "tests/resources/responses/user_public_key_get.json",
            |request_payload, filen_settings| user_public_key_get_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn user_public_key_get_request_async_should_be_correctly_typed() {
        let request_payload = UserPublicKeyGetRequestPayload {
            email: "test@test.com".to_owned(),
        };
        validate_contract_async(
            USER_PUBLIC_KEY_GET_PATH,
            request_payload,
            "tests/resources/responses/user_public_key_get.json",
            |request_payload, filen_settings| async move {
                user_public_key_get_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }
}
