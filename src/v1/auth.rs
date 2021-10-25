use crate::{
    crypto::{self, FilenPasswordWithMasterKey},
    filen_settings::FilenSettings,
    queries, utils,
};
use secstr::{SecUtf8, SecVec};
use serde::{Deserialize, Serialize};
use serde_with::*;
use snafu::{Backtrace, ResultExt, Snafu};

use super::api_response_struct;

type Result<T, E = Error> = std::result::Result<T, E>;

const AUTH_INFO_PATH: &str = "/v1/auth/info";
const LOGIN_PATH: &str = "/v1/login";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("{} query failed: {}", AUTH_INFO_PATH, source))]
    AuthInfoQueryFailed { source: queries::Error },

    #[snafu(display("Failed to decrypt metadata for {}: {}", property_name, source))]
    DecryptMetadataPropertyFailed {
        property_name: String,
        source: crypto::Error,
    },

    #[snafu(display("{} query failed (version {}): {}", LOGIN_PATH, auth_version, source))]
    LoginQueryFailed { auth_version: u32, source: queries::Error },

    #[snafu(display("Unsupported Filen auth version {}", version))]
    UnsupportedAuthVersion { version: i64, backtrace: Backtrace },
}

/// Used for requests to [AUTH_INFO_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthInfoRequestPayload {
    /// Registered user email.
    pub email: SecUtf8,

    /// Registered user 2FA key, if present. XXXXXX means no 2FA key.
    #[serde(rename = "twoFactorKey")]
    pub two_factor_key: SecUtf8,
}
utils::display_from_json!(AuthInfoRequestPayload);

/// Response data for [AUTH_INFO_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthInfoResponseData {
    /// Registered user email.
    pub email: SecUtf8,

    /// User-associated value which determines auth algorithm. Currently values of 1 & 2 can be encountered.
    /// 1 means [FilenPasswordWithMasterKey::from_user_password] should be used to generate Filen password for login;
    /// 2 means [FilenPasswordWithMasterKey::from_user_password_and_auth_info_salt] should be used instead.
    #[serde(rename = "authVersion")]
    pub auth_version: u32,

    /// 256 alphanumeric characters or empty.
    pub salt: Option<String>,
}
utils::display_from_json!(AuthInfoResponseData);

impl AuthInfoResponseData {
    /// Produces a Filen master key and a password hash used for a login API call.
    pub fn filen_password_with_master_key(&self, user_password: &SecUtf8) -> Result<FilenPasswordWithMasterKey> {
        match self.auth_version {
            1 => Ok(FilenPasswordWithMasterKey::from_user_password(user_password)),
            2 => {
                let filen_salt = SecUtf8::from(self.salt.clone().unwrap_or_else(String::new));
                Ok(FilenPasswordWithMasterKey::from_user_password_and_auth_info_salt(
                    user_password,
                    &filen_salt,
                ))
            }
            _ => UnsupportedAuthVersion {
                version: self.auth_version,
            }
            .fail(),
        }
    }
}

api_response_struct!(
    /// Response for [AUTH_INFO_PATH] endpoint.
    AuthInfoResponsePayload<Option<AuthInfoResponseData>>
);

/// Used for requests to [LOGIN_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LoginRequestPayload {
    /// Registered user email.
    pub email: SecUtf8,

    /// Filen-processed password. Note that this is not a registered user password, but its hash.
    /// Use one of [FilenPasswordWithMasterKey]::from... methods to calculate it.
    pub password: SecUtf8,

    /// Registered user 2FA key, if present. XXXXXX means no 2FA key.
    #[serde(rename = "twoFactorKey")]
    pub two_factor_key: SecUtf8,

    /// Set this to a value you received from auth/info call and used to generate Filen password.
    #[serde(rename = "authVersion")]
    pub auth_version: u32,
}
utils::display_from_json!(LoginRequestPayload);

/// Response data for [LOGIN_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LoginResponseData {
    /// Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// This string is a Filen metadata encrypted by the last master key and base64-encoded.
    /// It contains either a single master key string or multiple master keys strings delimited by '|'.
    /// Master key is in turn used to decrypt various metadata.
    /// Empty when no keys were set (currently before the first login).
    #[serde(rename = "masterKeys")]
    pub master_keys_metadata: Option<String>,

    /// A user's RSA private key stored as Filen metadata encrypted by user's last master key, containing a base64-encoded key bytes.
    /// Private key is currently used for decrypting name and metadata of the shared download folders.
    /// Empty when no keys were set (currently before the first login).
    #[serde(rename = "privateKey")]
    pub private_key_metadata: Option<String>,
}
utils::display_from_json!(LoginResponseData);

impl LoginResponseData {
    /// Decrypts [LoginResponseData].master_keys_metadata field into a list of key strings,
    /// using specified user's last master key.
    pub fn decrypt_master_keys(&self, last_master_key: &SecUtf8) -> Result<Vec<SecUtf8>> {
        crypto::decrypt_master_keys_metadata(&self.master_keys_metadata.as_deref(), last_master_key).context(
            DecryptMetadataPropertyFailed {
                property_name: "masterKeys",
            },
        )
    }

    /// Decrypts [LoginResponseData].private_key_metadata field into RSA key bytes,
    /// using specified user's last master key.
    pub fn decrypt_private_key(&self, last_master_key: &SecUtf8) -> Result<SecVec<u8>> {
        crypto::decrypt_private_key_metadata(&self.private_key_metadata.as_deref(), last_master_key).context(
            DecryptMetadataPropertyFailed {
                property_name: "privateKey",
            },
        )
    }
}

api_response_struct!(
    /// Response for [LOGIN_PATH] endpoint.
    LoginResponsePayload<Option<LoginResponseData>>
);

/// Calls [AUTH_INFO_PATH] endpoint. Used to get used auth version and Filen salt.
pub fn auth_info_request(
    payload: &AuthInfoRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<AuthInfoResponsePayload> {
    queries::query_filen_api(AUTH_INFO_PATH, payload, filen_settings).context(AuthInfoQueryFailed {})
}

/// Calls [AUTH_INFO_PATH] endpoint asynchronously. Used to get used auth version and Filen salt.
pub async fn auth_info_request_async(
    payload: &AuthInfoRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<AuthInfoResponsePayload> {
    queries::query_filen_api_async(AUTH_INFO_PATH, payload, filen_settings)
        .await
        .context(AuthInfoQueryFailed {})
}

/// Calls [LOGIN_PATH] endpoint. Used to get API key, master keys and private key.
pub fn login_request(payload: &LoginRequestPayload, filen_settings: &FilenSettings) -> Result<LoginResponsePayload> {
    queries::query_filen_api(LOGIN_PATH, payload, filen_settings).context(LoginQueryFailed {
        auth_version: payload.auth_version,
    })
}

/// Calls [LOGIN_PATH] endpoint asynchronously. Used to get API key, master keys and private key.
pub async fn login_request_async(
    payload: &LoginRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LoginResponsePayload> {
    queries::query_filen_api_async(LOGIN_PATH, payload, filen_settings)
        .await
        .context(LoginQueryFailed {
            auth_version: payload.auth_version,
        })
}

#[cfg(test)]
mod tests {
    use crate::{
        test_utils::{self, *},
        v1::auth::*,
    };
    use closure::closure;
    use pretty_assertions::assert_eq;
    use tokio::task::spawn_blocking;

    #[test]
    fn login_response_data_should_decrypt_master_keys() {
        let m_key = SecUtf8::from("ed8d39b6c2d00ece398199a3e83988f1c4942b24");
        let master_keys_metadata_encrypted =
            "U2FsdGVkX1/P4QDMaiaanx8kpL7fY+v/f3dSzC9Ajl58gQg5bffqGUbOIzROwGQn8m5NAZa0tRnVya84aJnf1w==".to_owned();
        let response_data = LoginResponseData {
            api_key: SecUtf8::from(""),
            master_keys_metadata: Some(master_keys_metadata_encrypted),
            private_key_metadata: Some("".to_owned()),
        };

        let decrypted_m_keys = response_data.decrypt_master_keys(&m_key).unwrap();

        assert_eq!(decrypted_m_keys.len(), 1);
        assert_eq!(decrypted_m_keys[0], m_key);
    }

    #[test]
    fn login_response_data_should_decrypt_private_key() {
        let m_key = SecUtf8::from("ed8d39b6c2d00ece398199a3e83988f1c4942b24");
        let expected_rsa_key_length = 2374;
        let private_key_file_contents = test_utils::read_project_file("tests/resources/filen_private_key.txt");
        let private_key_metadata_encrypted = String::from_utf8_lossy(&private_key_file_contents).to_string();
        let response_data = LoginResponseData {
            api_key: SecUtf8::from(""),
            master_keys_metadata: Some("".to_owned()),
            private_key_metadata: Some(private_key_metadata_encrypted),
        };

        let decrypted_private_key = response_data.decrypt_private_key(&m_key).unwrap();

        assert_eq!(decrypted_private_key.unsecure().len(), expected_rsa_key_length);
    }

    #[tokio::test]
    async fn auth_info_request_and_async_should_work_with_v1() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = AuthInfoRequestPayload {
            email: SecUtf8::from("test@email.com"),
            two_factor_key: SecUtf8::from("XXXXXX"),
        };
        let expected_response: AuthInfoResponsePayload =
            deserialize_from_file("tests/resources/responses/auth_info_v1.json");
        let mock = setup_json_mock(AUTH_INFO_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { auth_info_request(&request_payload, &filen_settings) }),
        ).await.unwrap()?;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = auth_info_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }

    #[tokio::test]
    async fn auth_info_request_and_async_should_work_with_v2() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = AuthInfoRequestPayload {
            email: SecUtf8::from("test@email.com"),
            two_factor_key: SecUtf8::from("XXXXXX"),
        };
        let expected_response: AuthInfoResponsePayload =
            deserialize_from_file("tests/resources/responses/auth_info_v2.json");
        let mock = setup_json_mock(AUTH_INFO_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || auth_info_request(&request_payload, &filen_settings)),
        )
        .await.unwrap()?;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = auth_info_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }

    #[tokio::test]
    async fn login_request_and_async_should_work_with_v1() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = LoginRequestPayload {
            email: SecUtf8::from("test@email.com"),
            password: SecUtf8::from("test"),
            two_factor_key: SecUtf8::from("XXXXXX"),
            auth_version: 1,
        };
        let expected_response: LoginResponsePayload = deserialize_from_file("tests/resources/responses/login_v1.json");
        let mock = setup_json_mock(LOGIN_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || login_request(&request_payload, &filen_settings)),
        )
        .await
        .unwrap()?;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = login_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }
}
