use crate::{settings::FilenSettings, utils};
use anyhow::*;
use serde::{Deserialize, Serialize};
use serde_with::*;

const AUTH_INFO_PATH: &str = "/auth/info";

/// Used for requests to /v1/auth/info endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthInfoRequestPayload {
    pub email: String,

    /// XXXXXX means no key
    #[serde(rename = "twoFactorKey")]
    pub two_factor_key: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthInfoResponseData {
    pub email: String,

    /// Currently values of 1 & 2 can be encountered.
    #[serde(rename = "authVersion")]
    pub auth_version: u32,

    /// 256 alphanumeric characters or empty.
    pub salt: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthInfoResponsePayload {
    pub status: bool,
    pub message: String,
    pub data: Option<AuthInfoResponseData>,
}

pub fn auth_info_request(
    payload: &AuthInfoRequestPayload,
    settings: &FilenSettings,
) -> Result<AuthInfoResponsePayload> {
    utils::query_filen_api(AUTH_INFO_PATH, payload, settings)
}

pub async fn auth_info_request_async(
    payload: &AuthInfoRequestPayload,
    settings: &FilenSettings,
) -> Result<AuthInfoResponsePayload> {
    utils::query_filen_api_async(AUTH_INFO_PATH, payload, settings).await
}

#[cfg(test)]
mod tests {
    use crate::{auth::*, test_utils::*};
    use anyhow::Result;
    use closure::closure;
    use pretty_assertions::assert_eq;
    use tokio::task::spawn_blocking;

    #[tokio::test]
    async fn auth_info_request_and_async_should_work_with_v1() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = AuthInfoRequestPayload {
            email: "test@email.com".to_owned(),
            two_factor_key: None,
        };
        let expected_response: AuthInfoResponsePayload =
            deserialize_from_file("tests/resources/auth_info_v1_response.json");
        setup_json_mock(AUTH_INFO_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { auth_info_request(&request_payload, &filen_settings) }),
        )
        .await??;
        let async_response = auth_info_request_async(&request_payload, &filen_settings).await?;

        assert_eq!(response, expected_response);
        assert_eq!(async_response, expected_response);
        Ok(())
    }

    #[tokio::test]
    async fn auth_info_request_and_async_should_work_with_v2() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = AuthInfoRequestPayload {
            email: "test@email.com".to_owned(),
            two_factor_key: None,
        };
        let expected_response: AuthInfoResponsePayload =
            deserialize_from_file("tests/resources/auth_info_v2_response.json");
        setup_json_mock(AUTH_INFO_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { auth_info_request(&request_payload, &filen_settings) }),
        )
        .await??;
        let async_response = auth_info_request_async(&request_payload, &filen_settings).await?;

        assert_eq!(response, expected_response);
        assert_eq!(async_response, expected_response);
        Ok(())
    }
}
