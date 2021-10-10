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

    /// Can be null.
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
    use crate::{auth::*, test_utils};
    use anyhow::Result;
    use closure::closure;
    use httpmock::prelude::*;
    use pretty_assertions::assert_eq;
    use reqwest::Url;
    use serde_json::json;
    use tokio::task::spawn_blocking;

    #[tokio::test]
    async fn auth_info_request_and_async_should_() -> Result<()> {
        let (server, filen_settings) = init();
        let payload = AuthInfoRequestPayload {
            email: "test@email.com".to_owned(),
            two_factor_key: None,
        };
        let response_contents = test_utils::read_project_file("tests/resources/auth_info_v1_response.json");
        server.mock(|when, then| {
            when.method(POST)
                .path(AUTH_INFO_PATH)
                .header("content-type", "application/json")
                .json_body(json!(payload));
            then.status(200)
                .header("content-type", "text/html")
                .body(&response_contents);
        });
        let expected_auth_info_response: AuthInfoResponsePayload = serde_json::from_slice(&response_contents).unwrap();

        let response = spawn_blocking(
            closure!(clone payload, clone filen_settings, || { auth_info_request(&payload, &filen_settings) }),
        )
        .await??;
        let async_response = auth_info_request_async(&payload, &filen_settings).await?;

        assert_eq!(response, expected_auth_info_response);
        assert_eq!(async_response, expected_auth_info_response);
        Ok(())
    }

    fn init() -> (MockServer, FilenSettings) {
        let server = MockServer::start();
        let filen_settings = FilenSettings {
            api_servers: vec![Url::parse(&server.base_url()).unwrap()],
            download_servers: Vec::with_capacity(0),
        };
        (server, filen_settings)
    }
}
