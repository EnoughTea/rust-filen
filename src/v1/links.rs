use crate::{filen_settings::*, queries, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::*;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

const LINK_DIR_STATUS_PATH: &str = "/v1/link/dir/status";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("{} query failed: {}", LINK_DIR_STATUS_PATH, source))]
    LinkDirStatusQueryFailed { uuid: Uuid, source: queries::Error },
}

/// Used for requests to [LINK_DIR_STATUS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkDirStatusRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(LinkDirStatusRequestPayload);

/// Link UUID with link key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkIdWithKey {
    /// Link key, encrypted.
    #[serde(rename = "linkKey")]
    pub link_key: String,

    /// Link ID; hyphenated lowercased UUID V4.
    #[serde(rename = "linkUUID")]
    pub link_uuid: Uuid,
}

/// Response data for [LINK_DIR_STATUS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkDirStatusResponseData {
    /// True if at least one link for the specified folder exists; false otherwise.
    pub link: bool,

    /// Found links. None if given folder is not linked.
    pub links: Option<Vec<LinkIdWithKey>>,
}
utils::display_from_json!(LinkDirStatusResponseData);

api_response_struct!(
    /// Response for [LINK_DIR_STATUS_PATH] endpoint.
    LinkDirStatusResponsePayload<Option<LinkDirStatusResponseData>>
);

/// Calls [LINK_DIR_STATUS_PATH] endpoint.
pub fn link_dir_status_request(
    payload: &LinkDirStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LinkDirStatusResponsePayload> {
    queries::query_filen_api(LINK_DIR_STATUS_PATH, payload, filen_settings).context(LinkDirStatusQueryFailed {
        uuid: payload.uuid.clone(),
    })
}

/// Calls [LINK_DIR_STATUS_PATH] endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn link_dir_status_request_async(
    payload: &LinkDirStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LinkDirStatusResponsePayload> {
    queries::query_filen_api_async(LINK_DIR_STATUS_PATH, payload, filen_settings)
        .await
        .context(LinkDirStatusQueryFailed {
            uuid: payload.uuid.clone(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use once_cell::sync::Lazy;
    use secstr::SecUtf8;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"));

    #[test]
    fn link_dir_status_request_should_have_proper_contract_for_no_link() {
        let request_payload = LinkDirStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract(
            LINK_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/link_dir_status_no_link.json",
            |request_payload, filen_settings| link_dir_status_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn link_dir_status_request_async_should_have_proper_contract_for_no_link() {
        let request_payload = LinkDirStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract_async(
            LINK_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/link_dir_status_no_link.json",
            |request_payload, filen_settings| async move {
                link_dir_status_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn link_dir_status_request_should_have_proper_contract_for_a_link() {
        let request_payload = LinkDirStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract(
            LINK_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/link_dir_status.json",
            |request_payload, filen_settings| link_dir_status_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn link_dir_status_request_async_should_have_proper_contract_for_a_link() {
        let request_payload = LinkDirStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract_async(
            LINK_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/link_dir_status.json",
            |request_payload, filen_settings| async move {
                link_dir_status_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }
}