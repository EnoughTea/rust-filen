use crate::{filen_settings::*, queries, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::*;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

const LINK_EDIT_PATH: &str = "/v1/link/edit";
const LINK_STATUS_PATH: &str = "/v1/link/status";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("{} query failed: {}", LINK_EDIT_PATH, source))]
    LinkEditQueryFailed {
        payload: LinkEditRequestPayload,
        source: queries::Error,
    },

    #[snafu(display("{} query failed: {}", LINK_STATUS_PATH, source))]
    LinkStatusQueryFailed { file_uuid: Uuid, source: queries::Error },
}

/// Determines public link state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkState {
    /// Link is disabled.
    Disable,
    /// Link is enabled.
    Enable,
}

/// Used for requests to [LINK_EDIT_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkEditRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Filen sets this to "enable" by default.
    #[serde(rename = "downloadBtn")]
    pub download_btn: DownloadBtnState,

    /// Link expiration time in text form. Usually has value "never".
    pub expiration: Expire,

    /// File ID; hyphenated lowercased UUID V4.
    #[serde(rename = "fileUUID")]
    pub file_uuid: Uuid,

    /// Folder metadata.
    pub metadata: String,

    /// ID of the parent of the linked folder, hyphenated lowercased UUID V4 if non-base.
    /// Use "base" if linked folder is located in the root folder.
    pub parent: ParentId,

    /// "empty" means no password protection, "notempty" means password is present.
    pub password: PasswordState,

    /// Output of [crypto::derive_key_from_password_512] for user's plain text password with 32 random bytes of salt,
    /// converted to a hex string.
    #[serde(rename = "passwordHashed")]
    pub password_hashed: String,

    /// An alphanumeric string with 32 random characters.
    pub salt: String,

    /// "enable" to enable file link, "disable" to disable it.
    #[serde(rename = "type")]
    pub link_type: LinkState,

    /// Enabled link ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(LinkEditRequestPayload);

/// Used for requests to [LINK_STATUS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkStatusRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the file whose link should be checked; hyphenated lowercased UUID V4.
    #[serde(rename = "fileUUID")]
    pub file_uuid: Uuid,
}
utils::display_from_json!(LinkStatusRequestPayload);

/// Response data for [LINK_STATUS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkStatusResponseData {
    /// Links for files always implicitly exist, but can enabled/disabled. True if link for this file is enabled;
    /// false otherwise.
    pub enabled: bool,

    /// Link ID if link is enabled; hyphenated lowercased UUID V4. None if link is disabled.
    pub uuid: Option<Uuid>,

    /// Link expiration time, as Unix timestamp in seconds. None if link is disabled.
    pub expiration: Option<u64>,

    /// Link expiration time in text form. None if link is disabled.
    #[serde(rename = "expirationText")]
    pub expiration_text: Option<Expire>,

    /// Can be set to 1 even for disabled links.
    #[serde(rename = "downloadBtn")]
    pub download_btn: DownloadBtnStateByte,

    /// Link password hash in hex string form, or None if no password was set by user or if link is disabled.
    pub password: Option<String>,
}
utils::display_from_json!(LinkStatusResponseData);

api_response_struct!(
    /// Response for [LINK_STATUS_PATH] endpoint.
    LinkStatusResponsePayload<Option<LinkStatusResponseData>>
);

/// Calls [LINK_EDIT_PATH] endpoint. Used to edit given file link.
pub fn link_edit_request(payload: &LinkEditRequestPayload, filen_settings: &FilenSettings) -> Result<PlainApiResponse> {
    queries::query_filen_api(LINK_EDIT_PATH, payload, filen_settings).context(LinkEditQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [LINK_EDIT_PATH] endpoint asynchronously. Used to edit given file link.
#[cfg(feature = "async")]
pub async fn link_edit_request_async(
    payload: &LinkEditRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(LINK_EDIT_PATH, payload, filen_settings)
        .await
        .context(LinkEditQueryFailed {
            payload: payload.clone(),
        })
}

/// Calls [LINK_STATUS_PATH] endpoint. Used to check file link status.
pub fn link_status_request(
    payload: &LinkStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LinkStatusResponsePayload> {
    queries::query_filen_api(LINK_STATUS_PATH, payload, filen_settings).context(LinkStatusQueryFailed {
        file_uuid: payload.file_uuid.clone(),
    })
}

/// Calls [LINK_STATUS_PATH] endpoint asynchronously. Used to check file link status.
#[cfg(feature = "async")]
pub async fn link_status_request_async(
    payload: &LinkStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LinkStatusResponsePayload> {
    queries::query_filen_api_async(LINK_STATUS_PATH, payload, filen_settings)
        .await
        .context(LinkStatusQueryFailed {
            file_uuid: payload.file_uuid.clone(),
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
    fn link_status_request_should_have_proper_contract_for_disabled_link() {
        let request_payload = LinkStatusRequestPayload {
            api_key: API_KEY.clone(),
            file_uuid: Uuid::nil(),
        };
        validate_contract(
            LINK_STATUS_PATH,
            request_payload,
            "tests/resources/responses/link_status_disabled.json",
            |request_payload, filen_settings| link_status_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn link_status_request_async_should_have_proper_contract_for_disabled_link() {
        let request_payload = LinkStatusRequestPayload {
            api_key: API_KEY.clone(),
            file_uuid: Uuid::nil(),
        };
        validate_contract_async(
            LINK_STATUS_PATH,
            request_payload,
            "tests/resources/responses/link_status_disabled.json",
            |request_payload, filen_settings| async move {
                link_status_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn link_status_request_should_have_proper_contract_for_link_without_password() {
        let request_payload = LinkStatusRequestPayload {
            api_key: API_KEY.clone(),
            file_uuid: Uuid::nil(),
        };
        validate_contract(
            LINK_STATUS_PATH,
            request_payload,
            "tests/resources/responses/link_status_enabled_no_password.json",
            |request_payload, filen_settings| link_status_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn link_status_request_async_should_have_proper_contract_for_link_without_password() {
        let request_payload = LinkStatusRequestPayload {
            api_key: API_KEY.clone(),
            file_uuid: Uuid::nil(),
        };
        validate_contract_async(
            LINK_STATUS_PATH,
            request_payload,
            "tests/resources/responses/link_status_enabled_no_password.json",
            |request_payload, filen_settings| async move {
                link_status_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn link_status_request_should_have_proper_contract_for_link_with_password() {
        let request_payload = LinkStatusRequestPayload {
            api_key: API_KEY.clone(),
            file_uuid: Uuid::nil(),
        };
        validate_contract(
            LINK_STATUS_PATH,
            request_payload,
            "tests/resources/responses/link_status_enabled_with_password.json",
            |request_payload, filen_settings| link_status_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn link_status_request_async_should_have_proper_contract_for_link_with_password() {
        let request_payload = LinkStatusRequestPayload {
            api_key: API_KEY.clone(),
            file_uuid: Uuid::nil(),
        };
        validate_contract_async(
            LINK_STATUS_PATH,
            request_payload,
            "tests/resources/responses/link_status_enabled_with_password.json",
            |request_payload, filen_settings| async move {
                link_status_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }
}
