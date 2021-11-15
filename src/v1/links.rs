use crate::{queries, utils, v1::*, *};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

const LINK_DIR_ITEM_RENAME_PATH: &str = "/v1/link/dir/item/rename";
const LINK_DIR_ITEM_STATUS_PATH: &str = "/v1/link/dir/item/status";
const LINK_DIR_STATUS_PATH: &str = "/v1/link/dir/status";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("{} query failed: {}", LINK_DIR_ITEM_RENAME_PATH, source))]
    LinkDirItemRenameQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", LINK_DIR_ITEM_STATUS_PATH, source))]
    LinkDirItemStatusQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", LINK_DIR_STATUS_PATH, source))]
    LinkDirStatusQueryFailed { source: queries::Error },
}

/// Used for requests to [LINK_DIR_ITEM_RENAME_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkDirItemRenameRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Folder or file ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Link ID; hyphenated lowercased UUID V4.
    #[serde(rename = "linkUUID")]
    pub link_uuid: Uuid,

    /// Folder or file properties, encrypted with link key.
    pub metadata: String,
}
utils::display_from_json!(LinkDirItemRenameRequestPayload);

impl LinkDirItemRenameRequestPayload {
    pub fn from_file_properties(
        api_key: SecUtf8,
        link_uuid: Uuid,
        file_uuid: Uuid,
        file_properties: &FileProperties,
        link_key: &SecUtf8,
    ) -> LinkDirItemRenameRequestPayload {
        let metadata = file_properties.to_metadata_string(link_key);
        LinkDirItemRenameRequestPayload {
            api_key,
            metadata,
            link_uuid,
            uuid: file_uuid,
        }
    }

    pub fn from_folder_name(
        api_key: SecUtf8,
        link_uuid: Uuid,
        folder_uuid: Uuid,
        folder_name: &str,
        link_key: &SecUtf8,
    ) -> LinkDirItemRenameRequestPayload {
        let metadata = LocationNameMetadata::encrypt_name_to_metadata(folder_name, link_key);
        LinkDirItemRenameRequestPayload {
            api_key,
            metadata,
            link_uuid,
            uuid: folder_uuid,
        }
    }
}

/// Used for requests to [LINK_DIR_ITEM_STATUS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkDirItemStatusRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Item ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(LinkDirItemStatusRequestPayload);

/// Response data for [LINK_DIR_ITEM_STATUS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct LinkDirItemStatusResponseData {
    /// True if at least one link for the specified item exists; false otherwise.
    pub link: bool,

    /// Found links. Empty if given item is not linked.
    #[serde(default)]
    pub links: Vec<LinkIdWithKey>,
}
utils::display_from_json!(LinkDirItemStatusResponseData);

response_payload!(
    /// Response for [LINK_DIR_ITEM_STATUS_PATH] endpoint.
    LinkDirItemStatusResponsePayload<LinkDirItemStatusResponseData>
);

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
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct LinkIdWithKey {
    /// Link key, encrypted.
    /// Decrypted by user's master keys and used to decrypt linked item metadata.
    #[serde(rename = "linkKey")]
    pub link_key: String,

    /// Link ID; hyphenated lowercased UUID V4.
    #[serde(rename = "linkUUID")]
    pub link_uuid: Uuid,
}
utils::display_from_json!(LinkIdWithKey);

impl HasLinkKey for LinkIdWithKey {
    fn link_key_metadata_ref(&self) -> Option<&str> {
        Some(&self.link_key)
    }
}

/// Response data for [LINK_DIR_STATUS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct LinkDirStatusResponseData {
    /// True if at least one link for the specified folder exists; false otherwise.
    pub link: bool,

    /// Found links. Empty if given folder is not linked.
    #[serde(default)]
    pub links: Vec<LinkIdWithKey>,
}
utils::display_from_json!(LinkDirStatusResponseData);

response_payload!(
    /// Response for [LINK_DIR_STATUS_PATH] endpoint.
    LinkDirStatusResponsePayload<LinkDirStatusResponseData>
);

/// Calls [LINK_DIR_ITEM_RENAME_PATH] endpoint.
pub fn link_dir_item_rename_request(
    payload: &LinkDirItemRenameRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(LINK_DIR_ITEM_RENAME_PATH, payload, filen_settings)
        .context(LinkDirItemRenameQueryFailed {})
}

/// Calls [LINK_DIR_ITEM_RENAME_PATH] endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn link_dir_item_rename_request_async(
    payload: &LinkDirItemRenameRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(LINK_DIR_ITEM_RENAME_PATH, payload, filen_settings)
        .await
        .context(LinkDirItemRenameQueryFailed {})
}

/// Calls [LINK_DIR_ITEM_STATUS_PATH] endpoint.
pub fn link_dir_item_status_request(
    payload: &LinkDirItemStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LinkDirStatusResponsePayload> {
    queries::query_filen_api(LINK_DIR_ITEM_STATUS_PATH, payload, filen_settings)
        .context(LinkDirItemStatusQueryFailed {})
}

/// Calls [LINK_DIR_ITEM_STATUS_PATH] endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn link_dir_item_status_request_async(
    payload: &LinkDirItemStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LinkDirStatusResponsePayload> {
    queries::query_filen_api_async(LINK_DIR_ITEM_STATUS_PATH, payload, filen_settings)
        .await
        .context(LinkDirItemStatusQueryFailed {})
}

/// Calls [LINK_DIR_STATUS_PATH] endpoint. Used to check if given folder has links and return them, if any.
pub fn link_dir_status_request(
    payload: &LinkDirStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LinkDirStatusResponsePayload> {
    queries::query_filen_api(LINK_DIR_STATUS_PATH, payload, filen_settings).context(LinkDirStatusQueryFailed {})
}

/// Calls [LINK_DIR_STATUS_PATH] endpoint asynchronously.
/// Used to check if given folder has links and return them, if any.
#[cfg(feature = "async")]
pub async fn link_dir_status_request_async(
    payload: &LinkDirStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LinkDirStatusResponsePayload> {
    queries::query_filen_api_async(LINK_DIR_STATUS_PATH, payload, filen_settings)
        .await
        .context(LinkDirStatusQueryFailed {})
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
