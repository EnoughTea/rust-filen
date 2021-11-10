use crate::{filen_settings::*, queries, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::*;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

const SHARE_PATH: &str = "/v1/share";
const SHARE_DIR_STATUS_PATH: &str = "/v1/share/dir/status";
const USER_SHARED_ITEM_RENAME_PATH: &str = "/v1/user/shared/item/rename";
const USER_SHARED_ITEM_STATUS_PATH: &str = "/v1/user/shared/item/status";
const USER_SHARED_ITEM_IN_REMOVE_PATH: &str = "/v1/user/shared/item/in/remove";
const USER_SHARED_ITEM_OUT_REMOVE_PATH: &str = "/v1/user/shared/item/out/remove";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("{} query failed: {}", SHARE_DIR_STATUS_PATH, source))]
    ShareDirStatusQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", SHARE_PATH, source))]
    ShareQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_SHARED_ITEM_IN_REMOVE_PATH, source))]
    UserSharedItemInRemoveQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_SHARED_ITEM_OUT_REMOVE_PATH, source))]
    UserSharedItemOutRemoveQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_SHARED_ITEM_RENAME_PATH, source))]
    UserSharedItemRenameQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_SHARED_ITEM_STATUS_PATH, source))]
    UserSharedItemStatusQueryFailed { source: queries::Error },
}

/// Identifies shared item.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ShareTarget {
    /// Linked item is a file.
    File,
    /// Linked item is a folder.
    Folder,
}
utils::display_from_json!(ShareTarget);

/// Used for requests to [SHARE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShareRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Email to share item with.
    pub email: String,

    /// Base64-encoded RSA-encrypted file or folder properties.
    pub metadata: String,

    /// ID of the parent folder of the shared item.
    pub parent: Uuid,

    /// Determines whether a file or a folder is being shared.
    #[serde(rename = "type")]
    pub share_type: ShareTarget,

    /// ID of the file or folder to share; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(ShareRequestPayload);

/// Used for requests to [SHARE_DIR_STATUS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShareDirStatusRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the folder to check; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(ShareDirStatusRequestPayload);

/// User's email and RSA public key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserEmailWithPublicKey {
    /// Email.
    pub email: String,

    /// RSA public key.
    #[serde(rename = "publicKey")]
    pub public_key: String,
}
utils::display_from_json!(UserEmailWithPublicKey);

impl HasPublicKey for UserEmailWithPublicKey {
    fn public_key_ref(&self) -> Option<&str> {
        Some(&self.public_key)
    }
}

/// Response data for [SHARE_DIR_STATUS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShareDirStatusResponseData {
    /// True if the specified folder is shared; false otherwise.
    pub sharing: bool,

    /// Emails and public keys of the users the folder is shared with. Empty if folder is not shared.
    #[serde(default)]
    pub users: Vec<UserEmailWithPublicKey>,
}
utils::display_from_json!(ShareDirStatusResponseData);

api_response_struct!(
    /// Response for [SHARE_DIR_STATUS_PATH] endpoint.
    ShareDirStatusResponsePayload<Option<ShareDirStatusResponseData>>
);

/// Used for requests to [USER_SHARED_ITEM_RENAME_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSharedItemRenameRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Folder or file ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// ID of the user this item is being shared with. Set to 0 when renaming is done from the perspective of sharee.
    #[serde(rename = "receiverId")]
    pub receiver_id: u32,

    /// Folder or file properties, encrypted with RSA public key of the user this item is being shared with,
    /// base64-encoded.
    pub metadata: String,
}
utils::display_from_json!(UserSharedItemRenameRequestPayload);

/// Used for requests to [USER_SHARED_ITEM_IN_REMOVE_PATH] and [USER_SHARED_ITEM_OUT_REMOVE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSharedItemRemoveRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the user this item is being shared with. Set to 0 when removing is done from the perspective of sharee.
    #[serde(rename = "receiverId")]
    pub receiver_id: u32,

    /// ID of the shared item; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(UserSharedItemRemoveRequestPayload);

/// Used for requests to [USER_SHARED_ITEM_STATUS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSharedItemStatusRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the item to check; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(UserSharedItemStatusRequestPayload);

/// User's id and RSA public key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserIdWithPublicKey {
    /// User ID.
    pub id: u32,

    /// RSA public key.
    #[serde(rename = "publicKey")]
    pub public_key: String,
}
utils::display_from_json!(UserIdWithPublicKey);

impl HasPublicKey for UserIdWithPublicKey {
    fn public_key_ref(&self) -> Option<&str> {
        Some(&self.public_key)
    }
}

/// Response data for [USER_SHARED_ITEM_STATUS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSharedItemStatusResponseData {
    /// True if the specified folder is shared; false otherwise.
    pub sharing: bool,

    /// Emails and public keys of the users the folder is shared with. Empty if folder is not shared.
    #[serde(default)]
    pub users: Vec<UserIdWithPublicKey>,
}
utils::display_from_json!(UserSharedItemStatusResponseData);

api_response_struct!(
    /// Response for [USER_SHARED_ITEM_STATUS_PATH] endpoint.
    UserSharedItemStatusResponsePayload<Option<UserSharedItemStatusResponseData>>
);

/// Calls [SHARE_DIR_STATUS_PATH] endpoint.
pub fn share_dir_status_request(
    payload: &ShareDirStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<ShareDirStatusResponsePayload> {
    queries::query_filen_api(SHARE_DIR_STATUS_PATH, payload, filen_settings).context(ShareDirStatusQueryFailed {})
}

/// Calls [SHARE_DIR_STATUS_PATH] endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn share_dir_status_request_async(
    payload: &ShareDirStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<ShareDirStatusResponsePayload> {
    queries::query_filen_api_async(SHARE_DIR_STATUS_PATH, payload, filen_settings)
        .await
        .context(ShareDirStatusQueryFailed {})
}

/// Calls [SHARE_PATH] endpoint.
pub fn share_request(payload: &ShareRequestPayload, filen_settings: &FilenSettings) -> Result<PlainApiResponse> {
    queries::query_filen_api(SHARE_PATH, payload, filen_settings).context(ShareQueryFailed {})
}

/// Calls [SHARE_PATH] endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn share_request_async(
    payload: &ShareRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(SHARE_PATH, payload, filen_settings)
        .await
        .context(ShareQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_IN_REMOVE_PATH] endpoint.
/// Used to remove shared item from the perspective of a sharee: a user an item is being shared with.
pub fn user_shared_item_in_remove_request(
    payload: &UserSharedItemRemoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(USER_SHARED_ITEM_IN_REMOVE_PATH, payload, filen_settings)
        .context(UserSharedItemInRemoveQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_IN_REMOVE_PATH] endpoint asynchronously.
/// Used to remove shared item from the perspective of a sharee: a user an item is being shared with.
#[cfg(feature = "async")]
pub async fn user_shared_item_in_rename_request_async(
    payload: &UserSharedItemRemoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(USER_SHARED_ITEM_IN_REMOVE_PATH, payload, filen_settings)
        .await
        .context(UserSharedItemInRemoveQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_OUT_REMOVE_PATH] endpoint.
/// Used to remove shared item from the perspective of an item's owner: to stop sharing the item.
pub fn user_shared_item_out_remove_request(
    payload: &UserSharedItemRemoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(USER_SHARED_ITEM_OUT_REMOVE_PATH, payload, filen_settings)
        .context(UserSharedItemOutRemoveQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_OUT_REMOVE_PATH] endpoint asynchronously.
/// Used to remove shared item from the perspective of an item's owner: to stop sharing the item.
#[cfg(feature = "async")]
pub async fn user_shared_item_out_remove_request_async(
    payload: &UserSharedItemRemoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(USER_SHARED_ITEM_OUT_REMOVE_PATH, payload, filen_settings)
        .await
        .context(UserSharedItemOutRemoveQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_RENAME_PATH] endpoint.
pub fn user_shared_item_rename_request(
    payload: &UserSharedItemRenameRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(USER_SHARED_ITEM_RENAME_PATH, payload, filen_settings)
        .context(UserSharedItemRenameQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_RENAME_PATH] endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn user_shared_item_rename_request_async(
    payload: &UserSharedItemRenameRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(USER_SHARED_ITEM_RENAME_PATH, payload, filen_settings)
        .await
        .context(UserSharedItemRenameQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_STATUS_PATH] endpoint.
pub fn user_shared_item_status_request(
    payload: &UserSharedItemStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserSharedItemStatusResponsePayload> {
    queries::query_filen_api(USER_SHARED_ITEM_STATUS_PATH, payload, filen_settings)
        .context(UserSharedItemStatusQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_STATUS_PATH] endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn user_shared_item_status_request_async(
    payload: &UserSharedItemStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserSharedItemStatusResponsePayload> {
    queries::query_filen_api_async(USER_SHARED_ITEM_STATUS_PATH, payload, filen_settings)
        .await
        .context(UserSharedItemStatusQueryFailed {})
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
    fn share_dir_status_request_should_have_proper_contract_for_shared_folder() {
        let request_payload = ShareDirStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract(
            SHARE_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/share_dir_status.json",
            |request_payload, filen_settings| share_dir_status_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn share_dir_status_request_async_should_have_proper_contract_for_shared_folder() {
        let request_payload = ShareDirStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract_async(
            SHARE_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/share_dir_status.json",
            |request_payload, filen_settings| async move {
                share_dir_status_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn share_dir_status_request_should_have_proper_contract_for_non_shared_folder() {
        let request_payload = ShareDirStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract(
            SHARE_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/share_dir_status_not_shared.json",
            |request_payload, filen_settings| share_dir_status_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn share_dir_status_request_async_should_have_proper_contract_for_non_shared_folder() {
        let request_payload = ShareDirStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract_async(
            SHARE_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/share_dir_status_not_shared.json",
            |request_payload, filen_settings| async move {
                share_dir_status_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn user_shared_item_status_request_should_have_proper_contract_for_shared_folder() {
        let request_payload = UserSharedItemStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract(
            USER_SHARED_ITEM_STATUS_PATH,
            request_payload,
            "tests/resources/responses/user_shared_item_status.json",
            |request_payload, filen_settings| user_shared_item_status_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn user_shared_item_status_request_async_should_have_proper_contract_for_shared_folder() {
        let request_payload = UserSharedItemStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract_async(
            USER_SHARED_ITEM_STATUS_PATH,
            request_payload,
            "tests/resources/responses/user_shared_item_status.json",
            |request_payload, filen_settings| async move {
                user_shared_item_status_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }
}
