use crate::{filen_settings::FilenSettings, queries, utils, v1::*};
use anyhow::*;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};

const USER_USAGE_PATH: &str = "/v1/user/usage";
const USER_SYNC_GET_DATA_PATH: &str = "/v1/user/sync/get/data";

// Used for requests to [USER_SYNC_GET_DATA_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSyncGetDataRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,
}
utils::display_from_json!(UserSyncGetDataRequestPayload);

/// Response data for [USER_SYNC_GET_DATA_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSyncGetDataResponseData {
    /// User's email.
    pub email: String,

    /// Storage bytes available to user.
    #[serde(rename = "maxStorage")]
    pub max_storage: u64,

    /// Storage bytes used by user.
    #[serde(rename = "storageUsed")]
    pub storage_used: u64,

    /// Boolean field, 0 if user is a premium user.
    #[serde(rename = "isPremium")]
    pub is_premium: u32,
}
utils::display_from_json!(UserSyncGetDataResponseData);

api_response_struct!(
    /// Response for [USER_SYNC_GET_DATA_PATH] endpoint.
    UserSyncGetDataResponsePayload<Option<UserSyncGetDataResponseData>>
);

// Used for requests to [USER_USAGE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserUsageRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,
}
utils::display_from_json!(UserUsageRequestPayload);

/// Response data for [USER_USAGE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserUsageResponseData {
    /// Uploaded files count.
    pub uploads: u64,

    /// User folders count (including default).
    pub folders: u64,

    /// Storage bytes used by user.
    pub storage: u64,

    /// Storage bytes available to user.
    pub max: u64,

    /// True if 2FA is enabled; false otherwise.
    #[serde(rename = "twoFactorEnabled")]
    pub two_factor_enabled: bool,

    /// True if user is a premium user; false otherwise.
    pub pro: bool,

    /// User's email.
    pub email: String,
}
utils::display_from_json!(UserUsageResponseData);

api_response_struct!(UserUsageResponsePayload<Option<UserUsageResponseData>>);

/// Calls [USER_SYNC_GET_DATA] endpoint. Used to fetch user sync storage stats.
pub fn user_sync_get_data_request(
    payload: &UserSyncGetDataRequestPayload,
    settings: &FilenSettings,
) -> Result<UserSyncGetDataResponsePayload> {
    queries::query_filen_api(USER_SYNC_GET_DATA_PATH, payload, settings)
}

/// Calls [USER_SYNC_GET_DATA] endpoint asynchronously. Used to fetch user sync storage stats.
pub async fn user_sync_get_data_request_async(
    payload: &UserSyncGetDataRequestPayload,
    settings: &FilenSettings,
) -> Result<UserSyncGetDataResponsePayload> {
    queries::query_filen_api_async(USER_SYNC_GET_DATA_PATH, payload, settings).await
}

/// Calls [USER_USAGE_PATH] endpoint. Used to fetch user general usage stats.
pub fn user_usage_request(
    payload: &UserUsageRequestPayload,
    settings: &FilenSettings,
) -> Result<UserUsageResponsePayload> {
    queries::query_filen_api(USER_USAGE_PATH, payload, settings)
}

/// Calls [USER_USAGE_PATH] endpoint asynchronously. Used to fetch user general usage stats.
pub async fn user_usage_request_async(
    payload: &UserUsageRequestPayload,
    settings: &FilenSettings,
) -> Result<UserUsageResponsePayload> {
    queries::query_filen_api_async(USER_USAGE_PATH, payload, settings).await
}
