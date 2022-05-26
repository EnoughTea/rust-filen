use crate::{
    queries, utils,
    v1::{bool_from_int, bool_to_int, response_payload},
    FilenSettings,
};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};

type Result<T, E = Error> = std::result::Result<T, E>;

const USER_USAGE_PATH: &str = "/v1/user/usage";
const USER_SYNC_GET_DATA_PATH: &str = "/v1/user/sync/get/data";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("{} query failed: {}", USER_USAGE_PATH, source))]
    UserUsageQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_SYNC_GET_DATA_PATH, source))]
    UserSyncGetDataQueryFailed { source: queries::Error },
}

/// Response data for `USER_SYNC_GET_DATA_PATH` endpoint.
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

    /// True if user is a premium user; false otherwise.
    #[serde(
        rename = "isPremium",
        deserialize_with = "bool_from_int",
        serialize_with = "bool_to_int"
    )]
    pub is_premium: bool,
}
utils::display_from_json!(UserSyncGetDataResponseData);

response_payload!(
    /// Response for `USER_SYNC_GET_DATA_PATH` endpoint.
    UserSyncGetDataResponsePayload<UserSyncGetDataResponseData>
);

/// Response data for `USER_USAGE_PATH` endpoint.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserUsageResponseData {
    /// Uploaded files count.
    pub uploads: u64,

    /// User folders count (including default folder).
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

response_payload!(
    /// Response for `USER_USAGE_PATH` endpoint.
    UserUsageResponsePayload<UserUsageResponseData>
);

/// Calls `USER_SYNC_GET_DATA` endpoint. Used to fetch user sync storage stats.
pub fn user_sync_get_data_request(
    api_key: &SecUtf8,
    filen_settings: &FilenSettings,
) -> Result<UserSyncGetDataResponsePayload> {
    queries::query_filen_api(USER_SYNC_GET_DATA_PATH, &utils::api_key_json(api_key), filen_settings)
        .context(UserSyncGetDataQueryFailedSnafu {})
}

/// Calls `USER_SYNC_GET_DATA` endpoint asynchronously. Used to fetch user sync storage stats.
#[cfg(feature = "async")]
pub async fn user_sync_get_data_request_async(
    api_key: &SecUtf8,
    filen_settings: &FilenSettings,
) -> Result<UserSyncGetDataResponsePayload> {
    queries::query_filen_api_async(USER_SYNC_GET_DATA_PATH, &utils::api_key_json(api_key), filen_settings)
        .await
        .context(UserSyncGetDataQueryFailed {})
}

/// Calls `USER_USAGE_PATH` endpoint. Used to fetch user general usage stats.
pub fn user_usage_request(api_key: &SecUtf8, filen_settings: &FilenSettings) -> Result<UserUsageResponsePayload> {
    queries::query_filen_api(USER_USAGE_PATH, &utils::api_key_json(api_key), filen_settings)
        .context(UserUsageQueryFailedSnafu {})
}

/// Calls `USER_USAGE_PATH` endpoint asynchronously. Used to fetch user general usage stats.
#[cfg(feature = "async")]
pub async fn user_usage_request_async(
    api_key: &SecUtf8,
    filen_settings: &FilenSettings,
) -> Result<UserUsageResponsePayload> {
    queries::query_filen_api_async(USER_USAGE_PATH, &utils::api_key_json(api_key), filen_settings)
        .await
        .context(UserUsageQueryFailed {})
}
