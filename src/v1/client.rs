use crate::{crypto, filen_settings::*, queries, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::*;
use snafu::{ResultExt, Snafu};

type Result<T, E = Error> = std::result::Result<T, E>;

const DIR_COLOR_CHANGE_PATH: &str = "/v1/dir/color/change";
const ITEM_FAVORITE_PATH: &str = "/v1/item/favorite";
const SYNC_CLIENT_MESSAGE_PATH: &str = "/v1/sync/client/message";
const TRASH_EMPTY_PATH: &str = "/v1/trash/empty";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("{} query failed: {}", DIR_COLOR_CHANGE_PATH, source))]
    DirColorChangeQueryFailed { source: queries::Error },

    #[snafu(display("Cannot serialize data struct to JSON: {}", source))]
    CannotSerializeDataToJson { source: serde_json::Error },

    #[snafu(display("{} query failed: {}", ITEM_FAVORITE_PATH, source))]
    ItemFavoriteQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", SYNC_CLIENT_MESSAGE_PATH, source))]
    SyncClientMessageQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", TRASH_EMPTY_PATH, source))]
    TrashEmptyQueryFailed { source: queries::Error },
}

/// Used for requests to [DIR_COLOR_CHANGE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirColorChangeRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Folder color name.
    pub color: LocationColor,

    /// Folder ID.
    pub uuid: Uuid,
}
utils::display_from_json!(DirColorChangeRequestPayload);

/// Used for requests to [ITEM_FAVORITE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItemFavoriteRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of item to set favorite for.
    pub uuid: Uuid,

    /// What is favorited: a "file" or "folder"?
    #[serde(rename = "type")]
    pub item_type: ItemKind,

    /// 0 to unfavorite, 1 to favorite.
    #[serde(deserialize_with = "bool_from_int", serialize_with = "bool_to_int")]
    pub value: bool,
}
utils::display_from_json!(ItemFavoriteRequestPayload);

/// Used for requests to [SYNC_CLIENT_MESSAGE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncClientMessageRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Metadata with something to pass to Filen client.
    pub args: String,
}
utils::display_from_json!(SyncClientMessageRequestPayload);

impl SyncClientMessageRequestPayload {
    pub fn from_json(
        api_key: SecUtf8,
        json_value: serde_json::Value,
        last_master_key: &SecUtf8,
    ) -> SyncClientMessageRequestPayload {
        let metadata =
            crypto::encrypt_metadata_str(&json_value.to_string(), last_master_key.unsecure(), METADATA_VERSION)
                .unwrap();
        SyncClientMessageRequestPayload {
            api_key,
            args: metadata,
        }
    }

    pub fn from_data<T: Serialize>(
        api_key: SecUtf8,
        data: T,
        last_master_key: &SecUtf8,
    ) -> Result<SyncClientMessageRequestPayload> {
        let json_value = serde_json::to_value(&data).context(CannotSerializeDataToJson {})?;
        Ok(SyncClientMessageRequestPayload::from_json(
            api_key,
            json_value,
            last_master_key,
        ))
    }
}

/// Used for requests to [TRASH_EMPTY_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrashEmptyRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,
}
utils::display_from_json!(TrashEmptyRequestPayload);

/// Calls [DIR_COLOR_CHANGE_PATH] endpoint.
pub fn dir_color_change_request(
    payload: &DirColorChangeRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(DIR_COLOR_CHANGE_PATH, payload, filen_settings).context(DirColorChangeQueryFailed {})
}

/// Calls [DIR_COLOR_CHANGE_PATH] endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn dir_color_change_request_async(
    payload: &DirColorChangeRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(DIR_COLOR_CHANGE_PATH, payload, filen_settings)
        .await
        .context(DirColorChangeQueryFailed {})
}

/// Calls [ITEM_FAVORITE_PATH] endpoint.
pub fn item_favorite_request(
    payload: &ItemFavoriteRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(ITEM_FAVORITE_PATH, payload, filen_settings).context(ItemFavoriteQueryFailed {})
}

/// Calls [ITEM_FAVORITE_PATH] endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn item_favorite_request_async(
    payload: &ItemFavoriteRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(ITEM_FAVORITE_PATH, payload, filen_settings)
        .await
        .context(ItemFavoriteQueryFailed {})
}

/// Calls [SYNC_CLIENT_MESSAGE_PATH] endpoint. Used to pass data to Filen client.
pub fn sync_client_message_request(
    payload: &SyncClientMessageRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(SYNC_CLIENT_MESSAGE_PATH, payload, filen_settings).context(SyncClientMessageQueryFailed {})
}

/// Calls [SYNC_CLIENT_MESSAGE_PATH] endpoint asynchronously. Used to pass data to Filen client.
#[cfg(feature = "async")]
pub async fn sync_client_message_request_async(
    payload: &SyncClientMessageRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(SYNC_CLIENT_MESSAGE_PATH, payload, filen_settings)
        .await
        .context(SyncClientMessageQueryFailed {})
}

/// Calls [TRASH_EMPTY_PATH] endpoint. Used to permanently delete all files in the 'Trash' folder.
pub fn trash_empty_request(
    payload: &TrashEmptyRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(TRASH_EMPTY_PATH, payload, filen_settings).context(TrashEmptyQueryFailed {})
}

/// Calls [TRASH_EMPTY_PATH] endpoint asynchronously. Used to permanently delete all files in the 'Trash' folder.
#[cfg(feature = "async")]
pub async fn trash_empty_request_async(
    payload: &TrashEmptyRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(TRASH_EMPTY_PATH, payload, filen_settings)
        .await
        .context(TrashEmptyQueryFailed {})
}
