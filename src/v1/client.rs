use crate::{crypto, filen_settings::*, queries, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::*;
use snafu::{ResultExt, Snafu};

type Result<T, E = Error> = std::result::Result<T, E>;

const SYNC_CLIENT_MESSAGE_PATH: &str = "/v1/sync/client/message";
const TRASH_EMPTY_PATH: &str = "/v1/trash/empty";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Cannot serialize data struct to JSON: {}", source))]
    CannotSerializeDataToJson { source: serde_json::Error },

    #[snafu(display("{} query failed: {}", SYNC_CLIENT_MESSAGE_PATH, source))]
    SyncClientMessageQueryFailed { data: String, source: queries::Error },

    #[snafu(display("{} query failed: {}", TRASH_EMPTY_PATH, source))]
    TrashEmptyQueryFailed { source: queries::Error },
}

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

/// Calls [SYNC_CLIENT_MESSAGE_PATH] endpoint. Used to pass data to Filen client.
pub fn sync_client_message_request(
    payload: &SyncClientMessageRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(SYNC_CLIENT_MESSAGE_PATH, payload, filen_settings).context(SyncClientMessageQueryFailed {
        data: payload.args.clone(),
    })
}

/// Calls [SYNC_CLIENT_MESSAGE_PATH] endpoint asynchronously. Used to pass data to Filen client.
#[cfg(feature = "async")]
pub async fn sync_client_message_request_async(
    payload: &SyncClientMessageRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(SYNC_CLIENT_MESSAGE_PATH, payload, filen_settings)
        .await
        .context(SyncClientMessageQueryFailed {
            data: payload.args.clone(),
        })
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
