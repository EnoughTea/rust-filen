use crate::{filen_settings::*, queries, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::*;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

const SHARE_PATH: &str = "/v1/share";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("{} query failed: {}", SHARE_PATH, source))]
    ShareQueryFailed {
        payload: ShareRequestPayload,
        source: queries::Error,
    },
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

/// Calls [SHARE_PATH] endpoint.
pub fn share_request(payload: &ShareRequestPayload, filen_settings: &FilenSettings) -> Result<PlainApiResponse> {
    queries::query_filen_api(SHARE_PATH, payload, filen_settings).context(ShareQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [SHARE_PATH] endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn share_request_async(
    payload: &ShareRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(SHARE_PATH, payload, filen_settings)
        .await
        .context(ShareQueryFailed {
            payload: payload.clone(),
        })
}
