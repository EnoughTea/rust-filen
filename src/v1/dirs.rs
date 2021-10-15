use crate::{crypto, settings::FilenSettings, utils};
use anyhow::*;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::*;

use super::api_response_struct;

const USER_DIRS_PATH: &str = "/v1/user/dirs";

// Used for requests to [USER_DIRS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserDirsRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,
}

/// One of the folders in response data for [USER_DIRS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserDirData {
    /// Folder identifier, hyphenated UUID V4 string.
    pub uuid: String,

    /// Metadata containing folder name. Filen default folder is always named "Default".
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Parent folder; None means this folder has no parents and is located at root.
    pub parent: Option<String>,

    /// True if this is a default Filen folder; false otherwise.
    pub default: bool,

    /// True if this is a sync folder; false otherwise.
    /// Filen sync folder is a special unique folder that needs to be created if it does not exist.
    /// It is always named "Filen Sync" and created with a special type: "sync".
    pub sync: bool,

    /// Seems like [UserDirData::default] field double, only with integer type instead of bool.
    pub is_default: i32,

    /// Seems like [UserDirData::sync] field double, only with integer type instead of bool.
    pub is_sync: i32,

    /// Folder color name; None means default yellow color. Possible colors: "blue", "green", "purple", "red", "gray".
    pub color: Option<String>,
}

/// Typed folder name metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct NameMetadataTyped {
    pub name: String,
}

impl UserDirData {
    /// Decrypt name metadata into actual folder name. "Default" means root folder.
    pub fn decrypt_name_metadata_to_name(&self, last_master_key: &SecUtf8) -> Result<String> {
        crypto::decrypt_metadata_str(&self.name_metadata, last_master_key.unsecure()).and_then(|metadata| {
            serde_json::from_str::<NameMetadataTyped>(&metadata)
                .with_context(|| "Cannot deserialize user dir name metadata")
                .map(|typed| typed.name)
        })
    }
}

api_response_struct!(
    /// Response for [USER_DIRS_PATH] endpoint.
    UserDirsResponsePayload<Vec<UserDirData>>
);

/// Calls [USER_DIRS_PATH] endpoint. Used to get a list of user's folders.
/// Always includes Filen "Default" folder, and may possibly include special "Filen Sync" folder, created by Filen's client.
pub fn user_dirs_request(
    payload: &UserDirsRequestPayload,
    settings: &FilenSettings,
) -> Result<UserDirsResponsePayload> {
    utils::query_filen_api(USER_DIRS_PATH, payload, settings)
}

/// Calls [USER_DIRS_PATH] endpoint asynchronously. Used to get a list of user's folders.
/// Always includes Filen "Default" folder, and may possibly include special "Filen Sync" folder, created by Filen's client.
pub async fn user_dirs_request_async(
    payload: &UserDirsRequestPayload,
    settings: &FilenSettings,
) -> Result<UserDirsResponsePayload> {
    utils::query_filen_api_async(USER_DIRS_PATH, payload, settings).await
}
