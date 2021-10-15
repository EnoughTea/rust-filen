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

/// Response data for [USER_DIRS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserDirsResponseData {
    pub uuid: String,
    #[serde(rename = "name")]
    pub name_metadata: String,
    pub parent: Option<String>,
    pub default: bool,
    pub sync: bool,
    pub is_default: i32,
    pub is_sync: i32,
    /// TODO: Actually, I have no idea what 'color' is, just a wild guess that it is most probably a string.
    pub color: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct NameMetadataTyped {
    pub name: String,
}

impl UserDirsResponseData {
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
    UserDirsResponsePayload<Vec<UserDirsResponseData>>
);

/// Calls [USER_DIRS_PATH] endpoint. Used to get user folders.
pub fn user_dirs_request(
    payload: &UserDirsRequestPayload,
    settings: &FilenSettings,
) -> Result<UserDirsResponsePayload> {
    utils::query_filen_api(USER_DIRS_PATH, payload, settings)
}

/// Calls [USER_DIRS_PATH] endpoint asynchronously. Used to get user folders.
pub async fn user_dirs_request_async(
    payload: &UserDirsRequestPayload,
    settings: &FilenSettings,
) -> Result<UserDirsResponsePayload> {
    utils::query_filen_api_async(USER_DIRS_PATH, payload, settings).await
}