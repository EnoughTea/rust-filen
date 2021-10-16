use crate::{crypto, settings::FilenSettings, utils};
use anyhow::*;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::*;
use uuid::Uuid;

use super::api_response_struct;

pub const FILEN_FOLDER_TYPE: &str = "folder";
pub const FILEN_SYNC_FOLDER_NAME: &str = "Filen Sync";
pub const FILEN_SYNC_FOLDER_TYPE: &str = "sync";

const USER_DIRS_PATH: &str = "/v1/user/dirs";
const DIR_CREATE_PATH: &str = "/v1/dir/create";

/// Typed folder name metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct DirNameMetadata {
    pub name: String,
}

impl DirNameMetadata {
    /// Decrypt name metadata into actual folder name.
    pub fn decrypt_name_metadata_to_name(name_metadata: &str, last_master_key: &SecUtf8) -> Result<String> {
        crypto::decrypt_metadata_str(name_metadata, last_master_key.unsecure()).and_then(|metadata| {
            serde_json::from_str::<DirNameMetadata>(&metadata)
                .with_context(|| "Cannot deserialize user dir name metadata")
                .map(|typed| typed.name)
        })
    }
}

// Used for requests to [USER_DIRS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserDirsRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,
}
utils::display_from_json!(UserDirsRequestPayload);

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
    ///
    /// Filen sync folder is a special unique folder that is created by Filen client to store all synced files.
    /// If user never used Filen client, no sync folder would exist.
    ///
    /// Filen sync folder is always named "Filen Sync" and created with a special type: "sync".
    pub sync: bool,

    /// Seems like [UserDirData::default] field double, only with integer type instead of bool.
    pub is_default: i32,

    /// Seems like [UserDirData::sync] field double, only with integer type instead of bool.
    pub is_sync: i32,

    /// Folder color name; None means default yellow color. Possible colors: "blue", "green", "purple", "red", "gray".
    pub color: Option<String>,
}
utils::display_from_json!(UserDirData);

impl UserDirData {
    /// Decrypt name metadata into actual folder name.
    pub fn decrypt_name_metadata_to_name(&self, last_master_key: &SecUtf8) -> Result<String> {
        DirNameMetadata::decrypt_name_metadata_to_name(&self.name_metadata, last_master_key)
    }
}

api_response_struct!(
    /// Response for [USER_DIRS_PATH] endpoint.
    UserDirsResponsePayload<Vec<UserDirData>>
);

// Used for requests to [DIR_CREATE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirCreateRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// UUID V4 in hyphenated lower-case format.
    pub uuid: String,

    /// Metadata containing json with format: { "name": <name value> }
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Currently hash_fn of lower-case folder name.
    #[serde(rename = "nameHashed")]
    pub name_hashed: String,

    /// Should always be "folder", with "sync" reserved for Filen client sync folder.
    #[serde(rename = "type")]
    pub dir_type: String,
}
utils::display_from_json!(DirCreateRequestPayload);

impl DirCreateRequestPayload {
    /// Payload used for creation of the special Filen sync folder that is created by Filen client to store all synced files.
    /// You should only use this if you are writing your own replacement client.
    pub fn payload_for_sync_folder_creation(api_key: &SecUtf8, last_master_key: &SecUtf8) -> DirCreateRequestPayload {
        let mut payload = DirCreateRequestPayload::new(FILEN_SYNC_FOLDER_NAME, api_key, last_master_key);
        payload.dir_type = FILEN_SYNC_FOLDER_TYPE.to_owned();
        payload
    }

    /// Payload to create a new folder with the specified name.
    pub fn new(name: &str, api_key: &SecUtf8, last_master_key: &SecUtf8) -> DirCreateRequestPayload {
        let name_json = json!(DirNameMetadata { name: name.to_owned() }).to_string();
        let name_metadata = crypto::encrypt_metadata_str(&name_json, last_master_key.unsecure(), 1).unwrap();
        let name_hash = crypto::hash_fn(&name.to_lowercase());
        DirCreateRequestPayload {
            api_key: api_key.clone(),
            uuid: Uuid::new_v4().to_hyphenated().to_string(),
            name_metadata: name_metadata,
            name_hashed: name_hash,
            dir_type: FILEN_FOLDER_TYPE.to_owned(),
        }
    }
}

/// Response data for [DIR_CREATE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirCreateResponseData {}

api_response_struct!(
    /// Response for [DIR_CREATE_PATH] endpoint.
    DirCreateResponsePayload<Option<DirCreateResponseData>>
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

#[cfg(test)]
mod tests {
    use secstr::SecUtf8;

    use super::*;

    #[test]
    fn dir_create_request_payload_should_be_created_correctly_from_name() {
        let m_key = SecUtf8::from("b49cadfb92e1d7d54e9dd9d33ba9feb2af1f10ae");
        let api_key = SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6");
        let folder_name = "test_folder";
        let payload = DirCreateRequestPayload::new(folder_name, &api_key, &m_key);
        let decrypted_name = DirNameMetadata::decrypt_name_metadata_to_name(&payload.name_metadata, &m_key).unwrap();
        let parsed_uuid = Uuid::parse_str(&payload.uuid);

        assert_eq!(payload.api_key, api_key);
        assert!(parsed_uuid.is_ok());
        assert_eq!(decrypted_name, folder_name);
        assert_eq!(payload.name_hashed, "19d24c63b1170a0b1b40520a636a25235735f39f");
        assert_eq!(payload.dir_type, "folder");
    }
}
