use crate::{crypto, settings::FilenSettings, utils};
use anyhow::*;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::*;
use uuid::Uuid;

use super::api_response_struct;

pub use super::sync_dir::*;

pub const FILEN_FOLDER_TYPE: &str = "folder";
pub const FILEN_SYNC_FOLDER_NAME: &str = "Filen Sync";
pub const FILEN_SYNC_FOLDER_TYPE: &str = "sync";

const USER_DIRS_PATH: &str = "/v1/user/dirs";
const DIR_CREATE_PATH: &str = "/v1/dir/create";
const DIR_EXISTS_PATH: &str = "/v1/dir/exists";

/// Typed folder name metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct DirNameMetadata {
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

    /// Metadata containing folder name.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Parent folder; None means this folder has no parents and is located at root.
    pub parent: Option<String>,

    /// True if this is a default Filen folder; false otherwise.
    pub default: bool,

    /// True if this is a Filen sync folder; false otherwise.
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

    /// Folder ID, UUID V4 in hyphenated lowercase format.
    pub uuid: String,

    /// Metadata containing json with format: { "name": <name value> }
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Currently hash_fn of lowercase folder name.
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
        let name_metadata =
            crypto::encrypt_metadata_str(&name_json, last_master_key.unsecure(), super::METADATA_VERSION).unwrap();
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

api_response_struct!(
    /// Response for [DIR_CREATE_PATH] endpoint.
    DirCreateResponsePayload<Option<()>>
);

// Used for requests to [DIR_EXISTS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirExistsRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Parent folder ID, UUID V4 in hyphenated lowercase format.
    pub parent: String,

    /// Currently hash_fn of lowercase target folder name.
    #[serde(rename = "nameHashed")]
    pub name_hashed: String,
}
utils::display_from_json!(DirExistsRequestPayload);

impl DirExistsRequestPayload {
    fn new(api_key: SecUtf8, target_parent: String, target_name: &str) -> DirExistsRequestPayload {
        let name_hashed = crypto::hash_fn(&target_name.to_lowercase());
        DirExistsRequestPayload {
            api_key,
            parent: target_parent,
            name_hashed,
        }
    }
}

/// Response data for [DIR_EXISTS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirExistsResponseData {
    /// True if folder with given name already exists in the parent folder; false otherwise.
    pub exists: bool,

    /// Existing folder ID, UUID V4 in hyphenated lowercase format. Empty string if folder does not exist.
    pub uuid: String,
}
utils::display_from_json!(DirExistsResponseData);

api_response_struct!(
    /// Response for [DIR_EXISTS_PATH] endpoint.
    DirExistsResponsePayload<Option<DirExistsResponseData>>
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

/// Calls [DIR_CREATE_PATH] endpoint.
pub fn dir_create_request(
    payload: &DirCreateRequestPayload,
    settings: &FilenSettings,
) -> Result<DirCreateResponsePayload> {
    utils::query_filen_api(DIR_CREATE_PATH, payload, settings)
}

/// Calls [DIR_CREATE_PATH] endpoint asynchronously.
pub async fn dir_create_request_async(
    payload: &DirCreateRequestPayload,
    settings: &FilenSettings,
) -> Result<DirCreateResponsePayload> {
    utils::query_filen_api_async(DIR_CREATE_PATH, payload, settings).await
}

/// Calls [DIR_CREATE_PATH] endpoint.
pub fn dir_exists_request(
    payload: &DirExistsRequestPayload,
    settings: &FilenSettings,
) -> Result<DirExistsResponsePayload> {
    utils::query_filen_api(DIR_EXISTS_PATH, payload, settings)
}

/// Calls [DIR_CREATE_PATH] endpoint asynchronously.
pub async fn dir_exists_request_async(
    payload: &DirExistsRequestPayload,
    settings: &FilenSettings,
) -> Result<DirExistsResponsePayload> {
    utils::query_filen_api_async(DIR_EXISTS_PATH, payload, settings).await
}

#[cfg(test)]
mod tests {
    use closure::closure;
    use once_cell::sync::Lazy;
    use secstr::SecUtf8;
    use tokio::task::spawn_blocking;

    use crate::test_utils::*;

    use super::*;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"));
    const NAME: &str = "test_folder";
    const NAME_METADATA: &str = "U2FsdGVkX19d09wR+Ti+qMO7o8habxXkS501US7uv96+zbHHZwDDPbnq1di1z0/S";
    const NAME_HASHED: &str = "19d24c63b1170a0b1b40520a636a25235735f39f";

    #[test]
    fn dir_create_request_payload_should_be_created_correctly_from_name() {
        let m_key = SecUtf8::from("b49cadfb92e1d7d54e9dd9d33ba9feb2af1f10ae");
        let payload = DirCreateRequestPayload::new(NAME, &API_KEY.clone(), &m_key);
        let decrypted_name = DirNameMetadata::decrypt_name_metadata_to_name(&payload.name_metadata, &m_key).unwrap();
        let parsed_uuid = Uuid::parse_str(&payload.uuid);

        assert_eq!(payload.api_key, *API_KEY);
        assert!(parsed_uuid.is_ok());
        assert_eq!(decrypted_name, NAME);
        assert_eq!(payload.name_hashed, NAME_HASHED);
        assert_eq!(payload.dir_type, "folder");
    }

    #[tokio::test]
    async fn user_dirs_request_and_async_should_work() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = UserDirsRequestPayload {
            api_key: API_KEY.clone(),
        };
        let expected_response: UserDirsResponsePayload =
            deserialize_from_file("tests/resources/responses/user_dirs_default.json");
        let mock = setup_json_mock(USER_DIRS_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { user_dirs_request(&request_payload, &filen_settings) }),
        ).await??;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = user_dirs_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }

    #[tokio::test]
    async fn dir_create_request_and_async_should_work() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = DirCreateRequestPayload {
            api_key: API_KEY.clone(),
            uuid: "80f678c0-56ce-4b81-b4ef-f2a9c0c737c4".to_owned(),
            name_metadata: NAME_METADATA.to_owned(),
            name_hashed: NAME_HASHED.to_owned(),
            dir_type: "folder".to_owned(),
        };
        let expected_response: DirCreateResponsePayload =
            deserialize_from_file("tests/resources/responses/dir_create.json");
        let mock = setup_json_mock(DIR_CREATE_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { dir_create_request(&request_payload, &filen_settings) }),
        ).await??;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = dir_create_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }

    #[tokio::test]
    async fn dir_exists_request_and_async_should_work() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = DirExistsRequestPayload {
            api_key: API_KEY.clone(),
            parent: "80f678c0-56ce-4b81-b4ef-f2a9c0c737c4".to_owned(),
            name_hashed: NAME_HASHED.to_owned(),
        };
        let expected_response: DirExistsResponsePayload =
            deserialize_from_file("tests/resources/responses/dir_exists.json");
        let mock = setup_json_mock(DIR_EXISTS_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { dir_exists_request(&request_payload, &filen_settings) }),
        ).await??;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = dir_exists_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }
}
