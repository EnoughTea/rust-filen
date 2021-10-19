use crate::{
    queries,
    settings::FilenSettings,
    utils,
    v1::{fs::*, *},
};
use anyhow::*;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::*;

pub const FILEN_SYNC_FOLDER_TYPE: &str = "sync";

const GET_DIR_PATH: &str = "/v1/get/dir";

// Used for requests to [GET_DIR_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetDirRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Sync folder ID, UUID V4 in hyphenated lowercase format.
    #[serde(rename = "uuid")]
    pub sync_folder_uuid: String,

    /// If set to "true", will fetch entire sync folder contents, which can be quite a heavy operation.
    /// If set to "false", server will check if sync folder contents changed. If synced content has not been changed,
    /// empty folder and file data will be returned; otherwise, full retrieve will be performed.
    #[serde(rename = "firstRequest")]
    pub first_request: String,
}
utils::display_from_json!(GetDirRequestPayload);

/// Response data for [DIR_CREATE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetDirResponseData {
    pub folders: Vec<SyncedDirData>,

    pub files: Vec<SyncedFileData>,
}
utils::display_from_json!(GetDirResponseData);

/// Folder data for one of the folder in Filen sync folder.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncedDirData {
    /// Folder ID, UUID V4 in hyphenated lowercase format.
    pub uuid: String,

    /// Metadata containing folder name.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Either parent folder ID, or "base" for rooted folders.
    pub parent: String,
}
utils::display_from_json!(SyncedDirData);

impl SyncedDirData {
    /// Decrypt name metadata into actual folder name.
    pub fn decrypt_name_metadata(&self, last_master_key: &SecUtf8) -> Result<String> {
        LocationNameMetadata::decrypt_name_from_metadata(&self.name_metadata, last_master_key)
    }
}

/// Folder data for one of the folder in Filen sync folder.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncedFileData {
    /// File ID, UUID V4 in hyphenated lowercase format.
    pub uuid: String,

    /// Name of the Filen bucket where file data is stored.
    pub bucket: String,

    /// Name of the Filen region where file data is stored.
    pub region: String,

    /// ID of the folder which contains this file.
    pub parent: String,

    /// File metadata.
    pub metadata: String,

    /// Determines how file bytes should be encrypted/decrypted.
    /// File is encrypted using roughly the same algorithm as metadata encryption,
    /// use [crypto::encrypt_file_data] and [crypto::decrypt_file_data] for the task.
    pub version: u32,
}
utils::display_from_json!(SyncedFileData);

impl SyncedFileData {
    /// Decrypt name metadata into actual folder name.
    pub fn decrypt_file_metadata(&self, last_master_key: &SecUtf8) -> Result<FileMetadata> {
        FileMetadata::decrypt_file_metadata(&self.metadata, last_master_key)
    }
}

api_response_struct!(
    /// Response for [DIR_CREATE_PATH] endpoint.
    GetDirResponsePayload<Option<GetDirResponseData>>
);

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

    #[tokio::test]
    async fn get_dir_request_and_async_should_work_for_unchanged_data() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = GetDirRequestPayload {
            api_key: API_KEY.clone(),
            sync_folder_uuid: "80f678c0-56ce-4b81-b4ef-f2a9c0c737c4".to_owned(),
            first_request: "false".to_owned(),
        };
        let expected_response: GetDirResponsePayload =
            deserialize_from_file("tests/resources/responses/get_dir_same_data.json");
        let mock = setup_json_mock(GET_DIR_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { get_dir_request(&request_payload, &filen_settings) }),
        ).await??;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = get_dir_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }
}

/// Calls [DIR_CREATE_PATH] endpoint. It fetches the entire Filen sync folder contents, with option
/// to return empty data if nothing has been changed since the last call.
pub fn get_dir_request(payload: &GetDirRequestPayload, settings: &FilenSettings) -> Result<GetDirResponsePayload> {
    queries::query_filen_api(GET_DIR_PATH, payload, settings)
}

/// Calls [DIR_CREATE_PATH] endpoint asynchronously. It fetches the entire Filen sync folder contents, with option
/// to return empty data if nothing has been changed since the last call.
pub async fn get_dir_request_async(
    payload: &GetDirRequestPayload,
    settings: &FilenSettings,
) -> Result<GetDirResponsePayload> {
    queries::query_filen_api_async(GET_DIR_PATH, payload, settings).await
}
