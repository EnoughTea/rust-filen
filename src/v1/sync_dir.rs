use crate::{filen_settings::FilenSettings, queries, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};

type Result<T, E = Error> = std::result::Result<T, E>;

const GET_DIR_PATH: &str = "/v1/get/dir";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to decrypt file metadata for data {}: {}", file_data, source))]
    DecryptFileMetadataFailed {
        file_data: SyncedFileData,
        source: files::Error,
    },

    #[snafu(display("{} query failed: {}", GET_DIR_PATH, source))]
    GetDirQueryFailed {
        payload: GetDirRequestPayload,
        source: queries::Error,
    },
}

// Used for requests to [GET_DIR_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetDirRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Sync folder ID, UUID V4 in hyphenated lowercase format.
    #[serde(rename = "uuid")]
    pub sync_folder_uuid: String,

    /// If set to true, will fetch entire sync folder contents, which can be quite a heavy operation.
    /// If set to false, server will check if sync folder contents changed. If synced content has not been changed,
    /// empty folder and file data will be returned; otherwise, full retrieve will be performed.
    #[serde(
        rename = "firstRequest",
        deserialize_with = "bool_from_string",
        serialize_with = "bool_to_string"
    )]
    pub first_request: bool,
}
utils::display_from_json!(GetDirRequestPayload);

/// Response data for [GET_DIR_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetDirResponseData {
    pub folders: Vec<FolderData>,

    pub files: Vec<SyncedFileData>,
}
utils::display_from_json!(GetDirResponseData);

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
    pub fn decrypt_file_metadata(&self, last_master_key: &SecUtf8) -> Result<FileProperties> {
        FileProperties::decrypt_file_metadata(&self.metadata, last_master_key).context(DecryptFileMetadataFailed {
            file_data: self.clone(),
        })
    }
}

api_response_struct!(
    /// Response for [GET_DIR_PATH] endpoint.
    GetDirResponsePayload<Option<GetDirResponseData>>
);

/// Calls [GET_DIR_PATH] endpoint. It fetches the entire Filen sync folder contents, with option
/// to return empty data if nothing has been changed since the last call.
pub fn get_dir_request(
    payload: &GetDirRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<GetDirResponsePayload> {
    queries::query_filen_api(GET_DIR_PATH, payload, filen_settings).context(GetDirQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [GET_DIR_PATH] endpoint asynchronously. It fetches the entire Filen sync folder contents, with option
/// to return empty data if nothing has been changed since the last call.
#[cfg(feature = "async")]
pub async fn get_dir_request_async(
    payload: &GetDirRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<GetDirResponsePayload> {
    queries::query_filen_api_async(GET_DIR_PATH, payload, filen_settings)
        .await
        .context(GetDirQueryFailed {
            payload: payload.clone(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use once_cell::sync::Lazy;
    use pretty_assertions::assert_eq;
    use secstr::SecUtf8;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"));

    #[test]
    fn get_dir_request_should_work_for_unchanged_data() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = GetDirRequestPayload {
            api_key: API_KEY.clone(),
            sync_folder_uuid: "80f678c0-56ce-4b81-b4ef-f2a9c0c737c4".to_owned(),
            first_request: false,
        };
        let expected_response: GetDirResponsePayload =
            deserialize_from_file("tests/resources/responses/get_dir_same_data.json");
        let mock = setup_json_mock(GET_DIR_PATH, &request_payload, &expected_response, &server);

        let response = get_dir_request(&request_payload, &filen_settings)?;

        mock.assert_hits(1);
        assert_eq!(response, expected_response);
        Ok(())
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn get_dir_request_and_async_should_work_for_unchanged_data() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = GetDirRequestPayload {
            api_key: API_KEY.clone(),
            sync_folder_uuid: "80f678c0-56ce-4b81-b4ef-f2a9c0c737c4".to_owned(),
            first_request: false,
        };
        let expected_response: GetDirResponsePayload =
            deserialize_from_file("tests/resources/responses/get_dir_same_data.json");
        let mock = setup_json_mock(GET_DIR_PATH, &request_payload, &expected_response, &server);

        let async_response = get_dir_request_async(&request_payload, &filen_settings).await?;

        mock.assert_hits(1);
        assert_eq!(async_response, expected_response);
        Ok(())
    }
}
