use crate::{
    queries, utils,
    v1::{bool_to_string, response_payload, FolderData, HasFileMetadata, HasFiles, HasFolders, HasUuid},
    FilenSettings,
};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

const GET_DIR_PATH: &str = "/v1/get/dir";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("{} query failed: {}", GET_DIR_PATH, source))]
    GetDirQueryFailed { source: queries::Error },
}

/// Used for requests to `GET_DIR_PATH` endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GetDirRequestPayload<'get_dir> {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: &'get_dir SecUtf8,

    /// Sync folder ID, UUID V4 in hyphenated lowercase format.
    #[serde(rename = "uuid")]
    pub sync_folder_uuid: Uuid,

    /// If set to true, will fetch entire sync folder contents, which can be quite a heavy operation.
    /// If set to false, server will check if sync folder contents changed. If synced content has not been changed,
    /// empty folder and file data will be returned; otherwise, full retrieve will be performed.
    #[serde(rename = "firstRequest", serialize_with = "bool_to_string")]
    pub first_request: bool,
}
utils::display_from_json_with_lifetime!('get_dir, GetDirRequestPayload);

/// Response data for `GET_DIR_PATH` endpoint.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct GetDirResponseData {
    pub folders: Vec<FolderData>,

    pub files: Vec<SyncedFileData>,
}
utils::display_from_json!(GetDirResponseData);

impl HasFiles<SyncedFileData> for GetDirResponseData {
    fn files_ref(&self) -> &[SyncedFileData] {
        &self.files
    }
}

impl HasFolders<FolderData> for GetDirResponseData {
    fn folders_ref(&self) -> &[FolderData] {
        &self.folders
    }
}

/// Represents a file stored under Filen sync folder.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct SyncedFileData {
    /// File ID, UUID V4 in hyphenated lowercase format.
    pub uuid: Uuid,

    /// Name of the Filen bucket where file data is stored.
    pub bucket: String,

    /// Name of the Filen region where file data is stored.
    pub region: String,

    /// ID of the folder which contains this file.
    pub parent: Uuid,

    /// File metadata.
    pub metadata: String,

    /// Determines how file bytes should be encrypted/decrypted.
    /// File is encrypted using roughly the same algorithm as metadata encryption,
    /// use [crypto::encrypt_file_data] and [crypto::decrypt_file_data] for the task.
    pub version: u32,
}
utils::display_from_json!(SyncedFileData);

impl HasFileMetadata for SyncedFileData {
    fn file_metadata_ref(&self) -> &str {
        &self.metadata
    }
}

impl HasUuid for SyncedFileData {
    fn uuid_ref(&self) -> &Uuid {
        &self.uuid
    }
}

response_payload!(
    /// Response for `GET_DIR_PATH` endpoint.
    GetDirResponsePayload<GetDirResponseData>
);

/// Calls `GET_DIR_PATH` endpoint. It fetches the entire Filen sync folder contents, with option
/// to return empty data if nothing has been changed since the last call.
pub fn get_dir_request(
    payload: &GetDirRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<GetDirResponsePayload> {
    queries::query_filen_api(GET_DIR_PATH, payload, filen_settings).context(GetDirQueryFailedSnafu {})
}

/// Calls `GET_DIR_PATH` endpoint asynchronously. It fetches the entire Filen sync folder contents, with option
/// to return empty data if nothing has been changed since the last call.
#[cfg(feature = "async")]
pub async fn get_dir_request_async(
    payload: &GetDirRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<GetDirResponsePayload> {
    queries::query_filen_api_async(GET_DIR_PATH, payload, filen_settings)
        .await
        .context(GetDirQueryFailedSnafu {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::validate_contract;
    #[cfg(feature = "async")]
    use crate::test_utils::validate_contract_async;
    use once_cell::sync::Lazy;
    use secstr::SecUtf8;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"));

    #[test]
    fn get_dir_request_should_be_correctly_typed_for_changed_data() {
        let request_payload = GetDirRequestPayload {
            api_key: &API_KEY,
            sync_folder_uuid: Uuid::parse_str("80f678c0-56ce-4b81-b4ef-f2a9c0c737c4").unwrap(),
            first_request: true,
        };
        validate_contract(
            GET_DIR_PATH,
            request_payload,
            "tests/resources/responses/get_dir_changed_data.json",
            |request_payload, filen_settings| get_dir_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn get_dir_request_and_async_should_be_correctly_typed_for_changed_data() {
        let request_payload = GetDirRequestPayload {
            api_key: &API_KEY,
            sync_folder_uuid: Uuid::parse_str("80f678c0-56ce-4b81-b4ef-f2a9c0c737c4").unwrap(),
            first_request: true,
        };
        validate_contract_async(
            GET_DIR_PATH,
            request_payload,
            "tests/resources/responses/get_dir_changed_data.json",
            |request_payload, filen_settings| async move {
                get_dir_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn get_dir_request_should_be_correctly_typed_for_unchanged_data() {
        let request_payload = GetDirRequestPayload {
            api_key: &API_KEY,
            sync_folder_uuid: Uuid::parse_str("80f678c0-56ce-4b81-b4ef-f2a9c0c737c4").unwrap(),
            first_request: false,
        };
        validate_contract(
            GET_DIR_PATH,
            request_payload,
            "tests/resources/responses/get_dir_same_data.json",
            |request_payload, filen_settings| get_dir_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn get_dir_request_and_async_should_be_correctly_typed_for_unchanged_data() {
        let request_payload = GetDirRequestPayload {
            api_key: &API_KEY,
            sync_folder_uuid: Uuid::parse_str("80f678c0-56ce-4b81-b4ef-f2a9c0c737c4").unwrap(),
            first_request: false,
        };
        validate_contract_async(
            GET_DIR_PATH,
            request_payload,
            "tests/resources/responses/get_dir_same_data.json",
            |request_payload, filen_settings| async move {
                get_dir_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }
}
