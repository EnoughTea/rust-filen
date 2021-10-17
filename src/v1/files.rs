use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{crypto, errors::*, settings::FilenSettings, utils, v1::fs::*, v1::METADATA_VERSION};
use anyhow::*;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_json::json;

const FILE_ARCHIVE_PATH: &str = "/v1/file/archive";
const FILE_EXISTS_PATH: &str = "/v1/file/exists";
const FILE_MOVE_PATH: &str = "/v1/file/move";
const FILE_RENAME_PATH: &str = "/v1/file/rename";
const FILE_TRASH_PATH: &str = "/v1/file/trash";

/// File properties and a key used to decrypt file data.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileMetadata {
    /// Plain file name.
    pub name: String,

    /// File size in bytes.
    pub size: u64,

    /// File mime type. Can be an empty string.
    pub mime: String,

    /// Key used to decrypt file data.
    ///
    /// This is not a copy of master key, but a file-associated random alphanumeric string.
    pub key: SecUtf8,

    /// Timestamp in seconds.
    #[serde(rename = "lastModified")]
    pub last_modified: u64,
}

impl FileMetadata {
    pub fn from_name_and_local_path(name: &str, local_file_path: &PathBuf) -> Result<FileMetadata> {
        let fs_metadata = fs::metadata(local_file_path)?;
        let size = fs_metadata.len();
        if size <= 0 {
            bail!(bad_argument("File size is 0"));
        }

        let key = SecUtf8::from(utils::random_alphanumeric_string(32));
        let mime_guess = mime_guess::from_path(name).first_raw();
        let mime = mime_guess.unwrap_or("");
        let last_modified_time = fs_metadata.modified().unwrap_or(SystemTime::now());
        let last_modified = last_modified_time.duration_since(UNIX_EPOCH)?.as_secs();
        Ok(FileMetadata {
            name: name.to_owned(),
            size,
            mime: mime.to_owned(),
            key,
            last_modified,
        })
    }

    /// Decrypts file metadata string.
    pub fn decrypt_file_metadata(metadata: &str, last_master_key: &SecUtf8) -> Result<FileMetadata> {
        crypto::decrypt_metadata_str(metadata, last_master_key.unsecure()).and_then(|metadata| {
            serde_json::from_str::<FileMetadata>(&metadata).with_context(|| "Cannot deserialize synced file metadata")
        })
    }

    /// Decrypts file metadata string.
    pub fn encrypt_file_metadata(metadata: &FileMetadata, last_master_key: &SecUtf8) -> Result<String> {
        let metadata_json = json!(metadata).to_string();
        crypto::encrypt_metadata_str(&metadata_json, last_master_key.unsecure(), METADATA_VERSION)
    }

    pub fn to_metadata_string(&self, last_master_key: &SecUtf8) -> Result<String> {
        FileMetadata::encrypt_file_metadata(self, last_master_key)
    }
}

// Used for requests to [FILE_ARCHIVE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileArchiveRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the existing file to archive.
    pub uuid: String,

    /// Id of the file that will replace archived file.
    #[serde(rename = "updateUuid")]
    pub update_uuid: String,
}
utils::display_from_json!(FileArchiveRequestPayload);

// Used for requests to [FILE_MOVE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileMoveRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the parent folder where target file will be moved; hyphenated lowercased UUID V4.
    #[serde(rename = "folderUUID")]
    pub folder_uuid: String,

    /// ID of the file to move, hyphenated lowercased UUID V4.
    #[serde(rename = "fileUUID")]
    pub file_uuid: String,
}
utils::display_from_json!(FileMoveRequestPayload);

// Used for requests to [FILE_RENAME_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileRenameRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the file to rename, hyphenated lowercased UUID V4.
    pub uuid: String,

    /// Metadata with a new name.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Currently hash_fn of a lowercased new name.
    #[serde(rename = "nameHashed")]
    pub name_hashed: String,

    /// File metadata.
    #[serde(rename = "metaData")]
    pub metadata: String,
}
utils::display_from_json!(FileRenameRequestPayload);

impl FileRenameRequestPayload {
    pub fn new(
        api_key: SecUtf8,
        uuid: String,
        new_file_name: &str,
        file_metadata: &FileMetadata,
        last_master_key: &SecUtf8,
    ) -> FileRenameRequestPayload {
        let name_metadata = LocationNameMetadata::encrypt_name_to_metadata(new_file_name, last_master_key);
        let name_hashed = crypto::hash_fn(&new_file_name.to_lowercase());
        let metadata = file_metadata.to_metadata_string(last_master_key).unwrap(); // Should never panic... I think
        FileRenameRequestPayload {
            api_key,
            uuid,
            name_metadata,
            name_hashed,
            metadata,
        }
    }
}

/// Calls [FILE_ARCHIVE_PATH] endpoint.
/// Replaces one version of a file with another version of the same file.
/// Used when the file you want to upload already exists, so existing file needs to be archived first.
pub fn file_archive_request(payload: &FileArchiveRequestPayload, settings: &FilenSettings) -> Result<PlainApiResponse> {
    utils::query_filen_api(FILE_ARCHIVE_PATH, payload, settings)
}

/// Calls [FILE_ARCHIVE_PATH] endpoint asynchronously.
/// Replaces one version of a file with another version of the same file.
/// Used when the file you want to upload already exists, so existing file needs to be archived first.
pub async fn file_archive_request_async(
    payload: &FileArchiveRequestPayload,
    settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    utils::query_filen_api_async(FILE_ARCHIVE_PATH, payload, settings).await
}

/// Calls [FILE_EXISTS_PATH] endpoint.
/// Checks if file with the given name exists within the specified parent folder.
pub fn file_exists_request(
    payload: &LocationExistsRequestPayload,
    settings: &FilenSettings,
) -> Result<LocationExistsResponsePayload> {
    utils::query_filen_api(FILE_EXISTS_PATH, payload, settings)
}

/// Calls [FILE_EXISTS_PATH] endpoint asynchronously.
/// Checks if file with the given name exists within the specified parent folder.
pub async fn file_exists_request_async(
    payload: &LocationExistsRequestPayload,
    settings: &FilenSettings,
) -> Result<LocationExistsResponsePayload> {
    utils::query_filen_api_async(FILE_EXISTS_PATH, payload, settings).await
}

/// Calls [FILE_MOVE_PATH] endpoint.
/// Moves file with the given uuid to the specified parent folder. It is a good idea to check first if file
/// with the same name already exists within the parent folder.
pub fn dir_move_request(payload: &FileMoveRequestPayload, settings: &FilenSettings) -> Result<PlainApiResponse> {
    utils::query_filen_api(FILE_MOVE_PATH, payload, settings)
}

/// Calls [FILE_MOVE_PATH] endpoint asynchronously.
/// Moves file with the given uuid to the specified parent folder. It is a good idea to check first if file
/// with the same name already exists within the parent folder.
pub async fn file_move_request_async(
    payload: &FileMoveRequestPayload,
    settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    utils::query_filen_api_async(FILE_MOVE_PATH, payload, settings).await
}

/// Calls [FILE_RENAME_PATH] endpoint.
/// Changes name of the file with given UUID to the specified name. It is a good idea to check first if file
/// with the new name already exists within the parent folder.
pub fn file_rename_request(payload: &FileRenameRequestPayload, settings: &FilenSettings) -> Result<PlainApiResponse> {
    utils::query_filen_api(FILE_RENAME_PATH, payload, settings)
}

/// Calls [FILE_RENAME_PATH] endpoint asynchronously.
/// Changes name of the file with given UUID to the specified name. It is a good idea to check first if file
/// with the new name already exists within the parent folder.
pub async fn file_rename_request_async(
    payload: &FileRenameRequestPayload,
    settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    utils::query_filen_api_async(FILE_RENAME_PATH, payload, settings).await
}

/// Calls [FILE_TRASH_PATH] endpoint.
/// Moves file with given UUID to trash. Note that file's UUID will still be considired existing,
/// so you cannot create a new file with it.
pub fn file_trash_request(payload: &LocationTrashRequestPayload, settings: &FilenSettings) -> Result<PlainApiResponse> {
    utils::query_filen_api(FILE_TRASH_PATH, payload, settings)
}

/// Calls [FILE_TRASH_PATH] endpoint asynchronously.
/// Moves file with given UUID to trash. Note that file's UUID will still be considired existing,
/// so you cannot create a new file with it.
pub async fn file_trash_request_async(
    payload: &LocationTrashRequestPayload,
    settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    utils::query_filen_api_async(FILE_TRASH_PATH, payload, settings).await
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

    #[tokio::test]
    async fn file_exists_request_and_async_should_work() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = LocationExistsRequestPayload {
            api_key: API_KEY.clone(),
            parent: "b640414e-367e-4df6-b31a-030fd639bcff".to_owned(),
            name_hashed: NAME_HASHED.to_owned(),
        };
        let expected_response: LocationExistsResponsePayload =
            deserialize_from_file("tests/resources/responses/file_exists.json");
        let mock = setup_json_mock(FILE_EXISTS_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { file_exists_request(&request_payload, &filen_settings) }),
        ).await??;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = file_exists_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }
}
