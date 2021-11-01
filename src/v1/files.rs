use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{crypto, filen_settings::FilenSettings, queries, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_json::json;
use snafu::{ensure, Backtrace, ResultExt, Snafu};

type Result<T, E = Error> = std::result::Result<T, E>;

const FILE_ARCHIVE_PATH: &str = "/v1/file/archive";
const FILE_EXISTS_PATH: &str = "/v1/file/exists";
const FILE_MOVE_PATH: &str = "/v1/file/move";
const FILE_RENAME_PATH: &str = "/v1/file/rename";
const FILE_TRASH_PATH: &str = "/v1/file/trash";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Caller provided invalid argument: {}", message))]
    BadArgument { message: String, backtrace: Backtrace },

    #[snafu(display("Failed to deserialize file metadata {}: {}", metadata, source))]
    DeserializeFileMetadataFailed {
        metadata: String,
        source: serde_json::Error,
    },

    #[snafu(display("Failed to decrypt file metadata {}: {}", metadata, source))]
    DecryptFileMetadataFailed { metadata: String, source: crypto::Error },

    #[snafu(display("Failed to encrypt file metadata: {}", source))]
    EncryptFileMetadataFailed { source: crypto::Error },

    #[snafu(display("{} query failed: {}", FILE_ARCHIVE_PATH, source))]
    FileArchieveQueryFailed {
        payload: FileArchiveRequestPayload,
        source: queries::Error,
    },

    #[snafu(display("{} query failed: {}", FILE_EXISTS_PATH, source))]
    FileExistsQueryFailed {
        payload: LocationExistsRequestPayload,
        source: queries::Error,
    },

    #[snafu(display("{} query failed: {}", FILE_MOVE_PATH, source))]
    FileMoveQueryFailed {
        payload: FileMoveRequestPayload,
        source: queries::Error,
    },

    #[snafu(display("{} query failed: {}", FILE_RENAME_PATH, source))]
    FileRenameQueryFailed {
        payload: FileRenameRequestPayload,
        source: queries::Error,
    },

    #[snafu(display("{} query failed: {}", FILE_TRASH_PATH, source))]
    FileTrashQueryFailed {
        payload: LocationTrashRequestPayload,
        source: queries::Error,
    },

    #[snafu(display(
        "File path does not contain valid filename.\
         Check that given file path is a UTF-8 string with a file name at the end"
    ))]
    FilePathDoesNotContainValidFilename { backtrace: Backtrace },

    #[snafu(display("File system failed to get metadata for a file: {}", source))]
    FileSystemMetadataError { source: std::io::Error },

    #[snafu(display("Unknown system time error: {}", source))]
    SystemTimeError { source: std::time::SystemTimeError },
}

/// File properties and a key used to decrypt file data.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileProperties {
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

    /// 'Last modified' timestamp in seconds.
    #[serde(rename = "lastModified")]
    pub last_modified: u64,
}

impl FileProperties {
    pub fn from_name_size_modified(name: &str, size: u64, last_modified: &SystemTime) -> Result<FileProperties> {
        ensure!(
            size > 0,
            BadArgument {
                message: "File size should be > 0"
            }
        );

        let key = SecUtf8::from(utils::random_alphanumeric_string(32));
        let mime_guess = mime_guess::from_path(name).first_raw();
        let mime = mime_guess.unwrap_or("");
        let last_modified_secs = last_modified
            .duration_since(UNIX_EPOCH)
            .context(SystemTimeError {})?
            .as_secs();
        Ok(FileProperties {
            name: name.to_owned(),
            size,
            mime: mime.to_owned(),
            key,
            last_modified: last_modified_secs,
        })
    }

    pub fn from_local_path(local_file_path: &Path) -> Result<FileProperties> {
        match local_file_path.file_name().and_then(|filename| filename.to_str()) {
            Some(file_name) => FileProperties::from_name_and_local_path(file_name, local_file_path),
            None => FilePathDoesNotContainValidFilename {}.fail(),
        }
    }

    pub fn from_name_and_local_path(filen_filename: &str, local_file_path: &Path) -> Result<FileProperties> {
        let fs_metadata = fs::metadata(local_file_path).context(FileSystemMetadataError {})?;
        let last_modified_time = fs_metadata.modified().unwrap_or_else(|_| SystemTime::now());
        FileProperties::from_name_size_modified(filen_filename, fs_metadata.len(), &last_modified_time)
    }

    /// Decrypts file metadata string.
    pub fn decrypt_file_metadata(metadata: &str, last_master_key: &SecUtf8) -> Result<FileProperties> {
        crypto::decrypt_metadata_str(metadata, last_master_key.unsecure())
            .context(DecryptFileMetadataFailed {
                metadata: metadata.to_owned(),
            })
            .and_then(|metadata| {
                serde_json::from_str::<FileProperties>(&metadata).context(DeserializeFileMetadataFailed {
                    metadata: metadata.clone(),
                })
            })
    }

    /// Decrypts file metadata string.
    pub fn encrypt_file_metadata(metadata: &FileProperties, last_master_key: &SecUtf8) -> Result<String> {
        let metadata_json = json!(metadata).to_string();
        crypto::encrypt_metadata_str(&metadata_json, last_master_key.unsecure(), METADATA_VERSION)
            .context(EncryptFileMetadataFailed {})
    }

    pub fn to_metadata_string(&self, last_master_key: &SecUtf8) -> Result<String> {
        FileProperties::encrypt_file_metadata(self, last_master_key)
    }

    pub fn name_encrypted(&self) -> String {
        crypto::encrypt_metadata_str(&self.name, self.key.unsecure(), METADATA_VERSION).unwrap()
    }

    pub fn size_encrypted(&self) -> String {
        crypto::encrypt_metadata_str(&self.size.to_string(), self.key.unsecure(), METADATA_VERSION).unwrap()
    }

    pub fn mime_encrypted(&self) -> String {
        crypto::encrypt_metadata_str(&self.mime.to_string(), self.key.unsecure(), METADATA_VERSION).unwrap()
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
    pub fn new<S: Into<String>>(
        api_key: SecUtf8,
        uuid: S,
        new_file_name: &str,
        file_metadata: &FileProperties,
        last_master_key: &SecUtf8,
    ) -> FileRenameRequestPayload {
        let name_metadata = LocationNameMetadata::encrypt_name_to_metadata(new_file_name, last_master_key);
        let name_hashed = LocationNameMetadata::name_hashed(new_file_name);
        let metadata = file_metadata.to_metadata_string(last_master_key).unwrap(); // Should never panic...
        FileRenameRequestPayload {
            api_key,
            uuid: uuid.into(),
            name_metadata,
            name_hashed,
            metadata,
        }
    }
}

/// Calls [FILE_ARCHIVE_PATH] endpoint.
/// Replaces one version of a file with another version of the same file.
/// Used when the file you want to upload already exists, so existing file needs to be archived first.
pub fn file_archive_request(
    payload: &FileArchiveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(FILE_ARCHIVE_PATH, payload, filen_settings).context(FileArchieveQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [FILE_ARCHIVE_PATH] endpoint asynchronously.
/// Replaces one version of a file with another version of the same file.
/// Used when the file you want to upload already exists, so existing file needs to be archived first.
#[cfg(feature = "async")]
pub async fn file_archive_request_async(
    payload: &FileArchiveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(FILE_ARCHIVE_PATH, payload, filen_settings)
        .await
        .context(FileArchieveQueryFailed {
            payload: payload.clone(),
        })
}

/// Calls [FILE_EXISTS_PATH] endpoint.
/// Checks if file with the given name exists within the specified parent folder.
pub fn file_exists_request(
    payload: &LocationExistsRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LocationExistsResponsePayload> {
    queries::query_filen_api(FILE_EXISTS_PATH, payload, filen_settings).context(FileExistsQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [FILE_EXISTS_PATH] endpoint asynchronously.
/// Checks if file with the given name exists within the specified parent folder.
#[cfg(feature = "async")]
pub async fn file_exists_request_async(
    payload: &LocationExistsRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LocationExistsResponsePayload> {
    queries::query_filen_api_async(FILE_EXISTS_PATH, payload, filen_settings)
        .await
        .context(FileExistsQueryFailed {
            payload: payload.clone(),
        })
}

/// Calls [FILE_MOVE_PATH] endpoint.
/// Moves file with the given uuid to the specified parent folder. It is a good idea to check first if file
/// with the same name already exists within the parent folder.
///
/// If file is moved into a linked and/or shared folder, don't forget to call [dir_link_add_request]
/// and/or [share_request] after a successfull move.
pub fn file_move_request(payload: &FileMoveRequestPayload, filen_settings: &FilenSettings) -> Result<PlainApiResponse> {
    queries::query_filen_api(FILE_MOVE_PATH, payload, filen_settings).context(FileMoveQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [FILE_MOVE_PATH] endpoint asynchronously.
/// Moves file with the given uuid to the specified parent folder. It is a good idea to check first if file
/// with the same name already exists within the parent folder.
///
/// If file is moved into a linked and/or shared folder, don't forget to call [dir_link_add_request]
/// and/or [share_request] after a successfull move.
#[cfg(feature = "async")]
pub async fn file_move_request_async(
    payload: &FileMoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(FILE_MOVE_PATH, payload, filen_settings)
        .await
        .context(FileMoveQueryFailed {
            payload: payload.clone(),
        })
}

/// Calls [FILE_RENAME_PATH] endpoint.
/// Changes name of the file with given UUID to the specified name. It is a good idea to check first if file
/// with the new name already exists within the parent folder.
pub fn file_rename_request(
    payload: &FileRenameRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(FILE_RENAME_PATH, payload, filen_settings).context(FileRenameQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [FILE_RENAME_PATH] endpoint asynchronously.
/// Changes name of the file with given UUID to the specified name. It is a good idea to check first if file
/// with the new name already exists within the parent folder.
#[cfg(feature = "async")]
pub async fn file_rename_request_async(
    payload: &FileRenameRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(FILE_RENAME_PATH, payload, filen_settings)
        .await
        .context(FileRenameQueryFailed {
            payload: payload.clone(),
        })
}

/// Calls [FILE_TRASH_PATH] endpoint.
/// Moves file with given UUID to trash. Note that file's UUID will still be considired existing,
/// so you cannot create a new file with it.
pub fn file_trash_request(
    payload: &LocationTrashRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(FILE_TRASH_PATH, payload, filen_settings).context(FileTrashQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [FILE_TRASH_PATH] endpoint asynchronously.
/// Moves file with given UUID to trash. Note that file's UUID will still be considired existing,
/// so you cannot create a new file with it.
#[cfg(feature = "async")]
pub async fn file_trash_request_async(
    payload: &LocationTrashRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(FILE_TRASH_PATH, payload, filen_settings)
        .await
        .context(FileTrashQueryFailed {
            payload: payload.clone(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use once_cell::sync::Lazy;
    use secstr::SecUtf8;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"));
    const NAME: &str = "test_folder";
    const NAME_METADATA: &str = "U2FsdGVkX19d09wR+Ti+qMO7o8habxXkS501US7uv96+zbHHZwDDPbnq1di1z0/S";
    const NAME_HASHED: &str = "19d24c63b1170a0b1b40520a636a25235735f39f";

    #[test]
    fn file_exists_request_should_work() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = LocationExistsRequestPayload {
            api_key: API_KEY.clone(),
            parent: "b640414e-367e-4df6-b31a-030fd639bcff".to_owned(),
            name_hashed: NAME_HASHED.to_owned(),
        };
        let expected_response: LocationExistsResponsePayload =
            deserialize_from_file("tests/resources/responses/file_exists.json");
        let mock = setup_json_mock(super::FILE_EXISTS_PATH, &request_payload, &expected_response, &server);

        let response = file_exists_request(&request_payload, &filen_settings)?;

        mock.assert_hits(1);
        assert_eq!(response, expected_response);
        Ok(())
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn file_exists_request_async_should_work() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = LocationExistsRequestPayload {
            api_key: API_KEY.clone(),
            parent: "b640414e-367e-4df6-b31a-030fd639bcff".to_owned(),
            name_hashed: NAME_HASHED.to_owned(),
        };
        let expected_response: LocationExistsResponsePayload =
            deserialize_from_file("tests/resources/responses/file_exists.json");
        let mock = setup_json_mock(super::FILE_EXISTS_PATH, &request_payload, &expected_response, &server);

        let async_response = file_exists_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(1);
        assert_eq!(async_response, expected_response);
        Ok(())
    }
}
