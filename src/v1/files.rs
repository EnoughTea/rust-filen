use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    crypto, queries, utils,
    v1::{
        response_payload, DirContentFile, LocationExistsRequestPayload, LocationExistsResponsePayload,
        LocationNameMetadata, LocationTrashRequestPayload, PlainResponsePayload, METADATA_VERSION,
    },
    FilenSettings,
};
use secstr::{SecUtf8, SecVec};
use serde::{Deserialize, Serialize};
use serde_json::json;
use snafu::{ensure, Backtrace, ResultExt, Snafu};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

const FILE_ARCHIVE_PATH: &str = "/v1/file/archive";
const FILE_EXISTS_PATH: &str = "/v1/file/exists";
const FILE_MOVE_PATH: &str = "/v1/file/move";
const FILE_RENAME_PATH: &str = "/v1/file/rename";
const FILE_RESTORE_PATH: &str = "/v1/file/restore";
const FILE_TRASH_PATH: &str = "/v1/file/trash";
const RM_PATH: &str = "/v1/rm";
const USER_DELETE_ALL_PATH: &str = "/v1/user/delete/all";
const USER_RECENT_PATH: &str = "/v1/user/recent";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Caller provided invalid argument: {}", message))]
    BadArgument { message: String, backtrace: Backtrace },

    #[snafu(display("Expected metadata to be base64-encoded, but cannot decode it as such"))]
    CannotDecodeBase64Metadata {
        metadata: String,
        source: base64::DecodeError,
    },

    #[snafu(display("Failed to deserialize file metadata '{}': {}", metadata, source))]
    DeserializeFileMetadataFailed {
        metadata: String,
        source: serde_json::Error,
    },

    #[snafu(display("Failed to decrypt file metadata '{}': {}", metadata, source))]
    DecryptFileMetadataFailed { metadata: String, source: crypto::Error },

    #[snafu(display("Failed to decrypt file metadata '{}' using RSA: {}", metadata, source))]
    DecryptFileMetadataRsaFailed { metadata: String, source: crypto::Error },

    #[snafu(display("Failed to encrypt file metadata '{}' using RSA: {}", metadata, source))]
    EncryptFileMetadataRsaFailed { metadata: String, source: crypto::Error },

    #[snafu(display("{} query failed: {}", FILE_ARCHIVE_PATH, source))]
    FileArchieveQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", FILE_EXISTS_PATH, source))]
    FileExistsQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", FILE_MOVE_PATH, source))]
    FileMoveQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", FILE_RENAME_PATH, source))]
    FileRenameQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", FILE_RESTORE_PATH, source))]
    FileRestoreQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", FILE_TRASH_PATH, source))]
    FileTrashQueryFailed { source: queries::Error },

    #[snafu(display(
        "File path does not contain valid filename.\
         Check that given file path is a UTF-8 string with a file name at the end"
    ))]
    FilePathDoesNotContainValidFilename { backtrace: Backtrace },

    #[snafu(display("File system failed to get metadata for a file: {}", source))]
    FileSystemMetadataError { source: std::io::Error },

    #[snafu(display("{} query failed: {}", RM_PATH, source))]
    RmQueryFailed { source: queries::Error },

    #[snafu(display("Unknown system time error: {}", source))]
    SystemTimeError { source: std::time::SystemTimeError },

    #[snafu(display("{} query failed: {}", USER_DELETE_ALL_PATH, source))]
    UserDeleteAllQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_RECENT_PATH, source))]
    UserRecentQueryFailed { source: queries::Error },
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
utils::display_from_json!(FileProperties);

impl FileProperties {
    /// Fills file properties from name, size, last modified and optional file key.
    ///
    /// * `name` - Filename with extension, e.g. "readme.txt".
    /// * `size` - File size in bytes.
    /// * `last_modified` - Last modification time as reported by file system.
    /// * `file_key` - Optional file key to use. If none, random alphanumeric string (32 chars) will be used.
    pub fn from_name_size_modified_key(
        name: &str,
        size: u64,
        last_modified: &SystemTime,
        file_key: Option<SecUtf8>,
    ) -> Result<Self> {
        ensure!(
            size > 0,
            BadArgumentSnafu {
                message: "file size should be > 0"
            }
        );

        let mime_guess = mime_guess::from_path(name).first_raw();
        let mime = mime_guess.unwrap_or("");
        let last_modified_secs = last_modified
            .duration_since(UNIX_EPOCH)
            .context(SystemTimeSnafu {})?
            .as_secs();
        Ok(Self {
            name: name.to_owned(),
            size,
            mime: mime.to_owned(),
            key: file_key.unwrap_or_else(|| SecUtf8::from(utils::random_alphanumeric_string(32))),
            last_modified: last_modified_secs,
        })
    }

    /// Fills file properties from name, size and last modified. File key will be randomly generated.
    pub fn from_name_size_modified(name: &str, size: u64, last_modified: &SystemTime) -> Result<Self> {
        Self::from_name_size_modified_key(name, size, last_modified, None)
    }

    /// Fills file properties from local file properties. File key will be randomly generated.
    pub fn from_local_path(local_file_path: &Path) -> Result<Self> {
        match local_file_path.file_name().and_then(std::ffi::OsStr::to_str) {
            Some(file_name) => Self::from_name_and_local_path(file_name, local_file_path),
            None => FilePathDoesNotContainValidFilenameSnafu {}.fail(),
        }
    }

    /// Fills file properties from local file properties, with a way to change file name.
    /// File key will be randomly generated.
    pub fn from_name_and_local_path(filen_filename: &str, local_file_path: &Path) -> Result<Self> {
        let fs_metadata = fs::metadata(local_file_path).context(FileSystemMetadataSnafu {})?;
        let last_modified_time = fs_metadata.modified().unwrap_or_else(|_| SystemTime::now());
        Self::from_name_size_modified(filen_filename, fs_metadata.len(), &last_modified_time)
    }

    /// Decrypts file properties from metadata string.
    pub fn decrypt_file_metadata(metadata: &str, master_keys: &[SecUtf8]) -> Result<Self> {
        crypto::decrypt_metadata_str_any_key(metadata, master_keys)
            .context(DecryptFileMetadataFailedSnafu {
                metadata: metadata.to_owned(),
            })
            .and_then(|file_properties_json| {
                serde_json::from_str::<Self>(&file_properties_json).context(DeserializeFileMetadataFailedSnafu {
                    metadata: metadata.to_owned(),
                })
            })
    }

    /// Encrypts file properties to a metadata string.
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn encrypt_file_metadata(file_properties: &Self, last_master_key: &SecUtf8) -> String {
        let metadata_json = json!(file_properties).to_string();
        // Cannot panic due to the way encrypt_metadata_str is implemented.
        crypto::encrypt_metadata_str(&metadata_json, last_master_key, METADATA_VERSION).unwrap()
    }

    /// Decrypts file properties from a metadata string using RSA private key.
    /// Assumes given metadata string is base64-encoded.
    pub fn decrypt_file_metadata_rsa(metadata: &str, rsa_private_key_bytes: &SecVec<u8>) -> Result<Self> {
        let decoded = base64::decode(metadata).context(CannotDecodeBase64MetadataSnafu {
            metadata: metadata.to_owned(),
        })?;
        let decrypted = crypto::decrypt_rsa(&decoded, rsa_private_key_bytes.unsecure()).context(
            DecryptFileMetadataRsaFailedSnafu {
                metadata: metadata.to_owned(),
            },
        )?;
        serde_json::from_slice::<Self>(&decrypted).context(DeserializeFileMetadataFailedSnafu {
            metadata: metadata.to_owned(),
        })
    }

    /// Encrypts file properties to a metadata string using RSA public key of the user with whom item is shared
    /// aka receiver. Returns base64-encoded bytes.
    pub fn encrypt_file_metadata_rsa(file_properties: &Self, rsa_public_key_bytes: &[u8]) -> Result<String> {
        let metadata_json = json!(file_properties).to_string();
        let encrypted = crypto::encrypt_rsa(metadata_json.as_bytes(), rsa_public_key_bytes).context(
            EncryptFileMetadataRsaFailedSnafu {
                metadata: metadata_json,
            },
        )?;
        Ok(base64::encode(&encrypted))
    }

    #[must_use]
    pub fn to_metadata_string(&self, last_master_key: &SecUtf8) -> String {
        Self::encrypt_file_metadata(self, last_master_key)
    }

    pub fn to_metadata_rsa_string(&self, rsa_public_key_bytes: &[u8]) -> Result<String> {
        Self::encrypt_file_metadata_rsa(self, rsa_public_key_bytes)
    }

    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn name_encrypted(&self) -> String {
        // Cannot panic due to the way encrypt_metadata_str is implemented.
        crypto::encrypt_metadata_str(&self.name, &self.key, METADATA_VERSION).unwrap()
    }

    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn size_encrypted(&self) -> String {
        // Cannot panic due to the way encrypt_metadata_str is implemented.
        crypto::encrypt_metadata_str(&self.size.to_string(), &self.key, METADATA_VERSION).unwrap()
    }

    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn mime_encrypted(&self) -> String {
        // Cannot panic due to the way encrypt_metadata_str is implemented.
        crypto::encrypt_metadata_str(&self.mime, &self.key, METADATA_VERSION).unwrap()
    }
}

/// Used for requests to `FILE_ARCHIVE_PATH` endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileArchiveRequestPayload<'file_archive> {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: &'file_archive SecUtf8,

    /// ID of the existing file to archive.
    pub uuid: Uuid,

    /// Id of the file that will replace archived file.
    #[serde(rename = "updateUuid")]
    pub update_uuid: Uuid,
}
utils::display_from_json_with_lifetime!('file_archive, FileArchiveRequestPayload);

/// Used for requests to `FILE_MOVE_PATH` endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileMoveRequestPayload<'file_move> {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: &'file_move SecUtf8,

    /// ID of the parent folder where target file will be moved; hyphenated lowercased UUID V4.
    #[serde(rename = "folderUUID")]
    pub folder_uuid: Uuid,

    /// ID of the file to move, hyphenated lowercased UUID V4.
    #[serde(rename = "fileUUID")]
    pub file_uuid: Uuid,
}
utils::display_from_json_with_lifetime!('file_move, FileMoveRequestPayload);

/// Used for requests to `FILE_RENAME_PATH` endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileRenameRequestPayload<'file_rename> {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: &'file_rename SecUtf8,

    /// ID of the file to rename, hyphenated lowercased UUID V4.
    pub uuid: Uuid,

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
utils::display_from_json_with_lifetime!('file_rename, FileRenameRequestPayload);

impl<'file_rename> FileRenameRequestPayload<'file_rename> {
    #[must_use]
    pub fn new(
        api_key: &'file_rename SecUtf8,
        uuid: Uuid,
        new_file_name: &str,
        file_metadata: &FileProperties,
        last_master_key: &SecUtf8,
    ) -> Self {
        let name_metadata = LocationNameMetadata::encrypt_name_to_metadata(new_file_name, last_master_key);
        let name_hashed = LocationNameMetadata::name_hashed(new_file_name);
        let metadata = file_metadata.to_metadata_string(last_master_key);
        Self {
            api_key,
            uuid,
            name_metadata,
            name_hashed,
            metadata,
        }
    }
}

/// Used for requests to `FILE_RESTORE_PATH` endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileRestoreRequestPayload<'file_restore> {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: &'file_restore SecUtf8,

    /// Trashed file ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json_with_lifetime!('file_restore, FileRestoreRequestPayload);

/// Used for requests to `RM_PATH` endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RmRequestPayload<'rm> {
    /// ID of the file to delete; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Random alphanumeric string associated with the file. After file uploading, 'rm' can be viewed with
    /// queries like `file_versions_request` or `dir_content_request`.
    pub rm: &'rm str,
}
utils::display_from_json_with_lifetime!('rm, RmRequestPayload);

response_payload!(
    /// Response for `USER_RECENT_PATH` endpoint.
    UserRecentResponsePayload<Vec<DirContentFile>>
);

/// Calls `FILE_ARCHIVE_PATH` endpoint.
/// Replaces one version of a file with another version of the same file.
/// Used when the file you want to upload already exists, so existing file needs to be archived first.
pub fn file_archive_request(
    payload: &FileArchiveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(FILE_ARCHIVE_PATH, payload, filen_settings).context(FileArchieveQueryFailedSnafu {})
}

/// Calls `FILE_ARCHIVE_PATH` endpoint asynchronously.
/// Replaces one version of a file with another version of the same file.
/// Used when the file you want to upload already exists, so existing file needs to be archived first.
#[cfg(feature = "async")]
pub async fn file_archive_request_async(
    payload: &FileArchiveRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(FILE_ARCHIVE_PATH, payload, filen_settings)
        .await
        .context(FileArchieveQueryFailedSnafu {})
}

/// Calls `FILE_EXISTS_PATH` endpoint.
/// Checks if file with the given name exists within the specified parent folder.
pub fn file_exists_request(
    payload: &LocationExistsRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LocationExistsResponsePayload> {
    queries::query_filen_api(FILE_EXISTS_PATH, payload, filen_settings).context(FileExistsQueryFailedSnafu {})
}

/// Calls `FILE_EXISTS_PATH` endpoint asynchronously.
/// Checks if file with the given name exists within the specified parent folder.
#[cfg(feature = "async")]
pub async fn file_exists_request_async(
    payload: &LocationExistsRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<LocationExistsResponsePayload> {
    queries::query_filen_api_async(FILE_EXISTS_PATH, payload, filen_settings)
        .await
        .context(FileExistsQueryFailedSnafu {})
}

/// Calls `FILE_MOVE_PATH` endpoint.
/// Moves file with the given uuid to the specified parent folder. It is a good idea to check first if file
/// with the same name already exists within the parent folder.
///
/// If file is moved into a linked and/or shared folder, don't forget to call `dir_link_add_request`
/// and/or `share_request` after a successfull move.
pub fn file_move_request(
    payload: &FileMoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(FILE_MOVE_PATH, payload, filen_settings).context(FileMoveQueryFailedSnafu {})
}

/// Calls `FILE_MOVE_PATH` endpoint asynchronously.
/// Moves file with the given uuid to the specified parent folder. It is a good idea to check first if file
/// with the same name already exists within the parent folder.
///
/// If file is moved into a linked and/or shared folder, don't forget to call `dir_link_add_request`
/// and/or `share_request` after a successfull move.
#[cfg(feature = "async")]
pub async fn file_move_request_async(
    payload: &FileMoveRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(FILE_MOVE_PATH, payload, filen_settings)
        .await
        .context(FileMoveQueryFailedSnafu {})
}

/// Calls `FILE_RENAME_PATH` endpoint.
/// Changes name of the file with given UUID to the specified name. It is a good idea to check first if file
/// with the new name already exists within the parent folder.
pub fn file_rename_request(
    payload: &FileRenameRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(FILE_RENAME_PATH, payload, filen_settings).context(FileRenameQueryFailedSnafu {})
}

/// Calls `FILE_RENAME_PATH` endpoint asynchronously.
/// Changes name of the file with given UUID to the specified name. It is a good idea to check first if file
/// with the new name already exists within the parent folder.
#[cfg(feature = "async")]
pub async fn file_rename_request_async(
    payload: &FileRenameRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(FILE_RENAME_PATH, payload, filen_settings)
        .await
        .context(FileRenameQueryFailedSnafu {})
}

/// Calls `FILE_RESTORE_PATH` endpoint. Used to restore file from the 'trash' folder.
pub fn file_restore_request(
    payload: &FileRestoreRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(FILE_RESTORE_PATH, payload, filen_settings).context(FileRestoreQueryFailedSnafu {})
}

/// Calls `FILE_RESTORE_PATH` endpoint asynchronously. Used to restore file from the 'trash' folder.
#[cfg(feature = "async")]
pub async fn file_restore_request_async(
    payload: &FileRestoreRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(FILE_RESTORE_PATH, payload, filen_settings)
        .await
        .context(FileRestoreQueryFailedSnafu {})
}

/// Calls `FILE_TRASH_PATH` endpoint.
/// Moves file with given UUID to trash. Note that file's UUID will still be considired existing,
/// so you cannot create a new file with it.
pub fn file_trash_request(
    payload: &LocationTrashRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(FILE_TRASH_PATH, payload, filen_settings).context(FileTrashQueryFailedSnafu {})
}

/// Calls `FILE_TRASH_PATH` endpoint asynchronously.
/// Moves file with given UUID to trash. Note that file's UUID will still be considired existing,
/// so you cannot create a new file with it.
#[cfg(feature = "async")]
pub async fn file_trash_request_async(
    payload: &LocationTrashRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(FILE_TRASH_PATH, payload, filen_settings)
        .await
        .context(FileTrashQueryFailedSnafu {})
}

/// Calls `RM_PATH` endpoint. Used to delete file.
pub fn rm_request(payload: &RmRequestPayload, filen_settings: &FilenSettings) -> Result<PlainResponsePayload> {
    queries::query_filen_api(RM_PATH, payload, filen_settings).context(RmQueryFailedSnafu {})
}

/// Calls `RM_PATH` endpoint asynchronously. Used to delete file.
#[cfg(feature = "async")]
pub async fn rm_request_async(
    payload: &RmRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(RM_PATH, payload, filen_settings)
        .await
        .context(RmQueryFailedSnafu {})
}

/// Calls `USER_DELETE_ALL_PATH` endpoint. Used to delete *all* user files and folders.
pub fn user_delete_all_request(api_key: &SecUtf8, filen_settings: &FilenSettings) -> Result<UserRecentResponsePayload> {
    queries::query_filen_api(USER_DELETE_ALL_PATH, &utils::api_key_json(api_key), filen_settings)
        .context(UserDeleteAllQueryFailedSnafu {})
}

/// Calls `USER_DELETE_ALL_PATH` endpoint. Used to delete *all* user files and folders.
#[cfg(feature = "async")]
pub async fn user_delete_all_request_async(
    api_key: &SecUtf8,
    filen_settings: &FilenSettings,
) -> Result<UserRecentResponsePayload> {
    queries::query_filen_api_async(USER_DELETE_ALL_PATH, &utils::api_key_json(api_key), filen_settings)
        .await
        .context(UserDeleteAllQueryFailedSnafu {})
}

/// Calls `USER_RECENT_PATH` endpoint. Used to fetch recent files.
pub fn user_recent_request(api_key: &SecUtf8, filen_settings: &FilenSettings) -> Result<UserRecentResponsePayload> {
    queries::query_filen_api(USER_RECENT_PATH, &utils::api_key_json(api_key), filen_settings)
        .context(UserRecentQueryFailedSnafu {})
}

/// Calls `USER_RECENT_PATH` endpoint asynchronously. Used to fetch recent files.
#[cfg(feature = "async")]
pub async fn user_recent_request_async(
    api_key: &SecUtf8,
    filen_settings: &FilenSettings,
) -> Result<UserRecentResponsePayload> {
    queries::query_filen_api_async(USER_RECENT_PATH, &utils::api_key_json(api_key), filen_settings)
        .await
        .context(UserRecentQueryFailedSnafu {})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "async")]
    use crate::test_utils::validate_contract_async;
    use crate::{test_utils::validate_contract, v1::ParentOrBase};
    use once_cell::sync::Lazy;
    use secstr::SecUtf8;
    use std::str::FromStr;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"));
    // const NAME: &str = "test_folder";
    // const NAME_METADATA: &str = "U2FsdGVkX19d09wR+Ti+qMO7o8habxXkS501US7uv96+zbHHZwDDPbnq1di1z0/S";
    const NAME_HASHED: &str = "19d24c63b1170a0b1b40520a636a25235735f39f";

    #[test]
    fn file_exists_request_should_be_correctly_typed() {
        let request_payload = LocationExistsRequestPayload {
            api_key: &API_KEY,
            parent: ParentOrBase::from_str("b640414e-367e-4df6-b31a-030fd639bcff").unwrap(),
            name_hashed: NAME_HASHED.to_owned(),
        };
        validate_contract(
            FILE_EXISTS_PATH,
            request_payload,
            "tests/resources/responses/file_exists.json",
            |request_payload, filen_settings| file_exists_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn file_exists_request_async_should_be_correctly_typed() {
        let request_payload = LocationExistsRequestPayload {
            api_key: &API_KEY,
            parent: ParentOrBase::from_str("b640414e-367e-4df6-b31a-030fd639bcff").unwrap(),
            name_hashed: NAME_HASHED.to_owned(),
        };
        validate_contract_async(
            FILE_EXISTS_PATH,
            request_payload,
            "tests/resources/responses/file_exists.json",
            |request_payload, filen_settings| async move {
                file_exists_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn user_recent_request_should_be_correctly_typed() {
        let request_payload = utils::api_key_json(&API_KEY);
        validate_contract(
            USER_RECENT_PATH,
            request_payload,
            "tests/resources/responses/user_recent.json",
            |_, filen_settings| user_recent_request(&API_KEY, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn user_recent_request_async_should_be_correctly_typed() {
        let request_payload = utils::api_key_json(&API_KEY);
        validate_contract_async(
            USER_RECENT_PATH,
            request_payload,
            "tests/resources/responses/user_recent.json",
            |_, filen_settings| async move { user_recent_request_async(&API_KEY, &filen_settings).await },
        )
        .await;
    }
}
