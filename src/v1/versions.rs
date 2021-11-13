use crate::{filen_settings::*, queries, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

const FILE_ARCHIVE_RESTORE_PATH: &str = "/v1/file/archive/restore";
const FILE_VERSIONS_PATH: &str = "/v1/file/versions";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("{} query failed: {}", FILE_ARCHIVE_RESTORE_PATH, source))]
    FileArchiveRestoreQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", FILE_VERSIONS_PATH, source))]
    FileVersionsQueryFailed { source: queries::Error },
}

/// Used for requests to [FILE_ARCHIVE_RESTORE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileArchiveRestoreRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Archived file ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Current file ID; hyphenated lowercased UUID V4.
    #[serde(rename = "currentUUID")]
    pub current_uuid: Uuid,
}
utils::display_from_json!(FileArchiveRestoreRequestPayload);

/// Response data for [FILE_ARCHIVE_RESTORE_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileArchiveRestoreResponseData {
    /// Archived file ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Current file ID; hyphenated lowercased UUID V4.
    #[serde(rename = "currentUUID")]
    pub current_uuid: Uuid,

    /// File metadata.
    pub metadata: String,

    /// Filen file storage info.
    #[serde(flatten)]
    pub storage: FileStorageInfo,

    /// Parent folder ID; hyphenated lowercased UUID V4.
    pub parent: Uuid,

    /// Random alphanumeric string associated with the file. Used for deleting and versioning.
    pub rm: String,

    /// File creation time, as Unix timestamp in seconds.
    pub timestamp: u64,

    /// Determines how file bytes should be encrypted/decrypted.
    /// File is encrypted using roughly the same algorithm as metadata encryption,
    /// use [crypto::encrypt_file_data] and [crypto::decrypt_file_data] for the task.
    pub version: u32,

    /// true if user has marked file as favorite; false otherwise.
    #[serde(deserialize_with = "bool_from_int", serialize_with = "bool_to_int")]
    pub favorited: bool,
}
utils::display_from_json!(FileArchiveRestoreResponseData);

response_payload!(
    /// Response for [FILE_ARCHIVE_RESTORE_PATH] endpoint.
    FileArchiveRestoreResponsePayload<FileArchiveRestoreResponseData>
);

/// File version info.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileVersion {
    /// File ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// File metadata.
    pub metadata: String,

    /// Filen file storage info.
    #[serde(flatten)]
    pub storage: FileStorageInfo,

    /// Random alphanumeric string associated with the file. Used for deleting and versioning.
    pub rm: String,

    /// File creation time, as Unix timestamp in seconds.
    pub timestamp: u64,

    /// Determines how file bytes should be encrypted/decrypted.
    /// File is encrypted using roughly the same algorithm as metadata encryption,
    /// use [crypto::encrypt_file_data] and [crypto::decrypt_file_data] for the task.
    pub version: u32,
}

/// Used for requests to [FILE_VERSIONS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileVersionsRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// File ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(FileVersionsRequestPayload);

/// Response data for [FILE_VERSIONS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileVersionsResponseData {
    /// Found versions.
    #[serde(default)]
    pub links: Vec<FileVersion>,
}
utils::display_from_json!(FileVersionsResponseData);

response_payload!(
    /// Response for [FILE_VERSIONS_PATH] endpoint.
    FileVersionsResponsePayload<FileVersionsResponseData>
);

/// Calls [FILE_ARCHIVE_RESTORE_PATH] endpoint. Used to get versions of the given file.
pub fn file_archive_restore_request(
    payload: &FileArchiveRestoreRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<FileArchiveRestoreResponsePayload> {
    queries::query_filen_api(FILE_ARCHIVE_RESTORE_PATH, payload, filen_settings)
        .context(FileArchiveRestoreQueryFailed {})
}

/// Calls [FILE_ARCHIVE_RESTORE_PATH] endpoint asynchronously. Used to get versions of the given file.
#[cfg(feature = "async")]
pub async fn file_archive_restore_request_async(
    payload: &FileArchiveRestoreRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<FileArchiveRestoreResponsePayload> {
    queries::query_filen_api_async(FILE_ARCHIVE_RESTORE_PATH, payload, filen_settings)
        .await
        .context(FileArchiveRestoreQueryFailed {})
}

/// Calls [FILE_VERSIONS_PATH] endpoint. Used to get versions of the given file.
pub fn file_versions_request(
    payload: &FileVersionsRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<FileVersionsResponsePayload> {
    queries::query_filen_api(FILE_VERSIONS_PATH, payload, filen_settings).context(FileVersionsQueryFailed {})
}

/// Calls [FILE_VERSIONS_PATH] endpoint asynchronously. Used to get versions of the given file.
#[cfg(feature = "async")]
pub async fn file_versions_request_async(
    payload: &FileVersionsRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<FileVersionsResponsePayload> {
    queries::query_filen_api_async(FILE_VERSIONS_PATH, payload, filen_settings)
        .await
        .context(FileVersionsQueryFailed {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use once_cell::sync::Lazy;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"));

    #[test]
    fn file_archive_restore_request_should_be_correctly_typed() {
        let request_payload = FileArchiveRestoreRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::parse_str("b5ec90d2-957c-4481-b211-08a68accd1b2").unwrap(),
            current_uuid: Uuid::parse_str("0d9e14cd-69be-4f44-8390-b493eaba3468").unwrap(),
        };
        validate_contract(
            FILE_ARCHIVE_RESTORE_PATH,
            request_payload,
            "tests/resources/responses/file_archive_restore.json",
            |request_payload, filen_settings| file_archive_restore_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn file_archive_restore_request_async_should_be_correctly_typed() {
        let request_payload = FileArchiveRestoreRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::parse_str("b5ec90d2-957c-4481-b211-08a68accd1b2").unwrap(),
            current_uuid: Uuid::parse_str("0d9e14cd-69be-4f44-8390-b493eaba3468").unwrap(),
        };
        validate_contract_async(
            FILE_ARCHIVE_RESTORE_PATH,
            request_payload,
            "tests/resources/responses/file_archive_restore.json",
            |request_payload, filen_settings| async move {
                file_archive_restore_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn file_versions_request_should_be_correctly_typed() {
        let request_payload = FileVersionsRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::parse_str("b5ec90d2-957c-4481-b211-08a68accd1b2").unwrap(),
        };
        validate_contract(
            FILE_VERSIONS_PATH,
            request_payload,
            "tests/resources/responses/file_versions.json",
            |request_payload, filen_settings| file_versions_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn file_versions_request_async_should_be_correctly_typed() {
        let request_payload = FileVersionsRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::parse_str("b5ec90d2-957c-4481-b211-08a68accd1b2").unwrap(),
        };
        validate_contract_async(
            FILE_VERSIONS_PATH,
            request_payload,
            "tests/resources/responses/file_versions.json",
            |request_payload, filen_settings| async move {
                file_versions_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }
}
