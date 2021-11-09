use crate::{filen_settings::*, queries, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::*;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

const FILE_VERSIONS_PATH: &str = "/v1/file/versions";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("{} query failed: {}", FILE_VERSIONS_PATH, source))]
    FileVersionsQueryFailed { uuid: Uuid, source: queries::Error },
}

/// File version info.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileVersion {
    /// File ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// File metadata.
    pub metadata: String,

    /// Name of the Filen bucket where file data is stored.
    pub bucket: String,

    /// Name of the Filen region where file data is stored.
    pub region: String,

    /// Amount of chunks file is split into.
    pub chunks: u32,

    /// Random alphanumeric string associated with the file. Used for versioning.
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

api_response_struct!(
    /// Response for [FILE_VERSIONS_PATH] endpoint.
    FileVersionsResponsePayload<Option<FileVersionsResponseData>>
);

/// Calls [FILE_VERSIONS_PATH] endpoint. Used to get versions of the given file.
pub fn file_versions_request(
    payload: &FileVersionsRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<FileVersionsResponsePayload> {
    queries::query_filen_api(FILE_VERSIONS_PATH, payload, filen_settings)
        .context(FileVersionsQueryFailed { uuid: payload.uuid })
}

/// Calls [FILE_VERSIONS_PATH] endpoint asynchronously. Used to get versions of the given file.
#[cfg(feature = "async")]
pub async fn file_versions_request_async(
    payload: &FileVersionsRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<FileVersionsResponsePayload> {
    queries::query_filen_api_async(FILE_VERSIONS_PATH, payload, filen_settings)
        .await
        .context(FileVersionsQueryFailed { uuid: payload.uuid })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use once_cell::sync::Lazy;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"));

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
