use crate::{crypto, filen_settings::FilenSettings, queries, retry_settings::RetrySettings, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use std::io::Write;
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

const DOWNLOAD_DIR_PATH: &str = "/v1/download/dir";
const DOWNLOAD_DIR_SHARED_PATH: &str = "/v1/download/dir/shared";
const DOWNLOAD_DIR_LINK_PATH: &str = "/v1/download/dir/link";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to decrypt file mime metadata '{}': {}", metadata, source))]
    DecryptFileMimeMetadataFailed { metadata: String, source: crypto::Error },

    #[snafu(display("Failed to decrypt file name metadata '{}': {}", metadata, source))]
    DecryptFileNameMetadataFailed { metadata: String, source: crypto::Error },

    #[snafu(display("Failed to decrypt file size metadata '{}': {}", metadata, source))]
    DecryptFileSizeMetadataFailed { metadata: String, source: crypto::Error },

    #[snafu(display("Decrypted size '{}' was invalid: {}", size, source))]
    DecryptedSizeIsInvalid {
        size: String,
        source: std::num::ParseIntError,
    },

    #[snafu(display("download_and_decrypt_file call failed for data {}: {}", file_data, source))]
    DownloadAndDecryptFileFailed {
        file_data: Box<FileData>,
        source: download_file::Error,
    },

    #[snafu(display("{} query failed: {}", DOWNLOAD_DIR_LINK_PATH, source))]
    DownloadDirLinkQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", DOWNLOAD_DIR_SHARED_PATH, source))]
    DownloadDirSharedQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", DOWNLOAD_DIR_PATH, source))]
    DownloadDirQueryFailed { source: queries::Error },
}

/// Used for requests to [DOWNLOAD_DIR_LINK_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DownloadDirLinkRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Link ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Item ID; hyphenated lowercased UUID V4.
    pub parent: Uuid,

    /// Output of [crypto::derive_key_from_password_512] for link's password with 32 random bytes of salt;
    /// converted to a hex string.
    pub password: String,
}

api_response_struct!(
    /// Response for [DOWNLOAD_DIR_LINK_PATH] endpoint.
    DownloadDirLinkResponsePayload<Option<DownloadDirResponseData>>
);

/// Used for requests to [DOWNLOAD_DIR_SHARED_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DownloadDirSharedRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}

api_response_struct!(
    /// Response for [DOWNLOAD_DIR_SHARED_PATH] endpoint.
    DownloadDirSharedResponsePayload<Option<DownloadDirResponseData>>
);

/// Used for requests to [DOWNLOAD_DIR_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DownloadDirRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}

/// Response data for [DOWNLOAD_DIR_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DownloadDirResponseData {
    pub folders: Vec<FolderData>,

    pub files: Vec<FileData>,
}
utils::display_from_json!(DownloadDirResponseData);

impl DownloadDirResponseData {
    pub fn decrypt_all_folder_names(&self, master_keys: &[SecUtf8]) -> Result<Vec<(FolderData, String)>, FsError> {
        self.folders
            .iter()
            .map(|data| data.decrypt_name_metadata(master_keys).map(|name| (data.clone(), name)))
            .collect::<Result<Vec<_>, FsError>>()
    }

    pub fn decrypt_all_file_properties(
        &self,
        master_keys: &[SecUtf8],
    ) -> Result<Vec<(FileData, FileProperties)>, FsError> {
        self.files
            .iter()
            .map(|data| {
                data.decrypt_file_metadata(master_keys)
                    .map(|properties| (data.clone(), properties))
            })
            .collect::<Result<Vec<_>, FsError>>()
    }
}

/// Represents a file downloadable from Filen.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileData {
    /// File ID, UUID V4 in hyphenated lowercase format.
    pub uuid: Uuid,

    /// Name of the Filen bucket where file data is stored.
    pub bucket: String,

    /// Name of the Filen region where file data is stored.
    pub region: String,

    /// Metadata containing file name string.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Metadata containing file size as a string.
    #[serde(rename = "size")]
    pub size_metadata: String,

    /// Metadata containing file mime type or empty string.
    #[serde(rename = "mime")]
    pub mime_metadata: String,

    /// Amount of chunks the file is split into.
    pub chunks: u32,

    /// Parent folder ID, UUID V4 in hyphenated lowercase format.
    pub parent: Uuid,

    /// File metadata.
    pub metadata: String,

    /// Determines how file bytes should be encrypted/decrypted.
    /// File is encrypted using roughly the same algorithm as metadata encryption,
    /// use [crypto::encrypt_file_data] and [crypto::decrypt_file_data] for the task.
    pub version: u32,
}
utils::display_from_json!(FileData);

impl HasFileMetadata for FileData {
    fn file_metadata_ref(&self) -> &str {
        &self.metadata
    }
}

impl FileData {
    /// Decrypt name, size and mime metadata. File key is contained within file metadata in
    /// [DownloadedFileData::metadata] field, which can be decrypted with [DownloadedFileData::decrypt_file_metadata]
    /// call.
    pub fn decrypt_name_size_mime(&self, file_key: &SecUtf8) -> Result<FileNameSizeMime> {
        let name = crypto::decrypt_metadata_str(&self.name_metadata, file_key.unsecure()).context(
            DecryptFileNameMetadataFailed {
                metadata: self.name_metadata.clone(),
            },
        )?;
        let size_string = &crypto::decrypt_metadata_str(&self.size_metadata, file_key.unsecure()).context(
            DecryptFileSizeMetadataFailed {
                metadata: self.size_metadata.clone(),
            },
        )?;
        let size = str::parse::<u64>(size_string).context(DecryptedSizeIsInvalid { size: size_string })?;
        let mime = crypto::decrypt_metadata_str(&self.mime_metadata, file_key.unsecure()).context(
            DecryptFileMimeMetadataFailed {
                metadata: self.mime_metadata.clone(),
            },
        )?;
        Ok(FileNameSizeMime { name, size, mime })
    }

    pub fn get_file_location(&self) -> FileLocation {
        FileLocation::new(&self.region, &self.bucket, self.uuid, self.chunks)
    }

    /// Uses this file's properties to call [download_and_decrypt_file].
    pub fn download_and_decrypt_file<W: Write>(
        &self,
        file_key: &SecUtf8,
        retry_settings: &RetrySettings,
        filen_settings: &FilenSettings,
        writer: &mut std::io::BufWriter<W>,
    ) -> Result<u64> {
        download_and_decrypt_file(
            &self.get_file_location(),
            self.version,
            file_key,
            retry_settings,
            filen_settings,
            writer,
        )
        .context(DownloadAndDecryptFileFailed {
            file_data: self.clone(),
        })
    }

    /// Uses this file's properties to call [download_and_decrypt_file_async].
    #[cfg(feature = "async")]
    pub async fn download_and_decrypt_file_async<W: Write>(
        &self,
        file_key: &SecUtf8,
        retry_settings: &RetrySettings,
        filen_settings: &FilenSettings,
        writer: &mut std::io::BufWriter<W>,
    ) -> Result<u64> {
        download_and_decrypt_file_async(
            &self.get_file_location(),
            self.version,
            file_key,
            retry_settings,
            filen_settings,
            writer,
        )
        .await
        .context(DownloadAndDecryptFileFailed {
            file_data: self.clone(),
        })
    }
}

pub struct FileNameSizeMime {
    pub name: String,
    pub size: u64,
    pub mime: String,
}

api_response_struct!(
    /// Response for [DOWNLOAD_DIR_PATH] endpoint.
    DownloadDirResponsePayload<Option<DownloadDirResponseData>>
);

/// Calls [DOWNLOAD_DIR_LINK_PATH] endpoint.
pub fn download_dir_link_request(
    payload: &DownloadDirLinkRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DownloadDirLinkResponsePayload> {
    queries::query_filen_api(DOWNLOAD_DIR_LINK_PATH, payload, filen_settings).context(DownloadDirLinkQueryFailed {})
}

/// Calls [DOWNLOAD_DIR_LINK_PATH] endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn download_dir_link_request_async(
    payload: &DownloadDirLinkRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DownloadDirLinkResponsePayload> {
    queries::query_filen_api_async(DOWNLOAD_DIR_LINK_PATH, payload, filen_settings)
        .await
        .context(DownloadDirLinkQueryFailed {})
}

/// Calls [DOWNLOAD_DIR_SHARED_PATH] endpoint.
pub fn download_dir_shared_request(
    payload: &DownloadDirSharedRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DownloadDirSharedResponsePayload> {
    queries::query_filen_api(DOWNLOAD_DIR_SHARED_PATH, payload, filen_settings).context(DownloadDirSharedQueryFailed {})
}

/// Calls [DOWNLOAD_DIR_SHARED_PATH] endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn download_dir_shared_request_async(
    payload: &DownloadDirSharedRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DownloadDirSharedResponsePayload> {
    queries::query_filen_api_async(DOWNLOAD_DIR_SHARED_PATH, payload, filen_settings)
        .await
        .context(DownloadDirSharedQueryFailed {})
}

/// Calls [DOWNLOAD_DIR_PATH] endpoint. Used to get a list of user's folders and files.
///
/// Always includes Filen "Default" folder, and may possibly include special "Filen Sync" folder,
/// created by Filen's client.
pub fn download_dir_request(
    payload: &DownloadDirRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DownloadDirResponsePayload> {
    queries::query_filen_api(DOWNLOAD_DIR_PATH, payload, filen_settings).context(DownloadDirQueryFailed {})
}

/// Calls [DOWNLOAD_DIR_PATH] endpoint asynchronously. Used to get a list of user's folders and files.
///
/// Always includes Filen "Default" folder, and may possibly include special "Filen Sync" folder,
/// created by Filen's client.
#[cfg(feature = "async")]
pub async fn download_dir_request_async(
    payload: &DownloadDirRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DownloadDirResponsePayload> {
    queries::query_filen_api_async(DOWNLOAD_DIR_PATH, payload, filen_settings)
        .await
        .context(DownloadDirQueryFailed {})
}

#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;
    use secstr::SecUtf8;

    use crate::test_utils::*;

    use super::*;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA0RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM10CDnklpFq6"));

    #[test]
    fn download_dir_request_should_be_correctly_typed() {
        let request_payload = DownloadDirRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::parse_str("cf2af9a0-6f4e-485d-862c-0459f4662cf1").unwrap(),
        };
        validate_contract(
            DOWNLOAD_DIR_PATH,
            request_payload,
            "tests/resources/responses/download_dir.json",
            |request_payload, filen_settings| download_dir_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn download_dir_request_async_should_be_correctly_typed() {
        let request_payload = DownloadDirRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::parse_str("cf2af9a0-6f4e-485d-862c-0459f4662cf1").unwrap(),
        };
        validate_contract_async(
            DOWNLOAD_DIR_PATH,
            request_payload,
            "tests/resources/responses/download_dir.json",
            |request_payload, filen_settings| async move {
                download_dir_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn download_dir_response_data_file_should_be_correctly_decrypted() {
        let m_key = SecUtf8::from("ed8d39b6c2d00ece398199a3e83988f1c4942b24");
        let download_dir_response: DownloadDirResponsePayload =
            deserialize_from_file("tests/resources/responses/download_dir.json");
        let data = download_dir_response.data.unwrap();
        let test_file = data.files.get(0).unwrap();

        let test_file_metadata_result = test_file.decrypt_file_metadata(&[m_key]);
        let test_file_metadata = test_file_metadata_result.unwrap();
        assert_eq!(test_file_metadata.key.unsecure(), "sh1YRHfx22Ij40tQBbt6BgpBlqkzch8Y");
        assert_eq!(test_file_metadata.last_modified, 1383742218);
        assert_eq!(test_file_metadata.mime, "image/png");
        assert_eq!(test_file_metadata.name, "lina.png");
        assert_eq!(test_file_metadata.size, 133641);

        let test_file_name_size_mime_result = test_file.decrypt_name_size_mime(&test_file_metadata.key);
        let test_file_name_size_mime = test_file_name_size_mime_result.unwrap();
        assert_eq!(test_file_name_size_mime.mime, test_file_metadata.mime);
        assert_eq!(test_file_name_size_mime.name, test_file_metadata.name);
        assert_eq!(test_file_name_size_mime.size, test_file_metadata.size);
    }
}
