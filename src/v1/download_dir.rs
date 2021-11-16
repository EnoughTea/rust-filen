use crate::{crypto, filen_settings::FilenSettings, queries, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

const DOWNLOAD_DIR_PATH: &str = "/v1/download/dir";
const DOWNLOAD_DIR_LINK_PATH: &str = "/v1/download/dir/link";
const DOWNLOAD_DIR_SHARED_PATH: &str = "/v1/download/dir/shared";

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
    
    #[snafu(display("Download and decrypt operation failed for linked file {}: {}", file_data, source))]
    DownloadAndDecryptLinkedFileFailed {
        file_data: Box<LinkedFileData>,
        source: download_file::Error,
    },

    #[snafu(display("Download and decrypt operation failed for shared file {}: {}", file_data, source))]
    DownloadAndDecryptSharedFileFailed {
        file_data: Box<SharedFileData>,
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
    /// Folder link ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Folder ID; hyphenated lowercased UUID V4.
    pub parent: Uuid,

    /// Folder link password.
    /// 
    /// Link's password can be read from link status queries.
    pub password: String,
}

/// Represents one of the linked folders.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct LinkedFolderData {
    /// Folder ID, UUID V4 in hyphenated lowercase format.
    pub uuid: Uuid,

    /// Metadata containing folder name; encrypted using user's public key, so use user's private key for decrypt.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Either parent folder ID (hyphenated lowercased UUID V4) or "base" when folder is located in the base folder,
    /// also known as 'cloud drive'.
    pub parent: ParentOrBase,
}
utils::display_from_json!(LinkedFolderData);

impl HasLinkedLocationName for LinkedFolderData {
    /// Decrypts name metadata into a folder name.
    fn name_metadata_ref(&self) -> &str {
        &self.name_metadata
    }
}

/// Represents a linked file downloadable from Filen.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct LinkedFileData {
    /// File ID, UUID V4 in hyphenated lowercase format.
    pub uuid: Uuid,

    /// Filen file storage info.
    #[serde(flatten)]
    pub storage: FileStorageInfo,

    /// Parent folder ID, UUID V4 in hyphenated lowercase format.
    pub parent: Uuid,

    /// File metadata.
    pub metadata: String,

    /// Determines how file bytes should be encrypted/decrypted.
    /// File is encrypted using roughly the same algorithm as metadata encryption,
    /// use [crypto::encrypt_file_data] and [crypto::decrypt_file_data] for the task.
    pub version: u32,
}
utils::display_from_json!(LinkedFileData);

impl HasLinkedFileMetadata for LinkedFileData {
    fn file_metadata_ref(&self) -> &str {
        &self.metadata
    }
}

impl HasFileLocation for LinkedFileData {
    fn file_storage_ref(&self) -> &FileStorageInfo {
        &self.storage
    }
}

impl HasUuid for LinkedFileData {
    fn uuid_ref(&self) -> &Uuid {
        &self.uuid
    }
}

impl LinkedFileData {
    gen_download_and_decrypt_file!();
}

macro_rules! gen_download_and_decrypt_file {
    (
        
    ) => {
        /// Uses this file's properties to call [download_and_decrypt_file].
        pub fn download_and_decrypt_file<W: std::io::Write>(
            &self,
            file_key: &secstr::SecUtf8,
            retry_settings: &crate::RetrySettings,
            filen_settings: &crate::FilenSettings,
            writer: &mut std::io::BufWriter<W>,
        ) -> Result<u64, crate::v1::download_file::Error> {
            download_and_decrypt_file(
                &self.get_file_location(),
                self.version,
                file_key,
                writer,
                retry_settings,
                filen_settings,
            )
        }

        /// Uses this file's properties to call [download_and_decrypt_file_async].
        #[cfg(feature = "async")]
        pub async fn download_and_decrypt_file_async<W: std::io::Write + Send>(
            &self,
            file_key: &secstr::SecUtf8,
            retry_settings: &crate::RetrySettings,
            filen_settings: &crate::FilenSettings,
            writer: &mut std::io::BufWriter<W>,
        ) -> Result<u64, crate::v1::download_file::Error> {
            download_and_decrypt_file_async(
                &self.get_file_location(),
                self.version,
                file_key,
                writer,
                retry_settings,
                filen_settings,
            )
            .await
        }
    };
}
pub(crate) use gen_download_and_decrypt_file;

/// Response data for [DOWNLOAD_DIR_LINK_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct DownloadDirLinkResponseData {
    pub folders: Vec<LinkedFolderData>,

    pub files: Vec<LinkedFileData>,
}
utils::display_from_json!(DownloadDirLinkResponseData);

response_payload!(
    /// Response for [DOWNLOAD_DIR_LINK_PATH] endpoint.
    DownloadDirLinkResponsePayload<DownloadDirLinkResponseData>
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

/// Represents one of the shared folders.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct SharedFolderData {
    /// Folder ID, UUID V4 in hyphenated lowercase format.
    pub uuid: Uuid,

    /// Metadata containing folder name; encrypted using user's public key, so use user's private key for decrypt.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Either parent folder ID (hyphenated lowercased UUID V4) or "base" when folder is located in the base folder,
    /// also known as 'cloud drive'.
    pub parent: ParentOrBase,
}
utils::display_from_json!(SharedFolderData);

impl HasSharedLocationName for SharedFolderData {
    /// Decrypts name metadata into a folder name.
    fn name_metadata_ref(&self) -> &str {
        &self.name_metadata
    }
}

/// Represents a shared file downloadable from Filen.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct SharedFileData {
    /// File ID, UUID V4 in hyphenated lowercase format.
    pub uuid: Uuid,

    /// Filen file storage info.
    #[serde(flatten)]
    pub storage: FileStorageInfo,

    /// Parent folder ID, UUID V4 in hyphenated lowercase format.
    pub parent: Uuid,

    /// File metadata.
    pub metadata: String,

    /// Determines how file bytes should be encrypted/decrypted.
    /// File is encrypted using roughly the same algorithm as metadata encryption,
    /// use [crypto::encrypt_file_data] and [crypto::decrypt_file_data] for the task.
    pub version: u32,
}
utils::display_from_json!(SharedFileData);

impl HasSharedFileMetadata for SharedFileData {
    fn file_metadata_ref(&self) -> &str {
        &self.metadata
    }
}

impl HasFileLocation for SharedFileData {
    fn file_storage_ref(&self) -> &FileStorageInfo {
        &self.storage
    }
}

impl HasUuid for SharedFileData {
    fn uuid_ref(&self) -> &Uuid {
        &self.uuid
    }
}

impl SharedFileData {
    gen_download_and_decrypt_file!();
}

/// Response data for [DOWNLOAD_DIR_SHARED_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct DownloadDirSharedResponseData {
    pub folders: Vec<SharedFolderData>,

    pub files: Vec<SharedFileData>,
}
utils::display_from_json!(DownloadDirSharedResponseData);

response_payload!(
    /// Response for [DOWNLOAD_DIR_SHARED_PATH] endpoint.
    DownloadDirSharedResponsePayload<DownloadDirSharedResponseData>
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
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct DownloadDirResponseData {
    pub folders: Vec<FolderData>,

    pub files: Vec<FileData>,
}
utils::display_from_json!(DownloadDirResponseData);

impl HasFiles<FileData> for DownloadDirResponseData {
    fn files_ref(&self) -> &[FileData] {
        &self.files
    }
}

impl HasFolders<FolderData> for DownloadDirResponseData {
    fn folders_ref(&self) -> &[FolderData] {
        &self.folders
    }
}

/// Represents a file downloadable from Filen.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FileData {
    /// File ID, UUID V4 in hyphenated lowercase format.
    pub uuid: Uuid,

    /// Filen file storage info.
    #[serde(flatten)]
    pub storage: FileStorageInfo,

    /// Metadata containing file name string.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Metadata containing file size as a string.
    #[serde(rename = "size")]
    pub size_metadata: String,

    /// Metadata containing file mime type or empty string.
    #[serde(rename = "mime")]
    pub mime_metadata: String,

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

impl HasFileLocation for FileData {
    fn file_storage_ref(&self) -> &FileStorageInfo {
        &self.storage
    }
}

impl HasUuid for FileData {
    fn uuid_ref(&self) -> &Uuid {
        &self.uuid
    }
}

impl FileData {
    /// Decrypt name, size and mime metadata. File key is contained within file metadata in
    /// [DownloadedFileData::metadata] field, which can be decrypted with [DownloadedFileData::decrypt_file_metadata]
    /// call.
    pub fn decrypt_name_size_mime(&self, file_key: &SecUtf8) -> Result<FileNameSizeMime> {
        let name =
            crypto::decrypt_metadata_str(&self.name_metadata, file_key).context(DecryptFileNameMetadataFailed {
                metadata: self.name_metadata.clone(),
            })?;
        let size_string =
            &crypto::decrypt_metadata_str(&self.size_metadata, file_key).context(DecryptFileSizeMetadataFailed {
                metadata: self.size_metadata.clone(),
            })?;
        let size = str::parse::<u64>(size_string).context(DecryptedSizeIsInvalid { size: size_string })?;
        let mime =
            crypto::decrypt_metadata_str(&self.mime_metadata, file_key).context(DecryptFileMimeMetadataFailed {
                metadata: self.mime_metadata.clone(),
            })?;
        Ok(FileNameSizeMime { name, size, mime })
    }

    gen_download_and_decrypt_file!();
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FileNameSizeMime {
    pub name: String,
    pub size: u64,
    pub mime: String,
}
utils::display_from_json!(FileNameSizeMime);

response_payload!(
    /// Response for [DOWNLOAD_DIR_PATH] endpoint.
    DownloadDirResponsePayload<DownloadDirResponseData>
);

/// Calls [DOWNLOAD_DIR_LINK_PATH] endpoint. Used to check contents of a linked folder.
///
/// Link UUID and password can be found out with [dir_link_status_request] using folder UUID.
pub fn download_dir_link_request(
    payload: &DownloadDirLinkRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DownloadDirLinkResponsePayload> {
    queries::query_filen_api(DOWNLOAD_DIR_LINK_PATH, payload, filen_settings).context(DownloadDirLinkQueryFailed {})
}

/// Calls [DOWNLOAD_DIR_LINK_PATH] endpoint asynchronously. Used to check contents of a linked folder.
///
/// Link UUID and password can be found out with [dir_link_status_request] using folder UUID.
#[cfg(feature = "async")]
pub async fn download_dir_link_request_async(
    payload: &DownloadDirLinkRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DownloadDirLinkResponsePayload> {
    queries::query_filen_api_async(DOWNLOAD_DIR_LINK_PATH, payload, filen_settings)
        .await
        .context(DownloadDirLinkQueryFailed {})
}

/// Calls [DOWNLOAD_DIR_SHARED_PATH] endpoint. Used to check contents of a 'received' folder:
/// folder someone shared with a user.
pub fn download_dir_shared_request(
    payload: &DownloadDirSharedRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DownloadDirSharedResponsePayload> {
    queries::query_filen_api(DOWNLOAD_DIR_SHARED_PATH, payload, filen_settings).context(DownloadDirSharedQueryFailed {})
}

/// Calls [DOWNLOAD_DIR_SHARED_PATH] endpoint asynchronously. Used to check contents of a 'received' folder:
/// folder someone shared with a user.
#[cfg(feature = "async")]
pub async fn download_dir_shared_request_async(
    payload: &DownloadDirSharedRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DownloadDirSharedResponsePayload> {
    queries::query_filen_api_async(DOWNLOAD_DIR_SHARED_PATH, payload, filen_settings)
        .await
        .context(DownloadDirSharedQueryFailed {})
}

/// Calls [DOWNLOAD_DIR_PATH] endpoint. Used to get a user's folder with given ID and its sub-folders and files.
/// 
/// For shared folders use [download_dir_shared_request], and for linked folders use [download_dir_link_request].
pub fn download_dir_request(
    payload: &DownloadDirRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DownloadDirResponsePayload> {
    queries::query_filen_api(DOWNLOAD_DIR_PATH, payload, filen_settings).context(DownloadDirQueryFailed {})
}

/// Calls [DOWNLOAD_DIR_PATH] endpoint asynchronously. 
/// Used to get a user's folder with given ID and its sub-folders and files.
/// 
/// For shared folders use [download_dir_shared_request_async],
/// and for linked folders use [download_dir_link_request_async].
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
    use super::*;
    use crate::test_utils::*;
    use once_cell::sync::Lazy;
    use secstr::SecUtf8;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA0RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM10CDnklpFq6"));

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
    fn download_dir_link_request_should_be_correctly_typed() {
        let request_payload = DownloadDirLinkRequestPayload {
            uuid: Uuid::parse_str("5c86494b-36ec-4d39-a839-9f391474ad00").unwrap(),
            parent: Uuid::parse_str("b013e93f-4c9b-4df3-a6de-093d95f13c57").unwrap(),
            password: "4366faac2229d73a206dcc4384e4a560be054f69d8e9ecc307d7d1701c90b3d59/
            dd56676f7593a464d72755501462287393cc91a6c575eade9fa50ecafd4142d"
                .to_owned(),
        };
        validate_contract(
            DOWNLOAD_DIR_LINK_PATH,
            request_payload,
            "tests/resources/responses/download_dir_link.json",
            |request_payload, filen_settings| download_dir_link_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn download_dir_link_request_async_should_be_correctly_typed() {
        let request_payload = DownloadDirLinkRequestPayload {
            uuid: Uuid::parse_str("5c86494b-36ec-4d39-a839-9f391474ad00").unwrap(),
            parent: Uuid::parse_str("b013e93f-4c9b-4df3-a6de-093d95f13c57").unwrap(),
            password: "4366faac2229d73a206dcc4384e4a560be054f69d8e9ecc307d7d1701c90b3d59/
            dd56676f7593a464d72755501462287393cc91a6c575eade9fa50ecafd4142d"
                .to_owned(),
        };
        validate_contract_async(
            DOWNLOAD_DIR_LINK_PATH,
            request_payload,
            "tests/resources/responses/download_dir_link.json",
            |request_payload, filen_settings| async move {
                download_dir_link_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn download_dir_shared_request_should_be_correctly_typed() {
        let request_payload = DownloadDirSharedRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::parse_str("5c86494b-36ec-4d39-a839-9f391474ad00").unwrap(),
        };
        validate_contract(
            DOWNLOAD_DIR_SHARED_PATH,
            request_payload,
            "tests/resources/responses/download_dir_shared.json",
            |request_payload, filen_settings| download_dir_shared_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn download_dir_shared_request_async_should_be_correctly_typed() {
        let request_payload = DownloadDirSharedRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::parse_str("5c86494b-36ec-4d39-a839-9f391474ad00").unwrap(),
        };
        validate_contract_async(
            DOWNLOAD_DIR_SHARED_PATH,
            request_payload,
            "tests/resources/responses/download_dir_shared.json",
            |request_payload, filen_settings| async move {
                download_dir_shared_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }
}
