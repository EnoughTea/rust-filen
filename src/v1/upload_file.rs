use std::{
    cmp::*,
    convert::TryInto,
    io::{BufReader, Read, Seek, SeekFrom},
};

use crate::{
    crypto,
    file_chunk_pos::{FileChunkPosition, FileChunkPositions},
    filen_settings::FilenSettings,
    queries,
    retry_settings::RetrySettings,
    utils,
    v1::*,
};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use snafu::{Backtrace, ResultExt, Snafu};
use url::Url;
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

const FILE_CHUNK_SIZE: u32 = 1024 * 1024; // Hardcoded mostly because Filen has hardcoded chunk size as well
const UPLOAD_PATH: &str = "/v1/upload";
const UPLOAD_DONE_PATH: &str = "/v1/upload/done";
const UPLOAD_STOP_PATH: &str = "/v1/upload/stop";
const USER_UNFINISHED_DELETE_PATH: &str = "/v1/user/unfinished/delete";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display(
        "Chunk of size '{}' encryption failed, file key size was '{}' and file version was '{}'",
        chunk_size,
        file_key_size,
        file_version,
    ))]
    ChunkEncryptionError {
        chunk_size: usize,
        file_key_size: usize,
        file_version: u32,
        source: crypto::Error,
    },

    #[snafu(display("Filen did not accept at least one uploaded file chunk: {}", reason))]
    ChunkNotAccepted { reason: String, backtrace: Backtrace },

    #[snafu(display(
        "Not all uploaded chunks with status == true actually had data: {}",
        file_upload_info
    ))]
    ChunkUploadResponseMissingData { file_upload_info: Box<FileUploadInfo> },

    #[snafu(display("Filen did not accept uploaded dummy chunk: {}", reason))]
    DummyChunkNotAccepted { reason: String, backtrace: Backtrace },

    #[snafu(display("Cannot read file chunks due to IO error: {}", source))]
    SeekReadError { source: std::io::Error },

    #[snafu(display("{} ({} bytes) query failed: {}", api_endpoint, chunk_size, source))]
    UploadQueryFailed {
        api_endpoint: String,
        chunk_size: usize,
        source: queries::Error,
    },

    #[snafu(display("{} query failed: {}", UPLOAD_DONE_PATH, source))]
    UploadDoneQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", UPLOAD_STOP_PATH, source))]
    UploadStopQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_UNFINISHED_DELETE_PATH, source))]
    UserUnfinishedDeleteQueryFailed { source: queries::Error },
}

/// Response data for [UPLOAD_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UploadFileChunkResponseData {
    /// Server's bucket where file is stored.
    pub bucket: String,

    /// Server region.
    pub region: String,

    /// 1 if expire was set when uploading chunk; 0 otherwise.
    #[serde(
        rename = "expireSet",
        deserialize_with = "bool_from_int",
        serialize_with = "bool_to_int"
    )]
    pub expire_set: bool,

    /// Timestanp when chunk will be considired expired.
    #[serde(rename = "expireTimestamp")]
    pub expire_timestamp: u64,

    /// Timestanp when chunk will be deleted.
    #[serde(rename = "deleteTimestamp")]
    pub delete_timestamp: u64,
}
response_payload!(
    /// Response for [UPLOAD_PATH] endpoint.
    UploadFileChunkResponsePayload<UploadFileChunkResponseData>
);

/// Used for requests to [UPLOAD_DONE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UploadDoneRequestPayload {
    /// Uploaded file ID, UUID V4 in hyphenated lowercase format.
    pub uuid: Uuid,

    /// File upload key: random alphanumeric string associated with entire file upload.
    #[serde(rename = "uploadKey")]
    pub upload_key: String,
}
utils::display_from_json!(UploadDoneRequestPayload);

/// Used for requests to [UPLOAD_STOP_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UploadStopRequestPayload {
    /// Uploaded file ID, UUID V4 in hyphenated lowercase format.
    pub uuid: Uuid,

    /// File upload key: random alphanumeric string associated with entire file upload.
    #[serde(rename = "uploadKey")]
    pub upload_key: String,
}
utils::display_from_json!(UploadStopRequestPayload);

/// File properties needed to upload file to Filen.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileUploadProperties {
    /// File ID, UUID V4 in hyphenated lowercase format.
    pub uuid: Uuid,

    /// Metadata containing file name string.
    pub name_metadata: String,

    /// Contains hashed file name.
    pub name_hashed: String,

    /// Metadata containing file size as a string.
    pub size_metadata: String,

    /// File chunks count.
    pub chunks: u32,

    /// Metadata containing file mime type or empty string.
    pub mime_metadata: String,

    /// File metadata.
    pub file_metadata: String,

    /// Random alphanumeric key.
    pub file_key: SecUtf8,

    /// Random alphanumeric key associated with the file. Used for deleting and versioning.
    pub rm: String,

    /// Random alphanumeric key associated with entire file upload.
    pub upload_key: String,

    /// Expire marker. Always set to "never".
    pub expire: Expire,

    /// Parent folder ID, UUID V4 in hyphenated lowercase format.
    pub parent_uuid: Uuid,

    /// Determines how file bytes should be encrypted/decrypted.
    /// File is encrypted using roughly the same algorithm as metadata encryption,
    /// use [crypto::encrypt_file_data] and [crypto::decrypt_file_data] for the task.
    pub version: u32,
}

impl FileUploadProperties {
    /// Assigns file upload properties from given [FileProperties], parent folder and user's last master key.
    /// 'version' determines how file bytes should be encrypted/decrypted, for now Filen uses version = 1 everywhere.
    pub fn from_file_properties(
        file_properties: &FileProperties,
        version: u32,
        parent_folder_uuid: Uuid,
        last_master_key: &SecUtf8,
    ) -> FileUploadProperties {
        let rm = utils::random_alphanumeric_string(32);
        let upload_key = utils::random_alphanumeric_string(32);

        let file_metadata_encrypted = file_properties.to_metadata_string(last_master_key);
        let name_metadata_encrypted = file_properties.name_encrypted();
        let size_metadata_encrypted = file_properties.size_encrypted();
        let mime_metadata_encrypted = file_properties.mime_encrypted();
        let name_hashed = LocationNameMetadata::name_hashed(&file_properties.name);

        let file_chunks = calculate_chunk_count(FILE_CHUNK_SIZE, file_properties.size);
        FileUploadProperties {
            uuid: Uuid::new_v4(),
            name_metadata: name_metadata_encrypted,
            name_hashed,
            size_metadata: size_metadata_encrypted,
            chunks: file_chunks,
            mime_metadata: mime_metadata_encrypted,
            file_metadata: file_metadata_encrypted,
            file_key: file_properties.key.clone(),
            rm,
            upload_key,
            expire: Expire::Never,
            parent_uuid: parent_folder_uuid,
            version,
        }
    }

    /// Produces percent-encoded string of query parameters for Filen upload endpoint, using this properties.
    pub fn to_query_params(&self, chunk_index: u32, api_key: &SecUtf8) -> String {
        let query_builder = Url::parse_with_params(
            "https://localhost?",
            &[
                ("apiKey", api_key.unsecure()),
                ("uuid", &self.uuid.to_hyphenated().to_string()),
                ("name", &self.name_metadata),
                ("nameHashed", &self.name_hashed),
                ("size", &self.size_metadata),
                ("chunks", &self.chunks.to_string()),
                ("mime", &self.mime_metadata),
                ("index", &chunk_index.to_string()),
                ("rm", &self.rm),
                ("expire", &self.expire.to_string()),
                ("uploadKey", &self.upload_key),
                ("metaData", &self.file_metadata),
                ("parent", &self.parent_uuid.to_hyphenated().to_string()),
                ("version", &self.version.to_string()),
            ],
        )
        .unwrap();
        query_builder.query().unwrap().to_owned()
    }

    /// Produces API endpoint for file upload using this properties.
    pub fn to_api_endpoint(&self, chunk_index: u32, api_key: &SecUtf8) -> String {
        format!("{}?{}", UPLOAD_PATH, self.to_query_params(chunk_index, api_key))
    }
}
utils::display_from_json!(FileUploadProperties);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileUploadInfo {
    pub properties: FileUploadProperties,
    pub mark_done_response: PlainResponsePayload,
    pub chunk_responses: Vec<UploadFileChunkResponsePayload>,
}

impl FileUploadInfo {
    pub fn new(
        upload_properties: FileUploadProperties,
        mark_done_response: PlainResponsePayload,
        chunk_responses: Vec<UploadFileChunkResponsePayload>,
    ) -> FileUploadInfo {
        FileUploadInfo {
            properties: upload_properties,
            mark_done_response,
            chunk_responses,
        }
    }

    pub fn is_uploaded_successfully(&self) -> bool {
        self.mark_done_response.status
    }

    /// Retrieves uploaded file chunks locations, taking them from [FileUploadInfo::chunk_responses].
    pub fn get_file_chunk_locations(&self) -> Result<Vec<FileChunkLocation>> {
        let chunk_datas = self
            .chunk_responses
            .iter()
            .map(|chunk_response| chunk_response.data.clone())
            .flatten()
            .enumerate();

        let locations = chunk_datas
            .map(|(index, data)| FileChunkLocation {
                region: data.region,
                bucket: data.bucket,
                file_uuid: self.properties.uuid,
                chunk_index: index as u32,
            })
            .collect::<Vec<FileChunkLocation>>();

        // Sanity check that Filen did not return chunk's upload status == true without any data.
        if locations.len() == self.chunk_responses.len() {
            Ok(locations)
        } else {
            ChunkUploadResponseMissingData {
                file_upload_info: self.clone(),
            }
            .fail()
        }
    }
}
utils::display_from_json!(FileUploadInfo);

/// Calls [UPLOAD_DONE_PATH] endpoint. Used to mark upload as done after all file chunks (+1 dummy chunk) were uploaded.
pub fn upload_done_request(
    payload: &UploadDoneRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(UPLOAD_DONE_PATH, payload, filen_settings).context(UploadDoneQueryFailed {})
}

/// Calls [UPLOAD_DONE_PATH] endpoint asynchronously. Used to mark upload as done after all file chunks
/// (+1 dummy chunk) were uploaded.
#[cfg(feature = "async")]
pub async fn upload_done_request_async(
    payload: &UploadDoneRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(UPLOAD_DONE_PATH, payload, filen_settings)
        .await
        .context(UploadDoneQueryFailed {})
}

/// Calls [UPLOAD_STOP_PATH] endpoint.
/// Theoretically, can be used to stop upload in progress, but Filen never uses it.
pub fn upload_stop_request(
    payload: &UploadStopRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(UPLOAD_STOP_PATH, payload, filen_settings).context(UploadStopQueryFailed {})
}

/// Calls [UPLOAD_STOP_PATH] endpoint asynchronously.
/// Theoretically, can be used to stop upload in progress, but Filen never uses it.
#[cfg(feature = "async")]
pub async fn upload_stop_request_async(
    payload: &UploadStopRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(UPLOAD_STOP_PATH, payload, filen_settings)
        .await
        .context(UploadStopQueryFailed {})
}

/// Calls [UPLOAD_PATH] endpoint. Used to encrypt and upload a file chunk to Filen.
/// After uploading all file chunks, upload additional empty chunk with incremented chunk index.
/// That way Filen knows that file uploading is complete, and 'upload done' call for file's upload key will succeed.
pub fn encrypt_and_upload_chunk(
    api_key: &SecUtf8,
    chunk_index: u32,
    chunk: &[u8],
    upload_properties: &FileUploadProperties,
    filen_settings: &FilenSettings,
) -> Result<UploadFileChunkResponsePayload> {
    let file_key = upload_properties.file_key.unsecure().as_bytes().try_into().unwrap();
    let chunk_encrypted =
        crypto::encrypt_file_chunk(chunk, file_key, upload_properties.version).context(ChunkEncryptionError {
            chunk_size: chunk.len(),
            file_key_size: file_key.len(),
            file_version: upload_properties.version,
        })?;
    let chunk_size = chunk_encrypted.len();
    let api_endpoint = upload_properties.to_api_endpoint(chunk_index, api_key);
    queries::upload_to_filen::<UploadFileChunkResponsePayload>(
        &api_endpoint,
        chunk_encrypted.into_bytes(),
        filen_settings,
    )
    .context(UploadQueryFailed {
        api_endpoint,
        chunk_size,
    })
}

/// Calls [UPLOAD_PATH] endpoint asynchronously. Used to encrypt and upload a file chunk to Filen.
/// After uploading all file chunks, upload additional empty chunk with incremented chunk index.
/// That way Filen knows that file uploading is complete, and 'upload done' call for file's upload key will succeed.
#[cfg(feature = "async")]
pub async fn encrypt_and_upload_chunk_async(
    api_key: &SecUtf8,
    chunk_index: u32,
    chunk: &[u8],
    upload_properties: &FileUploadProperties,
    filen_settings: &FilenSettings,
) -> Result<UploadFileChunkResponsePayload> {
    let file_key = upload_properties.file_key.unsecure().as_bytes().try_into().unwrap();
    let chunk_encrypted =
        crypto::encrypt_file_chunk(chunk, file_key, upload_properties.version).context(ChunkEncryptionError {
            chunk_size: chunk.len(),
            file_key_size: file_key.len(),
            file_version: upload_properties.version,
        })?;

    let chunk_size = chunk_encrypted.len();
    let api_endpoint = upload_properties.to_api_endpoint(chunk_index, api_key);
    queries::upload_to_filen_async::<UploadFileChunkResponsePayload>(
        &api_endpoint,
        chunk_encrypted.into_bytes(),
        filen_settings,
    )
    .await
    .context(UploadQueryFailed {
        api_endpoint,
        chunk_size,
    })
}

/// Calls [USER_UNFINISHED_DELETE_PATH] endpoint. Used to delete all unfinished file uploads.
pub fn user_unfinished_delete_request(
    api_key: &SecUtf8,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(
        USER_UNFINISHED_DELETE_PATH,
        &utils::api_key_json(api_key),
        filen_settings,
    )
    .context(UserUnfinishedDeleteQueryFailed {})
}

/// Calls [USER_UNFINISHED_DELETE_PATH] endpoint asynchronously. Used to delete all unfinished file uploads.
#[cfg(feature = "async")]
pub async fn user_unfinished_delete_request_async(
    api_key: &SecUtf8,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(
        USER_UNFINISHED_DELETE_PATH,
        &utils::api_key_json(api_key),
        filen_settings,
    )
    .await
    .context(UserUnfinishedDeleteQueryFailed {})
}

/// Uploads file to Filen by reading file chunks from given reader,
/// encrypting them and uploading each chunk with additional dummy chunk at the end.
///
/// 'version' determines how file bytes should be encrypted/decrypted, for now Filen uses version = 1 everywhere.
pub fn encrypt_and_upload_file<R: Read + Seek>(
    api_key: &SecUtf8,
    parent_uuid: Uuid,
    file_properties: &FileProperties,
    version: u32,
    last_master_key: &SecUtf8,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
    reader: &mut BufReader<R>,
) -> Result<FileUploadInfo> {
    let upload_properties =
        FileUploadProperties::from_file_properties(file_properties, version, parent_uuid, last_master_key);
    let chunk_upload_responses = upload_chunks(
        api_key,
        FILE_CHUNK_SIZE,
        file_properties.size,
        &upload_properties,
        retry_settings,
        filen_settings,
        reader,
    )?;

    let finalize_action = |chunk_upload_responses: Vec<UploadFileChunkResponsePayload>| {
        send_dummy_chunk(
            FILE_CHUNK_SIZE,
            file_properties.size,
            api_key,
            &upload_properties,
            retry_settings,
            filen_settings,
        )
        .and_then(|dummy_chunk_response| {
            if dummy_chunk_response.status {
                let upload_done_payload = UploadDoneRequestPayload {
                    uuid: upload_properties.uuid,
                    upload_key: upload_properties.upload_key.clone(),
                };
                let mark_done_response =
                    retry_settings.retry(|| upload_done_request(&upload_done_payload, filen_settings))?;
                Ok(FileUploadInfo::new(
                    upload_properties,
                    mark_done_response,
                    chunk_upload_responses,
                ))
            } else {
                DummyChunkNotAccepted {
                    reason: dummy_chunk_response
                        .message
                        .unwrap_or_else(|| "unknown reason".to_owned()),
                }
                .fail()
            }
        })
    };

    utils::flatten_result(finalize_chunks_if_all_uploaded(chunk_upload_responses, finalize_action))
}

/// Asynchronously uploads file to Filen by reading file chunks from given reader,
/// encrypting them and uploading each chunk with additional dummy chunk at the end.
///
/// 'version' determines how file bytes should be encrypted/decrypted, for now Filen uses version = 1 everywhere.
///
/// Note that file upload is explicitly retriable and always requires RetrySettings as an argument.
/// You can pass [crate::NO_RETRIES] if you really want to fail the entire file upload  even if a single chunk
/// upload request fails temporarily, otherwise [crate::STANDARD_RETRIES] is a better fit.
#[cfg(feature = "async")]
pub async fn encrypt_and_upload_file_async<R: Read + Seek>(
    api_key: &SecUtf8,
    parent_uuid: Uuid,
    file_properties: &FileProperties,
    version: u32,
    last_master_key: &SecUtf8,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
    reader: &mut BufReader<R>,
) -> Result<FileUploadInfo> {
    let upload_properties =
        FileUploadProperties::from_file_properties(file_properties, version, parent_uuid, last_master_key);
    let chunk_upload_responses = upload_chunks_async(
        api_key,
        FILE_CHUNK_SIZE,
        file_properties.size,
        &upload_properties,
        retry_settings,
        filen_settings,
        reader,
    )
    .await?;

    let finalize_action = |chunk_upload_responses: Vec<UploadFileChunkResponsePayload>| async {
        let dummy_chunk_response = send_dummy_chunk_async(
            FILE_CHUNK_SIZE,
            file_properties.size,
            api_key,
            &upload_properties,
            retry_settings,
            filen_settings,
        )
        .await?;
        if dummy_chunk_response.status {
            let upload_done_payload = UploadDoneRequestPayload {
                uuid: upload_properties.uuid,
                upload_key: upload_properties.upload_key.clone(),
            };
            let mark_done_response = retry_settings
                .retry_async(|| upload_done_request_async(&upload_done_payload, filen_settings))
                .await?;
            Ok(FileUploadInfo::new(
                upload_properties,
                mark_done_response,
                chunk_upload_responses,
            ))
        } else {
            DummyChunkNotAccepted {
                reason: dummy_chunk_response
                    .message
                    .unwrap_or_else(|| "unknown reason".to_owned()),
            }
            .fail()
        }
    };

    match finalize_chunks_if_all_uploaded(chunk_upload_responses, finalize_action) {
        Ok(future_file_upload_info) => future_file_upload_info.await,
        Err(f_err) => Err(f_err),
    }
}

fn finalize_chunks_if_all_uploaded<F, FR>(
    chunk_upload_responses: Vec<UploadFileChunkResponsePayload>,
    finalize_action: F,
) -> Result<FR>
where
    F: FnOnce(Vec<UploadFileChunkResponsePayload>) -> FR,
{
    let maybe_failed_chunk = chunk_upload_responses.iter().find(|r| !r.status);
    match maybe_failed_chunk {
        Some(failed_chunk) => {
            let failure_reason = failed_chunk.message.as_deref().unwrap_or("unknown reason");
            // At least one chunk failed with 'status: false', so fail entire upload, I guess
            ChunkNotAccepted {
                reason: failure_reason.to_owned(),
            }
            .fail()
        }
        None => Ok(finalize_action(chunk_upload_responses)),
    }
}

/// Uploads all real file chunks to Filen; do not forget to upload dummy chunk after real chunks are uploaded.
/// Returned file chunk upload responses are in order: first upload response corresponds to the
/// first file chunk uploaded, and so on.
fn upload_chunks<R: Read + Seek>(
    api_key: &SecUtf8,
    file_chunk_size: u32,
    file_size: u64,
    upload_properties: &FileUploadProperties,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
    reader: &mut BufReader<R>,
) -> Result<Vec<UploadFileChunkResponsePayload>> {
    let chunk_processor = |chunk_pos: FileChunkPosition, chunk: Vec<u8>| {
        retry_settings
            .retry(|| encrypt_and_upload_chunk(api_key, chunk_pos.index, &chunk, upload_properties, filen_settings))
    };
    read_into_chunks_and_process(file_chunk_size, file_size, reader, chunk_processor)
        .flatten()
        .collect()
}

/// Uploads all real file chunks to Filen; do not forget to upload dummy chunk after real chunks are uploaded.
/// Returned file chunk upload responses are in order: first upload response corresponds to the
/// first file chunk uploaded, and so on.
#[cfg(feature = "async")]
async fn upload_chunks_async<R: Read + Seek>(
    api_key: &SecUtf8,
    file_chunk_size: u32,
    file_size: u64,
    upload_properties: &FileUploadProperties,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
    reader: &mut BufReader<R>,
) -> Result<Vec<UploadFileChunkResponsePayload>> {
    let chunk_processor = |chunk_pos: FileChunkPosition, chunk: Vec<u8>| async move {
        retry_settings
            .retry_async(|| {
                encrypt_and_upload_chunk_async(api_key, chunk_pos.index, &chunk, upload_properties, filen_settings)
            })
            .await
    };
    // You might notice that file chunks are still read sequentially.
    // I assume that trying to read multiple chunks of the file in parallel is not fast
    // because it forces continuos seeks during IO.
    let future_chunk_responses: Result<Vec<_>> =
        read_into_chunks_and_process(file_chunk_size, file_size, reader, chunk_processor).collect();
    futures::future::try_join_all(future_chunk_responses?).await
}

fn read_into_chunks_and_process<'reader, R, ProcType, ProcResult>(
    file_chunk_size: u32,
    file_size: u64,
    reader: &'reader mut BufReader<R>,
    chunk_processor: ProcType,
) -> impl Iterator<Item = Result<ProcResult>> + 'reader
where
    R: Read + Seek,
    ProcType: Fn(FileChunkPosition, Vec<u8>) -> ProcResult,
    ProcType: 'reader,
{
    let file_chunk_positions = FileChunkPositions::new(file_chunk_size, file_size);
    file_chunk_positions.map(move |chunk_pos| {
        let mut chunk_buf = vec![0u8; chunk_pos.chunk_size as usize];
        reader
            .seek(SeekFrom::Start(chunk_pos.start_position))
            .and_then(|_| reader.read_exact(&mut chunk_buf))
            .context(SeekReadError {})
            .map(|_| chunk_processor(chunk_pos, chunk_buf))
    })
}

fn send_dummy_chunk(
    chunk_size: u32,
    file_size: u64,
    api_key: &SecUtf8,
    upload_properties: &FileUploadProperties,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<UploadFileChunkResponsePayload> {
    assert!(file_size != 0);

    let last_index = ((file_size - 1) / chunk_size as u64) as u32;
    let dummy_buf = vec![0u8; 0];
    retry_settings
        .retry(|| encrypt_and_upload_chunk(api_key, last_index + 1, &dummy_buf, upload_properties, filen_settings))
}

#[cfg(feature = "async")]
async fn send_dummy_chunk_async(
    chunk_size: u32,
    file_size: u64,
    api_key: &SecUtf8,
    upload_properties: &FileUploadProperties,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<UploadFileChunkResponsePayload> {
    assert!(file_size != 0);

    let last_index = ((file_size - 1) / chunk_size as u64) as u32;
    let dummy_buf = vec![0u8; 0];
    retry_settings
        .retry_async(|| {
            encrypt_and_upload_chunk_async(api_key, last_index + 1, &dummy_buf, upload_properties, filen_settings)
        })
        .await
}

fn calculate_chunk_count(chunk_size: u32, file_size: u64) -> u32 {
    let mut dummy_offset = 0u64;
    let mut file_chunks = 0u32;
    while dummy_offset < file_size {
        file_chunks += 1;
        dummy_offset += chunk_size as u64;
    }

    file_chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::time::SystemTime;

    #[test]
    fn uploaded_file_properties_should_produce_query_string_with_expected_parts() {
        let m_key = SecUtf8::from("b49cadfb92e1d7d54e9dd9d33ba9feb2af1f10ae");
        let file_metadata = FileProperties::from_name_size_modified("test.txt", 128, &SystemTime::now()).unwrap();
        let properties = FileUploadProperties::from_file_properties(&file_metadata, 1, Uuid::nil(), &m_key);

        let query_params = properties.to_query_params(0, &SecUtf8::from("some api key"));
        let query_params_2 = properties.to_query_params(0, &SecUtf8::from("some api key"));

        assert_eq!(query_params, query_params_2);
        assert!(query_params.contains("apiKey=some+api+key"));
        assert!(query_params.contains("uuid="));
        assert!(query_params.contains("name="));
        assert!(query_params.contains("nameHashed=809a953250a3917a9993645d1ba146348a198fc2"));
        assert!(query_params.contains("size="));
        assert!(query_params.contains("chunks=1"));
        assert!(query_params.contains("mime="));
        assert!(query_params.contains("index=0"));
        assert!(query_params.contains("rm="));
        assert!(query_params.contains("expire=never"));
        assert!(query_params.contains("uploadKey="));
        assert!(query_params.contains("metaData="));
        assert!(query_params.contains("parent=00000000-0000-0000-0000-000000000000"));
        assert!(query_params.contains("version=1"));
    }
}
