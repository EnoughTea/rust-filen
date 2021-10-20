use std::{
    cmp::*,
    convert::TryInto,
    io::{Read, Seek, SeekFrom},
};

use crate::{
    crypto,
    file_chunk_pos::FileChunkPositions,
    filen_settings::FilenSettings,
    queries,
    retry_settings::RetrySettings,
    utils,
    v1::{fs::*, *},
};
use anyhow::*;
use reqwest::Url;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const DEFAULT_EXPIRE: &str = "never";
const FILE_CHUNK_SIZE: u32 = 1024 * 1024 * 1;
const FILE_VERSION: u32 = 1;
const UPLOAD_PATH: &str = "/v1/upload";
const UPLOAD_DONE_PATH: &str = "/v1/upload/done";

/// Response data for [UPLOAD_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UploadFileResponseData {
    pub bucket: String,

    pub region: String,

    #[serde(rename = "expireSet")]
    pub expire_set: u32,

    #[serde(rename = "expireTimestamp")]
    pub expire_timestamp: u64,

    #[serde(rename = "deleteTimestamp")]
    pub delete_timestamp: u64,
}
api_response_struct!(
    /// Response for [UPLOAD_PATH] endpoint.
    UploadFileResponsePayload<Option<UploadFileResponseData>>
);

/// Used for requests to [UPLOAD_DONE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UploadDoneRequestPayload {
    /// Uploaded file ID, UUID V4 in hyphenated lowercase format.
    pub uuid: String,

    /// File upload key: random alphanumeric string associated with entire file upload.
    #[serde(rename = "uploadKey")]
    pub upload_key: SecUtf8,
}
utils::display_from_json!(UploadDoneRequestPayload);

/// File properties needed to upload file to Filen.
struct UploadedFileProperties {
    /// File ID, UUID V4 in hyphenated lowercase format.
    pub uuid: String,

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

    /// Random alphanumeric key.
    pub rm: SecUtf8,

    /// Random alphanumeric key.
    pub upload_key: SecUtf8,

    /// Expire marker.
    pub expire: String,

    /// Parent folder ID, UUID V4 in hyphenated lowercase format.
    pub parent_uuid: String,

    /// Determines how file bytes should be encrypted/decrypted.
    /// File is encrypted using roughly the same algorithm as metadata encryption,
    /// use [crypto::encrypt_file_data] and [crypto::decrypt_file_data] for the task.
    pub version: u32,
}

impl UploadedFileProperties {
    pub fn from_file_properties(
        file_metadata: &FileProperties,
        parent_uuid: &str,
        chunk_size: u32,
        last_master_key: &SecUtf8,
    ) -> Result<UploadedFileProperties> {
        let new_file_uuid = Uuid::new_v4().to_hyphenated().to_string();
        let rm = SecUtf8::from(utils::random_alphanumeric_string(32));
        let upload_key = SecUtf8::from(utils::random_alphanumeric_string(32));

        let file_metadata_encrypted = file_metadata.to_metadata_string(&last_master_key)?;
        let name_metadata_encrypted = file_metadata.name_encrypted();
        let size_metadata_encrypted = file_metadata.size_encrypted();
        let mime_metadata_encrypted = file_metadata.mime_encrypted();
        let name_hashed = LocationNameMetadata::name_hashed(&file_metadata.name);

        let file_chunks = calculate_chunk_count(chunk_size, file_metadata.size);
        Ok(UploadedFileProperties {
            uuid: new_file_uuid,
            name_metadata: name_metadata_encrypted,
            name_hashed,
            size_metadata: size_metadata_encrypted,
            chunks: file_chunks,
            mime_metadata: mime_metadata_encrypted,
            file_metadata: file_metadata_encrypted,
            file_key: file_metadata.key.clone(),
            rm,
            upload_key,
            expire: DEFAULT_EXPIRE.to_owned(),
            parent_uuid: parent_uuid.to_owned(),
            version: FILE_VERSION,
        })
    }

    /// Produces percent-encoded string of query parameters for Filen upload endpoint.
    pub fn to_query_params(&self, chunk_index: u32, api_key: &SecUtf8) -> String {
        let query_builder = Url::parse_with_params(
            "https://localhost?",
            &[
                ("apiKey", api_key.unsecure()),
                ("uuid", &self.uuid),
                ("name", &self.name_metadata),
                ("nameHashed", &self.name_hashed),
                ("size", &self.size_metadata),
                ("chunks", &self.chunks.to_string()),
                ("mime", &self.mime_metadata),
                ("index", &chunk_index.to_string()),
                ("rm", self.rm.unsecure()),
                ("expire", &self.expire),
                ("uploadKey", self.upload_key.unsecure()),
                ("metaData", &self.file_metadata),
                ("parent", &self.parent_uuid),
                ("version", &self.version.to_string()),
            ],
        )
        .unwrap();
        query_builder.query().unwrap().to_owned()
    }

    pub fn to_api_endpoint(&self, chunk_index: u32, api_key: &SecUtf8) -> String {
        format!("{}?{}", UPLOAD_PATH, self.to_query_params(chunk_index, api_key))
    }
}

/// Calls [UPLOAD_DONE_PATH] endpoint. Used to mark upload as done after all file chunks were uploaded.
pub fn upload_done_request(
    payload: &UploadDoneRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(UPLOAD_DONE_PATH, payload, filen_settings)
}

/// Calls [UPLOAD_DONE_PATH] endpoint asynchronously. Used to mark upload as done after all file chunks were uploaded.
pub async fn upload_done_request_async(
    payload: &UploadDoneRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(UPLOAD_DONE_PATH, payload, filen_settings).await
}

/// Test blocking stuff; currently returns 'Upload chunks are not matching.' from upload_done_request.
fn upload_file<R: std::io::Read + std::io::Seek>(
    api_key: &SecUtf8,
    parent_uuid: &str,
    file_properties: &FileProperties,
    last_master_key: &SecUtf8,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
    reader: &mut std::io::BufReader<R>,
) -> Result<PlainApiResponse> {
    let upload_properties =
        UploadedFileProperties::from_file_properties(file_properties, parent_uuid, FILE_CHUNK_SIZE, last_master_key)?;
    let file_chunk_positions = FileChunkPositions::new(FILE_CHUNK_SIZE, file_properties.size);
    let _chunk_upload_responses = file_chunk_positions
        .map(|chunk_pos| {
            let mut chunk_buf = vec![0u8; chunk_pos.chunk_size as usize];
            let read_result = reader
                .seek(SeekFrom::Start(chunk_pos.start_position))
                .and_then(|_| reader.read_exact(&mut chunk_buf));
            read_result.map_err(|io_err| anyhow!(io_err)).and_then(|_| {
                encrypt_and_upload_chunk(
                    api_key,
                    chunk_pos.index,
                    chunk_buf,
                    &upload_properties,
                    retry_settings,
                    filen_settings,
                )
            })
        })
        .collect::<Result<Vec<UploadFileResponsePayload>>>()?;

    let upload_done_payload = UploadDoneRequestPayload {
        uuid: upload_properties.uuid,
        upload_key: upload_properties.upload_key,
    };
    upload_done_request(&upload_done_payload, &filen_settings)
}

fn encrypt_and_upload_chunk(
    api_key: &SecUtf8,
    chunk_index: u32,
    chunk: Vec<u8>,
    upload_properties: &UploadedFileProperties,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<UploadFileResponsePayload> {
    let chunk_encrypted = crypto::encrypt_file_data(
        &chunk,
        upload_properties.file_key.unsecure().as_bytes().try_into().unwrap(),
        upload_properties.version,
    )?;

    queries::upload_to_filen::<UploadFileResponsePayload>(
        &upload_properties.to_api_endpoint(chunk_index, api_key),
        chunk_encrypted,
        retry_settings,
        filen_settings,
    )
}

async fn encrypt_and_upload_chunk_async(
    api_key: &SecUtf8,
    chunk_index: u32,
    chunk: Vec<u8>,
    file_properties: &UploadedFileProperties,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<UploadFileResponsePayload> {
    let chunk_encrypted = crypto::encrypt_file_data(
        &chunk,
        file_properties.file_key.unsecure().as_bytes().try_into().unwrap(),
        file_properties.version,
    )?;

    queries::upload_to_filen_async::<UploadFileResponsePayload>(
        &file_properties.to_api_endpoint(chunk_index, api_key),
        chunk_encrypted,
        retry_settings,
        filen_settings,
    )
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
    use std::time::SystemTime;

    use super::*;

    #[test]
    fn uploaded_file_properties_should_produce_query_string_with_expected_parts() {
        let m_key = SecUtf8::from("b49cadfb92e1d7d54e9dd9d33ba9feb2af1f10ae");
        let file_metadata = FileProperties::from_name_size_modified("test.txt", 128, &SystemTime::now()).unwrap();
        let properties =
            UploadedFileProperties::from_file_properties(&file_metadata, "some parent uuid", FILE_CHUNK_SIZE, &m_key)
                .unwrap();

        let query_params = properties.to_query_params(0, &SecUtf8::from("some api key"));

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
        assert!(query_params.contains("parent=some+parent+uuid"));
        assert!(query_params.contains("version=1"));
    }
}
