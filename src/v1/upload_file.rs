use std::{convert::TryInto, fs, io::Read, path::PathBuf, time::SystemTime};

use crate::{
    crypto,
    filen_settings::FilenSettings,
    queries,
    retry_settings::RetrySettings,
    utils,
    v1::{fs::*, *},
};
use anyhow::*;
use futures::FutureExt;
use secstr::SecUtf8;
use uuid::Uuid;

use super::METADATA_VERSION;

const DEFAULT_EXPIRE: &str = "never";
const FILE_CHUNK_SIZE: u32 = 1024 * 1024 * 1;
const FILE_VERSION: u32 = 1;
const UPLOAD_PATH: &str = "/v1/upload";
const UPLOAD_DONE_PATH: &str = "/v1/upload/done";

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
    pub fn from_file_metadata(
        file_metadata: &FileMetadata,
        parent_uuid: String,
        last_master_key: &SecUtf8,
    ) -> Result<UploadedFileProperties> {
        let new_file_uuid = Uuid::new_v4().to_hyphenated().to_string();
        let rm = SecUtf8::from(utils::random_alphanumeric_string(32));
        let upload_key = SecUtf8::from(utils::random_alphanumeric_string(32));

        let file_metadata_encrypted = file_metadata.to_metadata_string(&last_master_key)?;
        let name_metadata_encrypted = file_metadata.name_encrypted(&last_master_key);
        let size_metadata_encrypted = file_metadata.size_encrypted(&last_master_key);
        let mime_metadata_encrypted = file_metadata.mime_encrypted(&last_master_key);
        let name_hashed = LocationNameMetadata::name_hashed(&file_metadata.name);

        let file_chunks = calculate_chunk_count(file_metadata.size, FILE_CHUNK_SIZE);
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
            parent_uuid: parent_uuid,
            version: FILE_VERSION,
        })
    }
}

fn calculate_chunk_count(file_size: u64, chunk_size: u32) -> u32 {
    let mut dummy_offset = 0u64;
    let mut file_chunks = 0u32;
    while dummy_offset < file_size {
        file_chunks += 1;
        dummy_offset += chunk_size as u64;
    }

    file_chunks
}
