use std::{convert::TryInto, io::Write};

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
use serde::{Deserialize, Serialize};
use serde_with::*;

/// Sets how many chunks to download and decrypt in parallel.
const ASYNC_CHUNK_BATCH_SIZE: usize = 16; // Is it a good idea to simply hardcode this param?
const DOWNLOAD_DIR: &str = "/v1/download/dir";

// Used for requests to [DOWNLOAD_DIR] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DownloadDirRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: String,
}

/// Response data for [DOWNLOAD_DIR] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DownloadDirResponseData {
    pub folders: Vec<SyncedDirData>,

    pub files: Vec<DownloadedFileData>,
}
utils::display_from_json!(DownloadDirResponseData);

/// Folder data for one of the folder in Filen sync folder.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DownloadedFileData {
    /// File ID, UUID V4 in hyphenated lowercase format.
    pub uuid: String,

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
    pub parent: String,

    /// File metadata.
    pub metadata: String,

    /// Determines how file bytes should be encrypted/decrypted.
    /// File is encrypted using roughly the same algorithm as metadata encryption,
    /// use [crypto::encrypt_file_data] and [crypto::decrypt_file_data] for the task.
    pub version: u32,
}
utils::display_from_json!(DownloadedFileData);

impl DownloadedFileData {
    /// Decrypts file metadata string.
    pub fn decrypt_file_metadata(&self, last_master_key: &SecUtf8) -> Result<FileMetadata> {
        FileMetadata::decrypt_file_metadata(&self.metadata, last_master_key)
    }

    /// Decrypt name, size and mime metadata. File key is contained within file metadata in [DownloadedFileData::metadata] field,
    /// which can be decrypted with [DownloadedFileData::decrypt_file_metadata] call.
    pub fn decrypt_name_size_mime(&self, file_key: &SecUtf8) -> Result<FileNameSizeMime> {
        let name = crypto::decrypt_metadata_str(&self.name_metadata, file_key.unsecure())?;
        let size_string = &crypto::decrypt_metadata_str(&self.size_metadata, file_key.unsecure())?;
        let size = str::parse::<u64>(size_string)?;
        let mime = crypto::decrypt_metadata_str(&self.mime_metadata, file_key.unsecure())?;
        Ok(FileNameSizeMime { name, size, mime })
    }

    /// Uses this file's properties to call [download_and_decrypt_file].
    pub fn download_and_decrypt_file<W: std::io::Write>(
        &self,
        file_key: &SecUtf8,
        retry_settings: &RetrySettings,
        filen_settings: &FilenSettings,
        writer: &mut std::io::BufWriter<W>,
    ) -> Result<u64> {
        download_and_decrypt_file(
            &self.region,
            &self.bucket,
            &self.uuid,
            self.chunks,
            self.version,
            file_key,
            retry_settings,
            filen_settings,
            writer,
        )
    }

    /// Uses this file's properties to call [download_and_decrypt_file_async].
    pub async fn download_and_decrypt_file_async<W: std::io::Write>(
        &self,
        file_key: &SecUtf8,
        retry_settings: &RetrySettings,
        filen_settings: &FilenSettings,
        writer: &mut std::io::BufWriter<W>,
    ) -> Result<u64> {
        download_and_decrypt_file_async(
            &self.region,
            &self.bucket,
            &self.uuid,
            self.chunks,
            self.version,
            file_key,
            retry_settings,
            filen_settings,
            writer,
        )
        .await
    }
}

pub struct FileNameSizeMime {
    pub name: String,
    pub size: u64,
    pub mime: String,
}

api_response_struct!(
    /// Response for [DOWNLOAD_DIR] endpoint.
    DownloadDirResponsePayload<Option<DownloadDirResponseData>>
);

/// Calls [USER_DIRS_PATH] endpoint. Used to get a list of user's folders.
/// Always includes Filen "Default" folder, and may possibly include special "Filen Sync" folder, created by Filen's client.
pub fn download_dir_request(
    payload: &DownloadDirRequestPayload,
    settings: &FilenSettings,
) -> Result<DownloadDirResponsePayload> {
    queries::query_filen_api(DOWNLOAD_DIR, payload, settings)
}

/// Calls [USER_DIRS_PATH] endpoint asynchronously. Used to get a list of user's folders.
/// Always includes Filen "Default" folder, and may possibly include special "Filen Sync" folder, created by Filen's client.
pub async fn download_dir_request_async(
    payload: &DownloadDirRequestPayload,
    settings: &FilenSettings,
) -> Result<DownloadDirResponsePayload> {
    queries::query_filen_api_async(DOWNLOAD_DIR, payload, settings).await
}

/// Gets encrypted file chunk bytes from Filen download server defined by a region and a bucket.
/// Resulting bytes can be decrypted with file key from file metadata.
///
/// Download server endpoint is <filen download server>/<region>/<bucket>/<file uuid>/<chunk index>
pub fn download_chunk(
    region: &str,
    bucket: &str,
    file_uuid: &str,
    chunk_index: u32,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<Vec<u8>> {
    let api_endpoint = utils::filen_file_address_to_api_endpoint(region, bucket, file_uuid, chunk_index);
    queries::download_from_filen(&api_endpoint, retry_settings, filen_settings)
}

/// Asynchronously gets encrypted file chunk bytes from Filen download server defined by a region and a bucket.
/// Resulting bytes can be decrypted with file key from file metadata.
///
/// Download server endpoint is <filen download server>/<region>/<bucket>/<file uuid>/<chunk index>
pub async fn download_chunk_async(
    region: &str,
    bucket: &str,
    file_uuid: &str,
    chunk_index: u32,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<Vec<u8>> {
    let api_endpoint = utils::filen_file_address_to_api_endpoint(region, bucket, file_uuid, chunk_index);
    queries::download_from_filen_async(&api_endpoint, retry_settings, filen_settings).await
}

/// Synchronously downloads and decryptes the specified file from Filen download server defined by a region and a bucket.
/// Returns total size of downloaded encrypted chunks.
/// All file chunks are downloaded and decrypted sequentially one by one, with each decrypted chunk immediately written to the provided writer.
pub fn download_and_decrypt_file<W: std::io::Write>(
    region: &str,
    bucket: &str,
    file_uuid: &str,
    chunk_count: u32,
    version: u32,
    file_key: &SecUtf8,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
    writer: &mut std::io::BufWriter<W>,
) -> Result<u64> {
    let written_chunk_lengths = (0..chunk_count)
        .map(|chunk_index| {
            let encrypted_bytes =
                download_chunk(region, bucket, file_uuid, chunk_index, retry_settings, filen_settings)?;
            let file_key_bytes: &[u8; 32] = file_key.unsecure().as_bytes().try_into()?;
            let decrypted_bytes = crypto::decrypt_file_data(&encrypted_bytes, file_key_bytes, version)?;
            writer
                .write_all(&decrypted_bytes)
                .map(|_| encrypted_bytes.len() as u64)
                .with_context(|| "Could not write file batch bytes")
        })
        .collect::<Result<Vec<u64>>>()?;

    Ok(written_chunk_lengths.iter().sum::<u64>())
}

/// Asynchronously downloads the specified file from Filen download server defined by a region and a bucket.
/// Returns total size of downloaded encrypted file chunks.
/// All file chunks are downloaded and decrypted in parallel first, and then written to the provided writer.
pub async fn download_and_decrypt_file_async<W: std::io::Write>(
    region: &str,
    bucket: &str,
    file_uuid: &str,
    chunk_count: u32,
    version: u32,
    file_key: &SecUtf8,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
    writer: &mut std::io::BufWriter<W>,
) -> Result<u64> {
    let download_and_decrypt_action = |batch_indices: Vec<u32>| {
        download_batch_async(region, bucket, file_uuid, batch_indices, retry_settings, filen_settings).map(
            |maybe_batch| match maybe_batch {
                Ok(batch) => decrypt_batch(&batch, version, file_key),
                Err(err) => Err(err),
            },
        )
    };
    let batches = batch_chunks(chunk_count, ASYNC_CHUNK_BATCH_SIZE);
    let download_and_decrypt_batches = batches.iter().map(|batch| download_and_decrypt_action(batch.clone()));
    let decrypted_batches = futures::future::try_join_all(download_and_decrypt_batches).await?;
    // Batches need to be written sequentially, I guess
    let written_batch_lengths = decrypted_batches
        .iter()
        .map(|(batch, encrypted_size)| write_batch(batch, encrypted_size.clone(), writer))
        .collect::<Result<Vec<u64>>>()?;

    Ok(written_batch_lengths.iter().sum::<u64>())
}

/// Writes batch of file chunks to the given writer and returns total size of passed encrypted batch.
/// If one write in the batch fails, entire batch fails.
fn write_batch<W: std::io::Write>(
    batch: &Vec<Vec<u8>>,
    batch_encrypted_size: u64,
    writer: &mut std::io::BufWriter<W>,
) -> Result<u64> {
    let written_lengths = batch
        .iter()
        .map(|bytes| {
            writer
                .write_all(&bytes)
                .map(|_| batch_encrypted_size)
                .with_context(|| "Could not write file batch bytes")
        })
        .collect::<Result<Vec<u64>>>()?;

    Ok(written_lengths.iter().sum::<u64>())
}

fn decrypt_batch(batch: &Vec<Vec<u8>>, version: u32, file_key: &SecUtf8) -> Result<(Vec<Vec<u8>>, u64)> {
    let mut encrypted_total: u64 = 0;
    let encrypted_bytes = batch
        .iter()
        .map(|encrypted_bytes| {
            let file_key_bytes: &[u8; 32] = file_key.unsecure().as_bytes().try_into()?;
            crypto::decrypt_file_data(&encrypted_bytes, file_key_bytes, version).map(|decrypted_bytes| {
                encrypted_total += encrypted_bytes.len() as u64;
                decrypted_bytes
            })
        })
        .collect::<Result<Vec<Vec<u8>>>>()?;

    Ok((encrypted_bytes, encrypted_total))
}

/// Asynchronously downloads Filen file data chunks with given indices. If one download in the batch fails, entire batch fails.
async fn download_batch_async(
    region: &str,
    bucket: &str,
    file_uuid: &str,
    batch_indices: Vec<u32>,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<Vec<Vec<u8>>> {
    let download_action =
        |chunk_index: u32| download_chunk_async(region, bucket, file_uuid, chunk_index, retry_settings, filen_settings);
    futures::future::try_join_all(
        batch_indices
            .iter()
            .map(|chunk_index| download_action(chunk_index.clone())),
    )
    .await
}

/// Calculates batch indices from the total amount of chunks and the single batch size.
fn batch_chunks(file_chunk_count: u32, batch_size: usize) -> Vec<Vec<u32>> {
    let chunk_indicies: Vec<u32> = (0..file_chunk_count).collect();
    chunk_indicies.chunks(batch_size).map(|slice| slice.to_vec()).collect()
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
        Lazy::new(|| SecUtf8::from("aYZmrwdVEbHJSqeA0RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM10CDnklpFq6"));

    #[tokio::test]
    async fn download_dir_request_and_async_should_be_correctly_typed() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = DownloadDirRequestPayload {
            api_key: API_KEY.clone(),
            uuid: "cf2af9a0-6f4e-485d-862c-0459f4662cf1".to_owned(),
        };
        let expected_response: DownloadDirResponsePayload =
            deserialize_from_file("tests/resources/responses/download_dir.json");
        let mock = setup_json_mock(DOWNLOAD_DIR, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { download_dir_request(&request_payload, &filen_settings) }),
        ).await??;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = download_dir_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }

    #[test]
    fn download_dir_response_data_file_should_be_correctly_decrypted() {
        let m_key = SecUtf8::from("ed8d39b6c2d00ece398199a3e83988f1c4942b24");
        let download_dir_response: DownloadDirResponsePayload =
            deserialize_from_file("tests/resources/responses/download_dir.json");
        let data = download_dir_response.data.unwrap();
        let test_file = data.files.get(0).unwrap();

        let test_file_metadata_result = test_file.decrypt_file_metadata(&m_key);
        assert!(test_file_metadata_result.is_ok());
        let test_file_metadata = test_file_metadata_result.unwrap();
        assert_eq!(test_file_metadata.key.unsecure(), "sh1YRHfx22Ij40tQBbt6BgpBlqkzch8Y");
        assert_eq!(test_file_metadata.last_modified, 1383742218);
        assert_eq!(test_file_metadata.mime, "image/png");
        assert_eq!(test_file_metadata.name, "lina.png");
        assert_eq!(test_file_metadata.size, 133641);

        let test_file_name_size_mime_result = test_file.decrypt_name_size_mime(&test_file_metadata.key);
        assert!(test_file_name_size_mime_result.is_ok());
        let test_file_name_size_mime = test_file_name_size_mime_result.unwrap();
        assert_eq!(test_file_name_size_mime.mime, test_file_metadata.mime);
        assert_eq!(test_file_name_size_mime.name, test_file_metadata.name);
        assert_eq!(test_file_name_size_mime.size, test_file_metadata.size);
    }
}
