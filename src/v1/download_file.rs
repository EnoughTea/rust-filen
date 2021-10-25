use std::{convert::TryInto, fmt::Display, io::Write};

use crate::{crypto, filen_settings::FilenSettings, queries, retry_settings::RetrySettings, utils, v1::*};
use secstr::SecUtf8;
use snafu::{ResultExt, Snafu};

type Result<T, E = Error> = std::result::Result<T, E>;

/// Sets how many chunks to download and decrypt concurrently.
const ASYNC_CHUNK_BATCH_SIZE: usize = 16; // Is it a good idea to simply hardcode this param?

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Cannot download file chunk '{}': {}", location, source))]
    CannotDownloadFileChunk {
        location: FileChunkLocation,
        source: queries::Error,
    },

    #[snafu(display("Writer could not write file chunk '{}' ({} bytes): {}", location, length, source))]
    CannotWriteFileChunk {
        length: usize,
        location: FileChunkLocation,
        source: std::io::Error,
    },

    #[snafu(display("Writer could not be flushed: {}", source))]
    CannotFlushWriter { source: std::io::Error },

    #[snafu(display("Cannot decrypt file chunk {} ({} bytes): {}", location, length, source))]
    CannotDecryptFileChunk {
        length: usize,
        location: FileChunkLocation,
        source: crypto::Error,
    },

    #[snafu(display("File key is not 32 bytes long: {}", source))]
    InvalidFileKeySize { source: std::array::TryFromSliceError },

    #[snafu(display("Cannot deserialize response body JSON: {}", source))]
    CannotDeserializeResponseBodyJson { source: reqwest::Error },
}

/// Represents file's address on Filen servers.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FileLocation {
    pub region: String,
    pub bucket: String,
    pub file_uuid: String,
    pub chunk_count: u32,
}

impl FileLocation {
    pub fn new(region: &str, bucket: &str, file_uuid: &str, chunk_count: u32) -> FileLocation {
        FileLocation {
            region: region.to_owned(),
            bucket: bucket.to_owned(),
            file_uuid: file_uuid.to_owned(),
            chunk_count,
        }
    }

    pub fn get_file_chunk_location(&self, chunk_index: u32) -> FileChunkLocation {
        FileChunkLocation::new(&self.region, &self.bucket, &self.file_uuid, chunk_index)
    }
}

impl Display for FileLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}/{} [{} chunks]",
            self.region, self.bucket, self.file_uuid, self.chunk_count
        )
    }
}

/// Represents file chunk's address on Filen servers.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FileChunkLocation {
    pub region: String,
    pub bucket: String,
    pub file_uuid: String,
    pub chunk_index: u32,
}

impl FileChunkLocation {
    pub fn new(region: &str, bucket: &str, file_uuid: &str, chunk_index: u32) -> FileChunkLocation {
        FileChunkLocation {
            region: region.to_owned(),
            bucket: bucket.to_owned(),
            file_uuid: file_uuid.to_owned(),
            chunk_index,
        }
    }
}

impl Display for FileChunkLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}/{}/{}",
            self.region, self.bucket, self.file_uuid, self.chunk_index
        )
    }
}

/// Gets encrypted file chunk bytes from Filen download server defined by a region and a bucket.
/// Resulting bytes can be decrypted with file key from file metadata.
///
/// Download server endpoint is <filen download server>/<region>/<bucket>/<file uuid>/<chunk index>
pub fn download_file_chunk(file_chunk_location: &FileChunkLocation, filen_settings: &FilenSettings) -> Result<Vec<u8>> {
    let api_endpoint = utils::filen_file_location_to_api_endpoint(file_chunk_location);
    queries::download_from_filen(&api_endpoint, filen_settings).context(CannotDownloadFileChunk {
        location: file_chunk_location.clone(),
    })
}

/// Asynchronously gets encrypted file chunk bytes from Filen download server defined by a region and a bucket.
/// Resulting bytes can be decrypted with file key from file metadata.
///
/// Download server endpoint is <filen download server>/<region>/<bucket>/<file uuid>/<chunk index>
pub async fn download_file_chunk_async(
    file_chunk_location: &FileChunkLocation,
    filen_settings: &FilenSettings,
) -> Result<Vec<u8>> {
    let api_endpoint = utils::filen_file_location_to_api_endpoint(file_chunk_location);
    queries::download_from_filen_async(&api_endpoint, filen_settings)
        .await
        .context(CannotDownloadFileChunk {
            location: file_chunk_location.to_owned(),
        })
}

/// Synchronously downloads and decrypts the file defined by given [DownloadedFileData] from Filen download server.
/// Returns total size of downloaded encrypted chunks.
/// All file chunks are downloaded and decrypted sequentially one by one, with each decrypted chunk immediately written
/// to the provided writer.
///
/// Note that file download is explicitly retriable and requires RetrySettings as an argument.
/// You can pass [crate::NO_RETRIES] if you really want to fail the entire file download even if a single chunk
/// download request fails temporarily, otherwise [crate::STANDARD_RETRIES] is a better fit.
pub fn download_and_decrypt_file_from_data_and_key<W: Write>(
    file_data: &DownloadedFileData,
    file_key: &SecUtf8,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
    writer: &mut std::io::BufWriter<W>,
) -> Result<u64> {
    download_and_decrypt_file(
        &file_data.get_file_location(),
        file_data.version,
        file_key,
        retry_settings,
        filen_settings,
        writer,
    )
}

/// Asynchronously downloads and decrypts the file defined by given [DownloadedFileData] from Filen download server.
/// Returns total size of downloaded encrypted chunks.
/// All file chunks are downloaded and decrypted in concurrently first, and then written to the provided writer.
///
/// Note that file download is explicitly retriable and requires RetrySettings as an argument.
/// You can pass [crate::NO_RETRIES] if you really want to fail the entire file download even if a single chunk
/// download request fails temporarily, otherwise [crate::STANDARD_RETRIES] is a better fit.
pub async fn download_and_decrypt_file_from_data_and_key_async<W: Write>(
    file_data: &DownloadedFileData,
    file_key: &SecUtf8,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
    writer: &mut std::io::BufWriter<W>,
) -> Result<u64> {
    download_and_decrypt_file_async(
        &file_data.get_file_location(),
        file_data.version,
        file_key,
        retry_settings,
        filen_settings,
        writer,
    )
    .await
}

/// Synchronously downloads and decrypts the specified file from Filen download server defined by a region and a bucket.
/// Returns total size of downloaded encrypted chunks.
/// All file chunks are downloaded and decrypted sequentially one by one, with each decrypted chunk immediately written to the provided writer.
pub fn download_and_decrypt_file<W: Write>(
    file_location: &FileLocation,
    version: u32,
    file_key: &SecUtf8,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
    writer: &mut std::io::BufWriter<W>,
) -> Result<u64> {
    let written_chunk_lengths = (0..file_location.chunk_count)
        .map(|chunk_index| {
            let file_chunk_location = file_location.get_file_chunk_location(chunk_index);
            let encrypted_bytes = retry_settings.retry(|| download_file_chunk(&file_chunk_location, filen_settings))?;
            let file_key_bytes: &[u8; 32] = file_key
                .unsecure()
                .as_bytes()
                .try_into()
                .context(InvalidFileKeySize {})?;
            let decrypted_bytes = crypto::decrypt_file_chunk(&encrypted_bytes, file_key_bytes, version).context(
                CannotDecryptFileChunk {
                    length: encrypted_bytes.len(),
                    location: file_chunk_location.clone(),
                },
            )?;
            writer
                .write_all(&decrypted_bytes)
                .map(|_| encrypted_bytes.len() as u64)
                .context(CannotWriteFileChunk {
                    length: decrypted_bytes.len(),
                    location: file_chunk_location,
                })
        })
        .collect::<Result<Vec<u64>>>()?;

    writer.flush().context(CannotFlushWriter {})?;
    Ok(written_chunk_lengths.iter().sum::<u64>())
}

/// Asynchronously downloads the specified file from Filen download server defined by a region and a bucket.
/// Returns total size of downloaded encrypted file chunks.
/// All file chunks are downloaded and decrypted concurrently first, and then written to the provided writer.
pub async fn download_and_decrypt_file_async<W: Write>(
    file_location: &FileLocation,
    version: u32,
    file_key: &SecUtf8,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
    writer: &mut std::io::BufWriter<W>,
) -> Result<u64> {
    let download_and_decrypt_action = |batch_index: usize, batch_indices: Vec<u32>| async move {
        let batch_or_err = download_batch_async(file_location, &batch_indices, retry_settings, filen_settings).await;
        match batch_or_err {
            Ok(batch) => decrypt_batch(batch_index, &batch, file_location, version, file_key),
            Err(err) => Err(err),
        }
    };
    let batches = batch_chunks(file_location.chunk_count, ASYNC_CHUNK_BATCH_SIZE);
    let download_and_decrypt_batches = batches
        .into_iter()
        .enumerate()
        .map(|(batch_index, batch)| download_and_decrypt_action(batch_index, batch));
    let decrypted_batches = futures::future::try_join_all(download_and_decrypt_batches).await?;
    // Batches need to be written sequentially, I guess
    let written_batch_lengths = decrypted_batches
        .iter()
        .enumerate()
        .map(|(index, (batch, encrypted_size))| {
            write_batch(
                batch,
                *encrypted_size,
                &file_location.get_file_chunk_location(index as u32),
                writer,
            )
        })
        .collect::<Result<Vec<u64>>>()?;

    writer.flush().context(CannotFlushWriter {})?;
    Ok(written_batch_lengths.iter().sum::<u64>())
}

/// Writes batch of file chunks to the given writer and returns total size of passed encrypted batch.
/// If one write in the batch fails, entire batch fails.
fn write_batch<W: Write>(
    batch: &[Vec<u8>],
    batch_encrypted_size: u64,
    file_chunk_location: &FileChunkLocation,
    writer: &mut std::io::BufWriter<W>,
) -> Result<u64> {
    let written_lengths = batch
        .iter()
        .map(|bytes| {
            writer
                .write_all(bytes)
                .map(|_| batch_encrypted_size)
                .context(CannotWriteFileChunk {
                    length: bytes.len(),
                    location: file_chunk_location.clone(),
                })
        })
        .collect::<Result<Vec<u64>>>()?;

    Ok(written_lengths.iter().sum::<u64>())
}

fn decrypt_batch(
    batch_index: usize,
    batch: &[Vec<u8>],
    file_location: &FileLocation,
    version: u32,
    file_key: &SecUtf8,
) -> Result<(Vec<Vec<u8>>, u64)> {
    let mut encrypted_total: u64 = 0;
    let encrypted_bytes = batch
        .iter()
        .enumerate()
        .map(|(index, encrypted_bytes)| {
            let file_key_bytes: &[u8; 32] = file_key
                .unsecure()
                .as_bytes()
                .try_into()
                .context(InvalidFileKeySize {})?;
            let chunk_index = batch_index + index;
            crypto::decrypt_file_chunk(encrypted_bytes, file_key_bytes, version)
                .map(|decrypted_bytes| {
                    encrypted_total += encrypted_bytes.len() as u64;
                    decrypted_bytes
                })
                .context(CannotDecryptFileChunk {
                    length: encrypted_bytes.len(),
                    location: file_location.get_file_chunk_location(chunk_index as u32),
                })
        })
        .collect::<Result<Vec<Vec<u8>>>>()?;

    Ok((encrypted_bytes, encrypted_total))
}

/// Asynchronously downloads Filen file data chunks with given indices. If one download in the batch fails, entire batch fails.
async fn download_batch_async(
    file_location: &FileLocation,
    batch_indices: &[u32],
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<Vec<Vec<u8>>> {
    let download_chunk_eventually = |chunk_index: u32| async move {
        let file_chunk_location = file_location.get_file_chunk_location(chunk_index);
        download_file_chunk_async(&file_chunk_location, filen_settings).await
    };
    let download_chunk_with_retries_eventually =
        |chunk_index: u32| retry_settings.retry_async(move || download_chunk_eventually(chunk_index));

    let chunk_download_tasks = batch_indices
        .iter()
        .map(|chunk_index| download_chunk_with_retries_eventually(*chunk_index));

    futures::future::try_join_all(chunk_download_tasks).await
}

/// Calculates batch indices from the total amount of chunks and the single batch size.
fn batch_chunks(file_chunk_count: u32, batch_size: usize) -> Vec<Vec<u32>> {
    let chunk_indicies: Vec<u32> = (0..file_chunk_count).collect();
    chunk_indicies.chunks(batch_size).map(|slice| slice.to_vec()).collect()
}
