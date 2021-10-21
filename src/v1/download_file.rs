use std::{convert::TryInto, io::Write};

use crate::{crypto, filen_settings::FilenSettings, queries, retry_settings::RetrySettings, utils, v1::fs::*};
use anyhow::*;
use futures::FutureExt;
use secstr::SecUtf8;

/// Sets how many chunks to download and decrypt concurrently.
const ASYNC_CHUNK_BATCH_SIZE: usize = 16; // Is it a good idea to simply hardcode this param?

/// Gets encrypted file chunk bytes from Filen download server defined by a region and a bucket.
/// Resulting bytes can be decrypted with file key from file metadata.
///
/// Download server endpoint is <filen download server>/<region>/<bucket>/<file uuid>/<chunk index>
pub fn download_chunk(
    region: &str,
    bucket: &str,
    file_uuid: &str,
    chunk_index: u32,
    filen_settings: &FilenSettings,
) -> Result<Vec<u8>> {
    let api_endpoint = utils::filen_file_address_to_api_endpoint(region, bucket, file_uuid, chunk_index);
    queries::download_from_filen(&api_endpoint, filen_settings)
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
    filen_settings: &FilenSettings,
) -> Result<Vec<u8>> {
    let api_endpoint = utils::filen_file_address_to_api_endpoint(region, bucket, file_uuid, chunk_index);
    queries::download_from_filen_async(&api_endpoint, filen_settings).await
}

/// Synchronously downloads and decrypts the file defined by given [DownloadedFileData] from Filen download server.
/// Returns total size of downloaded encrypted chunks.
/// All file chunks are downloaded and decrypted sequentially one by one, with each decrypted chunk immediately written to the provided writer.
pub fn download_and_decrypt_file_from_data_and_key<W: Write>(
    file_data: &DownloadedFileData,
    file_key: &SecUtf8,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
    writer: &mut std::io::BufWriter<W>,
) -> Result<u64> {
    download_and_decrypt_file(
        &file_data.region,
        &file_data.bucket,
        &file_data.uuid,
        file_data.chunks,
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
pub async fn download_and_decrypt_file_from_data_and_key_async<W: Write>(
    file_data: &DownloadedFileData,
    file_key: &SecUtf8,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
    writer: &mut std::io::BufWriter<W>,
) -> Result<u64> {
    download_and_decrypt_file_async(
        &file_data.region,
        &file_data.bucket,
        &file_data.uuid,
        file_data.chunks,
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
                retry_settings.retry(|| download_chunk(region, bucket, file_uuid, chunk_index, filen_settings))?;
            let file_key_bytes: &[u8; 32] = file_key.unsecure().as_bytes().try_into()?;
            let encrypted_bytes_len = encrypted_bytes.len() as u64;
            let decrypted_bytes = crypto::decrypt_file_chunk(&encrypted_bytes, file_key_bytes, version)?;
            writer
                .write_all(&decrypted_bytes)
                .map(|_| encrypted_bytes_len)
                .with_context(|| "Could not write file batch bytes")
        })
        .collect::<Result<Vec<u64>>>()?;

    writer.flush()?;
    Ok(written_chunk_lengths.iter().sum::<u64>())
}

/// Asynchronously downloads the specified file from Filen download server defined by a region and a bucket.
/// Returns total size of downloaded encrypted file chunks.
/// All file chunks are downloaded and decrypted concurrently first, and then written to the provided writer.
pub async fn download_and_decrypt_file_async<W: Write>(
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
        .map(|(batch, encrypted_size)| write_batch(batch, *encrypted_size, writer))
        .collect::<Result<Vec<u64>>>()?;

    writer.flush()?;
    Ok(written_batch_lengths.iter().sum::<u64>())
}

/// Writes batch of file chunks to the given writer and returns total size of passed encrypted batch.
/// If one write in the batch fails, entire batch fails.
fn write_batch<W: Write>(
    batch: &[Vec<u8>],
    batch_encrypted_size: u64,
    writer: &mut std::io::BufWriter<W>,
) -> Result<u64> {
    let written_lengths = batch
        .iter()
        .map(|bytes| {
            writer
                .write_all(bytes)
                .map(|_| batch_encrypted_size)
                .with_context(|| "Could not write file batch bytes")
        })
        .collect::<Result<Vec<u64>>>()?;

    Ok(written_lengths.iter().sum::<u64>())
}

fn decrypt_batch(batch: &[Vec<u8>], version: u32, file_key: &SecUtf8) -> Result<(Vec<Vec<u8>>, u64)> {
    let mut encrypted_total: u64 = 0;
    let encrypted_bytes = batch
        .iter()
        .map(|encrypted_bytes| {
            let file_key_bytes: &[u8; 32] = file_key.unsecure().as_bytes().try_into()?;
            crypto::decrypt_file_chunk(encrypted_bytes, file_key_bytes, version).map(|decrypted_bytes| {
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
    let download_action = |chunk_index: u32| {
        retry_settings.retry_async(move || download_chunk_async(region, bucket, file_uuid, chunk_index, filen_settings))
    };
    futures::future::try_join_all(batch_indices.iter().map(|chunk_index| download_action(*chunk_index))).await
}

/// Calculates batch indices from the total amount of chunks and the single batch size.
fn batch_chunks(file_chunk_count: u32, batch_size: usize) -> Vec<Vec<u32>> {
    let chunk_indicies: Vec<u32> = (0..file_chunk_count).collect();
    chunk_indicies.chunks(batch_size).map(|slice| slice.to_vec()).collect()
}
