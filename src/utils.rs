//! This module contains general purpose functions (aka dump).
use anyhow::*;
use once_cell::sync::Lazy;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use reqwest::header;
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::File;
use std::io::Read;
use std::num::ParseIntError;
use std::path::Path;
use std::time::Duration;

use crate::errors::*;
use crate::retry_settings::RetrySettings;
use crate::settings::FilenSettings;

static ASYNC_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| reqwest::Client::new());
static BLOCKING_CLIENT: Lazy<reqwest::blocking::Client> = Lazy::new(|| reqwest::blocking::Client::new());
static CRATE_USER_AGENT: &str = "Rust-Filen API (+https://github.com/EnoughTea/rust-filen)";

/// Generate random alphanumeric string of the specified length.
pub(crate) fn random_alphanumeric_string(size: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect()
}

/// Converts the specified bytes into corresponding hex-encoded string.
pub(crate) fn byte_vec_to_hex_string(data: &Vec<u8>) -> String {
    data.iter().map(|byte| format!("{:02x}", byte)).collect()
}

/// Converts the specified bytes into corresponding hex-encoded string.
pub(crate) fn byte_slice_to_hex_string(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{:02x}", byte)).collect()
}

/// Converts the specified hex-encoded string into bytes.
pub(crate) fn hex_string_to_bytes(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

/// Sends POST with given payload to one of Filen API servers.
pub(crate) fn query_filen_api<T: Serialize + ?Sized, U: DeserializeOwned>(
    api_endpoint: &str,
    payload: &T,
    filen_settings: &FilenSettings,
) -> Result<U> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.api_servers)?;
    let filen_response = post_json(
        filen_endpoint.as_str(),
        payload,
        filen_settings.request_timeout.as_secs(),
    )?;
    Ok(filen_response.json::<U>()?)
}

/// Asynchronously sends POST with given payload to one of Filen API servers.
pub(crate) async fn query_filen_api_async<T: Serialize + ?Sized, U: DeserializeOwned>(
    api_endpoint: &str,
    payload: &T,
    filen_settings: &FilenSettings,
) -> Result<U> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.api_servers)?;
    let filen_response = post_json_async(
        filen_endpoint.as_str(),
        payload,
        filen_settings.request_timeout.as_secs(),
    )
    .await?;
    Ok(filen_response.json::<U>().await?)
}

pub(crate) fn download_from_filen(
    api_endpoint: &str,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<Vec<u8>> {
    let filen_endpoint = produce_filen_endpoint(&api_endpoint, &filen_settings.download_servers)?;
    let download_action = || {
        get_bytes(filen_endpoint.as_str(), filen_settings.download_chunk_timeout.as_secs()).map_err(|err| {
            let message = &format!("Failed to download file chunk from: {}", filen_endpoint);
            anyhow!(web_request_fail(message, err))
        })
    };

    let policy = retry_settings.to_exp_backoff_iterator();
    let retry_result = retry::retry(policy, download_action);
    retry_result.map_err(|retry_err| match retry_err {
        retry::Error::Operation { error, .. } => error,
        retry::Error::Internal(description) => anyhow!(unknown(&description)),
    })
}

pub(crate) async fn download_from_filen_async(
    api_endpoint: &str,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<Vec<u8>> {
    let filen_endpoint = produce_filen_endpoint(&api_endpoint, &filen_settings.download_servers)?;
    let download_action = || async {
        get_bytes_async(filen_endpoint.as_str(), filen_settings.download_chunk_timeout.as_secs())
            .await
            .map_err(|err| {
                let message = &format!("Failed to download file chunk (async) from: {}", filen_endpoint);
                anyhow!(web_request_fail(message, err))
            })
    };

    let exp_backoff = retry_settings.to_exp_backoff_iterator();
    let policy = fure::policies::attempts(fure::policies::backoff(exp_backoff), retry_settings.max_tries);
    fure::retry(download_action, policy).await
}

/// Sends POST with given data blob to one of Filen upload servers.
pub(crate) fn upload_to_filen<U: DeserializeOwned>(
    api_endpoint: &str,
    blob: Vec<u8>,
    filen_settings: &FilenSettings,
) -> Result<U> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.upload_servers)?;
    let filen_response = post_blob(filen_endpoint.as_str(), blob, filen_settings.request_timeout.as_secs())?;
    Ok(filen_response.json::<U>()?)
}

/// Asynchronously sends POST with given data blob to one of Filen upload servers.
pub(crate) async fn upload_to_filen_async<U: DeserializeOwned>(
    api_endpoint: &str,
    blob: Vec<u8>,
    filen_settings: &FilenSettings,
) -> Result<U> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.upload_servers)?;
    let filen_response =
        post_blob_async(filen_endpoint.as_str(), blob, filen_settings.request_timeout.as_secs()).await?;
    Ok(filen_response.json::<U>().await?)
}

/// Reads file at the specified path to the end.
pub(crate) fn read_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>> {
    let mut f = File::open(&file_path)?;
    let mut buffer = Vec::new();
    let _bytes_read = f.read_to_end(&mut buffer)?;
    Ok(buffer)
}

pub(crate) fn filen_file_address_to_api_endpoint(
    region: &str,
    bucket: &str,
    file_uuid: &str,
    chunk_index: u32,
) -> String {
    vec![region, bucket, file_uuid, &chunk_index.to_string()]
        .join("/")
        .replace("//", "/")
}

/// Randomly chooses one of the URLs in the given slice.
fn choose_filen_server(servers: &[Url]) -> &Url {
    let chosen_server_index = thread_rng().gen_range(0..servers.len());
    &servers[chosen_server_index]
}

/// Sends GET with the given timeout to the specified URL.
fn get(url: &str, timeout_secs: u64) -> Result<reqwest::blocking::Response, reqwest::Error> {
    BLOCKING_CLIENT
        .get(url)
        .header(header::USER_AGENT, CRATE_USER_AGENT)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
}

/// Asynchronously sends GET with the given timeout to the specified URL.
async fn get_async(url: &str, timeout_secs: u64) -> Result<reqwest::Response, reqwest::Error> {
    ASYNC_CLIENT
        .post(url)
        .header(header::USER_AGENT, CRATE_USER_AGENT)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
        .await
}

fn get_bytes(filen_endpoint: &str, timeout_secs: u64) -> Result<Vec<u8>, reqwest::Error> {
    let response = get(filen_endpoint, timeout_secs)?;
    response.bytes().map(|bytes| bytes.to_vec())
}

async fn get_bytes_async(filen_endpoint: &str, timeout_secs: u64) -> Result<Vec<u8>, reqwest::Error> {
    let response = get_async(filen_endpoint, timeout_secs).await?;
    response.bytes().await.map(|bytes| bytes.to_vec())
}

/// Sends POST with given blob and timeout to the specified URL.
fn post_blob(url: &str, blob: Vec<u8>, timeout_secs: u64) -> Result<reqwest::blocking::Response, reqwest::Error> {
    BLOCKING_CLIENT
        .post(url)
        .body(blob)
        .header(header::USER_AGENT, CRATE_USER_AGENT)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
}

/// Asynchronously sends POST with given blob and timeout to the specified URL.
async fn post_blob_async(url: &str, blob: Vec<u8>, timeout_secs: u64) -> Result<reqwest::Response, reqwest::Error> {
    ASYNC_CLIENT
        .post(url)
        .body(blob)
        .header(header::USER_AGENT, CRATE_USER_AGENT)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
        .await
}

/// Sends POST with given payload and timeout to the specified URL.
fn post_json<T: Serialize + ?Sized>(
    url: &str,
    payload: &T,
    timeout_secs: u64,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    BLOCKING_CLIENT
        .post(url)
        .json(&payload)
        .header(header::USER_AGENT, CRATE_USER_AGENT)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
}

/// Asynchronously sends POST with given payload and timeout to the specified URL.
async fn post_json_async<T: Serialize + ?Sized>(
    url: &str,
    payload: &T,
    timeout_secs: u64,
) -> Result<reqwest::Response, reqwest::Error> {
    ASYNC_CLIENT
        .post(url)
        .json(&payload)
        .header(header::USER_AGENT, CRATE_USER_AGENT)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
        .await
}

/// Randomly chooses one of the URLs in servers slice and joins it with the given API endpoint path.
fn produce_filen_endpoint(api_endpoint: &str, servers: &[Url]) -> Result<Url> {
    let chosen_server = choose_filen_server(servers);
    chosen_server.join(api_endpoint).map_err(|_| {
        anyhow!(bad_argument(&format!(
            "Cannot join chosen server URL '{}' with API endpoint '{}'",
            chosen_server, api_endpoint
        )))
    })
}

/// This macro generates a simple [std::fmt::Display] implementation using Serde's json! on self.
macro_rules! display_from_json {
    (
        $target_data_type:ty
    ) => {
        impl std::fmt::Display for $target_data_type {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match *self {
                    _ => write!(f, "{}", serde_json::json!(self)),
                }
            }
        }
    };
}
// TODO: Should this be a derive proc macro?
pub(crate) use display_from_json;

#[cfg(test)]
mod tests {
    use crate::utils::*;

    #[test]
    fn byte_vec_to_hex_should_return_hex_codes_for_non_empty_bytes() {
        let expected_hash_hex = "f82a1812080acab7ed5751e7193984565c8b159be00bb6c66eac70ff0c8ad8dd";
        let hash: Vec<u8> = vec![
            248, 42, 24, 18, 8, 10, 202, 183, 237, 87, 81, 231, 25, 57, 132, 86, 92, 139, 21, 155, 224, 11, 182, 198,
            110, 172, 112, 255, 12, 138, 216, 221,
        ];

        let hash_hex = byte_vec_to_hex_string(&hash);

        assert_eq!(expected_hash_hex, hash_hex);
    }

    #[test]
    fn filen_file_address_to_api_endpoint_should_join_parts_correctly() {
        let expected = "de-1/filen-1/b5ec90d2-957c-4481-b211-08a68accd1b2/0";
        let file_url = filen_file_address_to_api_endpoint("de-1", "filen-1", "b5ec90d2-957c-4481-b211-08a68accd1b2", 0);
        assert_eq!(file_url, expected);
    }
}
