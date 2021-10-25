//! This module contains helper methods to perform web queries to Filen servers.
use once_cell::sync::Lazy;
use rand::{thread_rng, Rng};
use reqwest::header;
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::Serialize;
use snafu::{ResultExt, Snafu};
use std::time::Duration;

use crate::filen_settings::FilenSettings;

type Result<T, E = Error> = std::result::Result<T, E>;

static ASYNC_CLIENT: Lazy<reqwest::Client> = Lazy::new(reqwest::Client::new);
static BLOCKING_CLIENT: Lazy<reqwest::blocking::Client> = Lazy::new(reqwest::blocking::Client::new);
static CRATE_USER_AGENT: &str = "Rust-Filen API (+https://github.com/EnoughTea/rust-filen)";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display(
        "Cannot join chosen server URL '{}' with API endpoint '{}': {}",
        api_endpoint,
        chosen_server,
        source
    ))]
    CannotJoinApiEndpoint {
        api_endpoint: String,
        chosen_server: String,
        source: url::ParseError,
    },

    #[snafu(display("Cannot deserialize response body JSON: {}", source))]
    CannotDeserializeResponseBodyJson { source: reqwest::Error },

    #[snafu(display("{}: {}", message, source))]
    WebRequestFailed { message: String, source: reqwest::Error },
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
    );
    deserialize_response(filen_response, || {
        format!("Failed to query Filen API: {}", filen_endpoint)
    })
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
    .await;
    deserialize_response_async(filen_response, || {
        format!("Failed to query Filen API (async): {}", filen_endpoint)
    })
    .await
}

pub(crate) fn download_from_filen(api_endpoint: &str, filen_settings: &FilenSettings) -> Result<Vec<u8>> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.download_servers)?;
    get_bytes(filen_endpoint.as_str(), filen_settings.download_chunk_timeout.as_secs()).context(WebRequestFailed {
        message: format!("Failed to download file chunk from '{}'", filen_endpoint),
    })
}

pub(crate) async fn download_from_filen_async(api_endpoint: &str, filen_settings: &FilenSettings) -> Result<Vec<u8>> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.download_servers)?;
    get_bytes_async(filen_endpoint.as_str(), filen_settings.download_chunk_timeout.as_secs())
        .await
        .context(WebRequestFailed {
            message: format!("Failed to download file chunk (async) from '{}'", filen_endpoint),
        })
}

/// Sends POST with given data blob to one of Filen upload servers.
pub(crate) fn upload_to_filen<U: DeserializeOwned>(
    api_endpoint: &str,
    blob: Vec<u8>,
    filen_settings: &FilenSettings,
) -> Result<U> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.upload_servers)?;
    let upload_result = post_blob(filen_endpoint.as_str(), &blob, filen_settings.request_timeout.as_secs());
    deserialize_response(upload_result, || {
        format!("Failed to upload file chunk to '{}'", filen_endpoint)
    })
}

/// Asynchronously sends POST with given data blob to one of Filen upload servers.
pub(crate) async fn upload_to_filen_async<U: DeserializeOwned>(
    api_endpoint: &str,
    blob: Vec<u8>,
    filen_settings: &FilenSettings,
) -> Result<U> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.upload_servers)?;
    let upload_result = post_blob_async(filen_endpoint.as_str(), &blob, filen_settings.request_timeout.as_secs()).await;
    deserialize_response_async(upload_result, || {
        format!("Failed to upload file chunk (async) to '{}'", filen_endpoint)
    })
    .await
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
        .get(url)
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
fn post_blob(url: &str, blob: &[u8], timeout_secs: u64) -> Result<reqwest::blocking::Response, reqwest::Error> {
    BLOCKING_CLIENT
        .post(url)
        .body(blob.to_owned())
        .header(header::USER_AGENT, CRATE_USER_AGENT)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
}

/// Asynchronously sends POST with given blob and timeout to the specified URL.
async fn post_blob_async(url: &str, blob: &[u8], timeout_secs: u64) -> Result<reqwest::Response, reqwest::Error> {
    ASYNC_CLIENT
        .post(url)
        .body(blob.to_owned())
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
    chosen_server.join(api_endpoint).context(CannotJoinApiEndpoint {
        api_endpoint,
        chosen_server: chosen_server.to_string(),
    })
}

fn deserialize_response<U, F>(
    request_result: Result<reqwest::blocking::Response, reqwest::Error>,
    error_message: F,
) -> Result<U>
where
    U: DeserializeOwned,
    F: FnOnce() -> String,
{
    let response = request_result.context(WebRequestFailed {
        message: error_message(),
    })?;
    response.json::<U>().context(CannotDeserializeResponseBodyJson {})
}

async fn deserialize_response_async<U, F>(
    request_result: Result<reqwest::Response, reqwest::Error>,
    error_message: F,
) -> Result<U>
where
    U: DeserializeOwned,
    F: FnOnce() -> String,
{
    let response = request_result.context(WebRequestFailed {
        message: error_message(),
    })?;
    response.json::<U>().await.context(CannotDeserializeResponseBodyJson {})
}
