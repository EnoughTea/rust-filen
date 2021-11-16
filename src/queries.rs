//! This module contains helper methods to perform arbitrary web queries to Filen servers.
//! You can use it to add some missing API query or re-implement some of them to your liking.
use once_cell::sync::Lazy;
use rand::{thread_rng, Rng};
use serde::de::DeserializeOwned;
use serde::Serialize;
use snafu::{ResultExt, Snafu};
#[cfg(not(feature = "async"))]
use std::io::Read;
use std::time::Duration;
use url::Url;

use crate::filen_settings::FilenSettings;

type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(feature = "async")]
static ASYNC_CLIENT: Lazy<reqwest::Client> =
    Lazy::new(|| reqwest::Client::builder().user_agent(CRATE_USER_AGENT).build().unwrap());
#[cfg(feature = "async")]
static BLOCKING_CLIENT: Lazy<reqwest::blocking::Client> = Lazy::new(|| {
    reqwest::blocking::Client::builder()
        .user_agent(CRATE_USER_AGENT)
        .build()
        .unwrap()
});
#[cfg(not(feature = "async"))]
static AGENT: Lazy<ureq::Agent> = Lazy::new(|| ureq::AgentBuilder::new().user_agent(CRATE_USER_AGENT).build());

const CRATE_USER_AGENT: &str = "Rust-Filen API (+https://github.com/EnoughTea/rust-filen)";

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

    #[cfg(feature = "async")]
    #[snafu(display("Cannot deserialize response body JSON: {}", source))]
    ReqwestCannotDeserializeResponseBodyJson { source: reqwest::Error },

    #[cfg(not(feature = "async"))]
    #[snafu(display("Cannot deserialize response body JSON: {}", source))]
    UreqCannotDeserializeResponseBodyJson { source: std::io::Error },

    #[cfg(feature = "async")]
    #[snafu(display("{}: {}", message, source))]
    ReqwestWebRequestFailed { message: String, source: reqwest::Error },

    #[cfg(not(feature = "async"))]
    #[snafu(display("{}: {}", message, source))]
    UreqWebRequestFailed { message: String, source: ureq::Error },
}

/// Sends POST with given payload to one of Filen API servers.
/// `api_endpoint` parameter should be relative, eg `/v1/some/api`, as one of the Filen servers will be chosen randomly.
pub fn query_filen_api<T: Serialize + ?Sized, U: DeserializeOwned>(
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
/// `api_endpoint` parameter should be relative, eg `/v1/some/api`, as one of the Filen servers will be chosen randomly.
#[cfg(feature = "async")]
pub async fn query_filen_api_async<T: Serialize + ?Sized + Sync, U: DeserializeOwned>(
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

pub fn download_from_filen(api_endpoint: &str, filen_settings: &FilenSettings) -> Result<Vec<u8>> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.download_servers)?;
    let response = get_bytes(filen_endpoint.as_str(), filen_settings.download_chunk_timeout.as_secs());
    #[cfg(feature = "async")]
    {
        response.context(ReqwestWebRequestFailed {
            message: format!("Failed to download file chunk from '{}'", filen_endpoint),
        })
    }
    #[cfg(not(feature = "async"))]
    {
        response.context(UreqWebRequestFailed {
            message: format!("Failed to download file chunk from '{}'", filen_endpoint),
        })
    }
}

#[cfg(feature = "async")]
pub async fn download_from_filen_async(api_endpoint: &str, filen_settings: &FilenSettings) -> Result<Vec<u8>> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.download_servers)?;
    get_bytes_async(filen_endpoint.as_str(), filen_settings.download_chunk_timeout.as_secs())
        .await
        .context(ReqwestWebRequestFailed {
            message: format!("Failed to download file chunk (async) from '{}'", filen_endpoint),
        })
}

/// Sends POST with given data blob to one of Filen upload servers.
pub fn upload_to_filen<U: DeserializeOwned>(
    api_endpoint: &str,
    blob: &[u8],
    filen_settings: &FilenSettings,
) -> Result<U> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.upload_servers)?;
    let upload_result = post_blob(filen_endpoint.as_str(), blob, filen_settings.request_timeout.as_secs());
    deserialize_response(upload_result, || {
        format!("Failed to upload file chunk to '{}'", filen_endpoint)
    })
}

/// Asynchronously sends POST with given data blob to one of Filen upload servers.
#[cfg(feature = "async")]
pub async fn upload_to_filen_async<U: DeserializeOwned>(
    api_endpoint: &str,
    blob: &[u8],
    filen_settings: &FilenSettings,
) -> Result<U> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.upload_servers)?;
    let upload_result = post_blob_async(filen_endpoint.as_str(), blob, filen_settings.request_timeout.as_secs()).await;
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
#[cfg(not(feature = "async"))]
fn get(url: &str, timeout_secs: u64) -> Result<ureq::Response, ureq::Error> {
    AGENT.get(url).timeout(Duration::from_secs(timeout_secs)).call()
}

#[cfg(feature = "async")]
/// Sends GET with the given timeout to the specified URL.
fn get(url: &str, timeout_secs: u64) -> Result<reqwest::blocking::Response, reqwest::Error> {
    BLOCKING_CLIENT
        .get(url)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
}

/// Asynchronously sends GET with the given timeout to the specified URL.
#[cfg(feature = "async")]
async fn get_async(url: &str, timeout_secs: u64) -> Result<reqwest::Response, reqwest::Error> {
    ASYNC_CLIENT
        .get(url)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
        .await
}

/// Sends GET with the given timeout to the specified URL.
#[cfg(not(feature = "async"))]
fn get_bytes(filen_endpoint: &str, timeout_secs: u64) -> Result<Vec<u8>, ureq::Error> {
    let response = get(filen_endpoint, timeout_secs)?;
    let content_length = response
        .header("Content-Length")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1024 * 1024);

    let mut bytes: Vec<u8> = Vec::with_capacity(content_length);
    response.into_reader().read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Sends GET with the given timeout to the specified URL.
#[cfg(feature = "async")]
fn get_bytes(filen_endpoint: &str, timeout_secs: u64) -> Result<Vec<u8>, reqwest::Error> {
    let response = get(filen_endpoint, timeout_secs)?;
    response.bytes().map(|bytes| bytes.to_vec())
}

#[cfg(feature = "async")]
async fn get_bytes_async(filen_endpoint: &str, timeout_secs: u64) -> Result<Vec<u8>, reqwest::Error> {
    let response = get_async(filen_endpoint, timeout_secs).await?;
    response.bytes().await.map(|bytes| bytes.to_vec())
}

/// Sends POST with given blob and timeout to the specified URL.
#[cfg(not(feature = "async"))]
fn post_blob(url: &str, blob: &[u8], timeout_secs: u64) -> Result<ureq::Response, ureq::Error> {
    AGENT
        .post(url)
        .timeout(Duration::from_secs(timeout_secs))
        .send_bytes(blob)
}

/// Sends POST with given blob and timeout to the specified URL.
#[cfg(feature = "async")]
fn post_blob(url: &str, blob: &[u8], timeout_secs: u64) -> Result<reqwest::blocking::Response, reqwest::Error> {
    BLOCKING_CLIENT
        .post(url)
        .body(blob.to_owned())
        .timeout(Duration::from_secs(timeout_secs))
        .send()
}

/// Asynchronously sends POST with given blob and timeout to the specified URL.
#[cfg(feature = "async")]
async fn post_blob_async(url: &str, blob: &[u8], timeout_secs: u64) -> Result<reqwest::Response, reqwest::Error> {
    ASYNC_CLIENT
        .post(url)
        .body(blob.to_owned())
        .timeout(Duration::from_secs(timeout_secs))
        .send()
        .await
}

/// Sends POST with given payload and timeout to the specified URL.
#[cfg(not(feature = "async"))]
pub(crate) fn post_json<T: Serialize + ?Sized>(
    url: &str,
    payload: &T,
    timeout_secs: u64,
) -> Result<ureq::Response, ureq::Error> {
    use serde_json::json;

    AGENT
        .post(url)
        .timeout(Duration::from_secs(timeout_secs))
        .send_json(json!(payload))
}

/// Sends POST with given payload and timeout to the specified URL.
#[cfg(feature = "async")]
fn post_json<T: Serialize + ?Sized>(
    url: &str,
    payload: &T,
    timeout_secs: u64,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    BLOCKING_CLIENT
        .post(url)
        .json(payload)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
}

/// Asynchronously sends POST with given payload and timeout to the specified URL.
#[cfg(feature = "async")]
async fn post_json_async<T: Serialize + ?Sized + Sync>(
    url: &str,
    payload: &T,
    timeout_secs: u64,
) -> Result<reqwest::Response, reqwest::Error> {
    ASYNC_CLIENT
        .post(url)
        .json(payload)
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

#[cfg(not(feature = "async"))]
fn deserialize_response<U, F>(request_result: Result<ureq::Response, ureq::Error>, error_message: F) -> Result<U>
where
    U: DeserializeOwned,
    F: FnOnce() -> String,
{
    let response = request_result.context(UreqWebRequestFailed {
        message: error_message(),
    })?;
    response
        .into_json::<U>()
        .context(UreqCannotDeserializeResponseBodyJson {})
}

#[cfg(feature = "async")]
fn deserialize_response<U, F>(
    request_result: Result<reqwest::blocking::Response, reqwest::Error>,
    error_message: F,
) -> Result<U>
where
    U: DeserializeOwned,
    F: Send + FnOnce() -> String,
{
    let response = request_result.context(ReqwestWebRequestFailed {
        message: error_message(),
    })?;
    response
        .json::<U>()
        .context(ReqwestCannotDeserializeResponseBodyJson {})
}

#[cfg(feature = "async")]
async fn deserialize_response_async<U, F>(
    request_result: Result<reqwest::Response, reqwest::Error>,
    error_message: F,
) -> Result<U>
where
    U: DeserializeOwned,
    F: Send + FnOnce() -> String,
{
    let response = request_result.context(ReqwestWebRequestFailed {
        message: error_message(),
    })?;
    response
        .json::<U>()
        .await
        .context(ReqwestCannotDeserializeResponseBodyJson {})
}
