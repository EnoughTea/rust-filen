//! This module contains helper methods to perform web queries to Filen servers.
use anyhow::*;
use once_cell::sync::Lazy;
use rand::{thread_rng, Rng};
use reqwest::header;
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::Duration;

use crate::errors::*;
use crate::filen_settings::FilenSettings;
use crate::retry_settings::RetrySettings;

static ASYNC_CLIENT: Lazy<reqwest::Client> = Lazy::new(reqwest::Client::new);
static BLOCKING_CLIENT: Lazy<reqwest::blocking::Client> = Lazy::new(reqwest::blocking::Client::new);
static CRATE_USER_AGENT: &str = "Rust-Filen API (+https://github.com/EnoughTea/rust-filen)";

/// Sends POST with given payload to one of Filen API servers.
pub(crate) fn query_filen_api<T: Serialize + ?Sized, U: DeserializeOwned>(
    api_endpoint: &str,
    payload: &T,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<U> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.api_servers)?;
    let query_action = || {
        let filen_response = post_json(
            filen_endpoint.as_str(),
            payload,
            filen_settings.request_timeout.as_secs(),
        );
        deserialize_response(filen_response, || {
            format!("Failed to query Filen API: {}", filen_endpoint)
        })
    };

    retry_operation(retry_settings, query_action)
}

/// Asynchronously sends POST with given payload to one of Filen API servers.
pub(crate) async fn query_filen_api_async<T: Serialize + ?Sized, U: DeserializeOwned>(
    api_endpoint: &str,
    payload: &T,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<U> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.api_servers)?;
    let query_action = || async {
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
    };

    retry_operation_async(retry_settings, query_action).await
}

pub(crate) fn download_from_filen(
    api_endpoint: &str,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<Vec<u8>> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.download_servers)?;
    let download_action = || {
        get_bytes(filen_endpoint.as_str(), filen_settings.download_chunk_timeout.as_secs()).map_err(|err| {
            let message = &format!("Failed to download file chunk from: {}", filen_endpoint);
            anyhow!(web_request_fail(message, err))
        })
    };

    retry_operation(retry_settings, download_action)
}

pub(crate) async fn download_from_filen_async(
    api_endpoint: &str,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<Vec<u8>> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.download_servers)?;
    let download_action = || async {
        get_bytes_async(filen_endpoint.as_str(), filen_settings.download_chunk_timeout.as_secs())
            .await
            .map_err(|err| {
                let message = &format!("Failed to download file chunk (async) from: {}", filen_endpoint);
                anyhow!(web_request_fail(message, err))
            })
    };

    retry_operation_async(retry_settings, download_action).await
}

/// Sends POST with given data blob to one of Filen upload servers.
pub(crate) fn upload_to_filen<U: DeserializeOwned>(
    api_endpoint: &str,
    blob: Vec<u8>,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<U> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.upload_servers)?;
    let upload_action = || {
        let upload_result = post_blob(filen_endpoint.as_str(), &blob, filen_settings.request_timeout.as_secs());
        deserialize_response(upload_result, || {
            format!("Failed to upload file chunk to: {}", filen_endpoint)
        })
    };
    retry_operation(retry_settings, upload_action)
}

/// Asynchronously sends POST with given data blob to one of Filen upload servers.
pub(crate) async fn upload_to_filen_async<U: DeserializeOwned>(
    api_endpoint: &str,
    blob: Vec<u8>,
    retry_settings: &RetrySettings,
    filen_settings: &FilenSettings,
) -> Result<U> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.upload_servers)?;
    let upload_action = || async {
        let upload_result =
            post_blob_async(filen_endpoint.as_str(), &blob, filen_settings.request_timeout.as_secs()).await;
        deserialize_response_async(upload_result, || {
            format!("Failed to upload file chunk (async) to: {}", filen_endpoint)
        })
        .await
    };

    retry_operation_async(retry_settings, upload_action).await
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
    chosen_server.join(api_endpoint).map_err(|_| {
        anyhow!(bad_argument(&format!(
            "Cannot join chosen server URL '{}' with API endpoint '{}'",
            chosen_server, api_endpoint
        )))
    })
}

async fn retry_operation_async<T, CF>(retry_settings: &RetrySettings, operation: CF) -> Result<T>
where
    CF: fure::CreateFuture<T, Error>,
{
    let exp_backoff = retry_settings.get_exp_backoff_iterator();
    let policy = fure::policies::attempts(fure::policies::backoff(exp_backoff), retry_settings.max_tries);
    fure::retry(operation, policy).await
}

fn retry_operation<O, R, OR>(retry_settings: &RetrySettings, operation: O) -> Result<R>
where
    O: FnMut() -> OR,
    OR: Into<retry::OperationResult<R, Error>>,
{
    let policy = retry_settings.get_exp_backoff_iterator();
    let retry_result = retry::retry(policy, operation);
    retry_result.map_err(|retry_err| match retry_err {
        retry::Error::Operation { error, .. } => error,
        retry::Error::Internal(description) => anyhow!(unknown(&description)),
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
    match request_result {
        Ok(filen_response) => raw_deserialize_response_to_json(filen_response),
        Err(err) => Err(anyhow!(web_request_fail(&error_message(), err))),
    }
}

async fn deserialize_response_async<U, F>(
    request_result: Result<reqwest::Response, reqwest::Error>,
    error_message: F,
) -> Result<U>
where
    U: DeserializeOwned,
    F: FnOnce() -> String,
{
    match request_result {
        Ok(filen_response) => raw_deserialize_response_to_json_async(filen_response).await,
        Err(err) => Err(anyhow!(web_request_fail(&error_message(), err))),
    }
}

fn raw_deserialize_response_to_json<U: DeserializeOwned>(response: reqwest::blocking::Response) -> Result<U> {
    response
        .json::<U>()
        .map_err(|err| anyhow!(web_request_fail("Cannot deserialize response body JSON", err)))
}

async fn raw_deserialize_response_to_json_async<U: DeserializeOwned>(response: reqwest::Response) -> Result<U> {
    response
        .json::<U>()
        .await
        .map_err(|err| anyhow!(web_request_fail("Cannot deserialize response body JSON", err)))
}
