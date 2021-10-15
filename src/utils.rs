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
use crate::settings::FilenSettings;

static ASYNC_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| reqwest::Client::new());
static BLOCKING_CLIENT: Lazy<reqwest::blocking::Client> = Lazy::new(|| reqwest::blocking::Client::new());
static CRATE_USER_AGENT: &str = "Rust-Filen API (+https://github.com/EnoughTea/rust-filen)";

/// Generate random alphanumeric string of the specified length.
pub(crate) fn random_alpha_string(size: usize) -> String {
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
    let filen_response = post(filen_endpoint.as_str(), payload, filen_settings.timeout_secs)?;
    Ok(filen_response.json::<U>()?)
}

/// Asynchronously sends POST with given payload to one of Filen API servers.
pub(crate) async fn query_filen_api_async<T: Serialize + ?Sized, U: DeserializeOwned>(
    api_endpoint: &str,
    payload: &T,
    filen_settings: &FilenSettings,
) -> Result<U> {
    let filen_endpoint = produce_filen_endpoint(api_endpoint, &filen_settings.api_servers)?;
    let filen_response = post_async(filen_endpoint.as_str(), payload, filen_settings.timeout_secs).await?;
    Ok(filen_response.json::<U>().await?)
}

/// Reads file at the specified path to the end.
pub(crate) fn read_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>> {
    let mut f = File::open(&file_path)?;
    let mut buffer = Vec::new();
    let _bytes_read = f.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Randomly chooses one of the URLs in the given slice.
fn choose_filen_server(servers: &[Url]) -> &Url {
    let chosen_server_index = thread_rng().gen_range(0..servers.len());
    &servers[chosen_server_index]
}

/// Sends POST with given payload and timeout to the specified URL.
fn post<T: Serialize + ?Sized>(url: &str, payload: &T, timeout_secs: u64) -> Result<reqwest::blocking::Response> {
    BLOCKING_CLIENT
        .post(url)
        .json(&payload)
        .header(header::USER_AGENT, CRATE_USER_AGENT)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
        .map_err(|err| anyhow!(web_request_fail(&format!("Failed to send POST to: {}", url), err)))
}

/// Asynchronously sends POST with given payload and timeout to the specified URL.
async fn post_async<T: Serialize + ?Sized>(url: &str, payload: &T, timeout_secs: u64) -> Result<reqwest::Response> {
    ASYNC_CLIENT
        .post(url)
        .json(&payload)
        .header(header::USER_AGENT, CRATE_USER_AGENT)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
        .await
        .map_err(|err| {
            let message = &format!("Failed to send POST (async) to: {}", url);
            anyhow!(web_request_fail(message, err))
        })
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
}
