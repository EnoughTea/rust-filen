//! Contains [FilenSettings] used to provide Filen-specific information to API calls.
use std::time::Duration;

use once_cell::sync::Lazy;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_with::*;

pub static DEFAULT_FILEN_SETTINGS: Lazy<FilenSettings> = Lazy::new(FilenSettings::default);

static DEFAULT_API_SERVERS: Lazy<Vec<Url>> = Lazy::new(|| {
    vec![
        Url::parse("https://api.filen.io/").unwrap(),
        Url::parse("https://api.filen-1.xyz/").unwrap(),
        Url::parse("https://api.filen-2.xyz/").unwrap(),
        Url::parse("https://api.filen-3.xyz/").unwrap(),
        Url::parse("https://api.filen-4.xyz/").unwrap(),
        Url::parse("https://api.filen-5.xyz/").unwrap(),
    ]
});

static DEFAULT_DOWNLOAD_SERVERS: Lazy<Vec<Url>> = Lazy::new(|| {
    vec![
        Url::parse("https://down.filen.io/").unwrap(),
        Url::parse("https://down.filen-1.xyz/").unwrap(),
        Url::parse("https://down.filen-2.xyz/").unwrap(),
        Url::parse("https://down.filen-3.xyz/").unwrap(),
        Url::parse("https://down.filen-4.xyz/").unwrap(),
        Url::parse("https://down.filen-5.xyz/").unwrap(),
    ]
});

static DEFAULT_UPLOAD_SERVERS: Lazy<Vec<Url>> = Lazy::new(|| {
    vec![
        Url::parse("https://up.filen.io/").unwrap(),
        Url::parse("https://up.filen-1.xyz/").unwrap(),
        Url::parse("https://up.filen-2.xyz/").unwrap(),
        Url::parse("https://up.filen-3.xyz/").unwrap(),
        Url::parse("https://up.filen-4.xyz/").unwrap(),
        Url::parse("https://up.filen-5.xyz/").unwrap(),
    ]
});

const DOWNLOAD_TIMEOUT_SECS: u64 = 3600;
const REQUEST_TIMEOUT_SECS: u64 = 120;
const UPLOAD_TIMEOUT_SECS: u64 = 3600;

/// Filen-specific information for API calls, such as Filen server URLs.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FilenSettings {
    /// List of API servers which will be randomly queried.
    #[serde(rename = "apiServers")]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub api_servers: Vec<Url>,

    #[serde(rename = "downloadServers")]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub download_servers: Vec<Url>,

    #[serde(rename = "upServers")]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub upload_servers: Vec<Url>,

    /// File chunk download timeout.
    pub download_chunk_timeout: Duration,

    /// API requests timeout.
    pub request_timeout: Duration,

    /// File chunk upload timeout.
    pub upload_chunk_timeout: Duration,
}

impl Default for FilenSettings {
    fn default() -> Self {
        Self {
            api_servers: DEFAULT_API_SERVERS.clone(),
            download_servers: DEFAULT_DOWNLOAD_SERVERS.clone(),
            upload_servers: DEFAULT_UPLOAD_SERVERS.clone(),
            download_chunk_timeout: Duration::from_secs(DOWNLOAD_TIMEOUT_SECS),
            request_timeout: Duration::from_secs(REQUEST_TIMEOUT_SECS),
            upload_chunk_timeout: Duration::from_secs(UPLOAD_TIMEOUT_SECS),
        }
    }
}
