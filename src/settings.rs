use once_cell::sync::Lazy;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_with::*;

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
        Url::parse("https://api.filen.io/").unwrap(),
        Url::parse("https://api.filen-1.xyz/").unwrap(),
        Url::parse("https://api.filen-2.xyz/").unwrap(),
        Url::parse("https://api.filen-3.xyz/").unwrap(),
        Url::parse("https://api.filen-4.xyz/").unwrap(),
        Url::parse("https://api.filen-5.xyz/").unwrap(),
    ]
});

#[serde_as]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FilenSettings {
    #[serde(rename = "apiServers")]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub api_servers: Vec<Url>,

    #[serde(rename = "downloadServers")]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub download_servers: Vec<Url>,
}

impl Default for FilenSettings {
    fn default() -> Self {
        Self {
            api_servers: DEFAULT_API_SERVERS.clone(),
            download_servers: DEFAULT_DOWNLOAD_SERVERS.clone(),
        }
    }
}
