#![crate_type = "staticlib"]
#![forbid(unsafe_code)]

use once_cell::sync::Lazy;
#[cfg(not(feature = "async"))]
pub use ureq;
pub use {filen_settings::*, retry_settings::*};
#[cfg(feature = "async")]
pub use {fure, reqwest};
pub use {retry, secstr, uuid};

pub mod crypto;
mod file_chunk_pos;
mod filen_settings;
mod limited_exponential;
pub mod queries;
mod retry_settings;
mod utils;
pub mod v1;

#[cfg(test)]
mod test_utils;

/// Bundle with default Filen settings and retry settings
/// to retry 5 times with 1, 2, 4, 8 and 15 seconds pause between retries.
pub static STANDARD_SETTINGS_BUNDLE: Lazy<SettingsBundle> = Lazy::new(|| SettingsBundle {
    filen: DEFAULT_FILEN_SETTINGS.clone(),
    retry: *STANDARD_RETRIES,
});

/// Groups together several settings which can be used for API queries, when just `FilenSettings` does not cut it.
///
/// Default instance performs no retries.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct SettingsBundle {
    /// Holds Filen-specific information for API calls, such as Filen server URLs.
    pub filen: FilenSettings,

    /// Holds parameters for exponential backoff retry strategy with random jitter.
    pub retry: RetrySettings,
}

impl Default for SettingsBundle {
    /// Default Filen settings, and retry settings which perform no retries.
    fn default() -> Self {
        Self {
            filen: FilenSettings::default(),
            retry: RetrySettings::default(),
        }
    }
}

impl From<SettingsBundle> for FilenSettings {
    fn from(settings_bundle: SettingsBundle) -> Self {
        settings_bundle.filen
    }
}

impl From<SettingsBundle> for RetrySettings {
    fn from(settings_bundle: SettingsBundle) -> Self {
        settings_bundle.retry
    }
}
