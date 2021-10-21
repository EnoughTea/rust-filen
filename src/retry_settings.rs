use std::time::Duration;

use once_cell::sync::Lazy;

use crate::limited_exponential::LimitedExponential;

const RETRY_EXP_FACTOR: u32 = 2;
const RETRY_INITIAL_DELAY_MILLIS: u64 = 500;
const RETRY_MAX_DELAY_MILLIS: u64 = 10000;
const DEFAULT_MAX_TRIES: usize = 0;

/// Static instance of zero-retries [RetrySettings].
pub static NO_RETRIES: Lazy<RetrySettings> = Lazy::new(RetrySettings::default);

/// Parameters for exponential backoff retry strategy. Default instance performs no retries.
///
/// Instance returned from [RetrySettings::from_max_tries] has [RetrySettings::max_delay] set to [RETRY_MAX_DELAY_MILLIS] by default,
/// so an API query with RetrySettings::from_max_tries(6) call will take at most ≈half a minute,
/// with every additional retry adding another [RetrySettings::max_delay].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RetrySettings {
    /// Initial delay for exponential backoff.
    pub initial_delay: Duration,

    /// Exponential backoff factor. If set to 0, [max_delay] will always be used as a delay.
    pub exp_factor: u32,

    /// Max delay for exponential backoff.
    pub max_delay: Duration,

    /// Amount of retries to perform when something fails. If set to 0, no retries will be made.
    pub max_tries: usize,
}

impl RetrySettings {
    pub fn new(max_tries: usize, initial_delay: Duration, exp_factor: u32, max_delay: Duration) -> RetrySettings {
        RetrySettings {
            initial_delay,
            exp_factor,
            max_delay,
            max_tries,
        }
    }

    /// Creates exponential backoff retry strategy with given amount of max retries.
    pub fn from_max_tries(max_tries: usize) -> RetrySettings {
        RetrySettings {
            max_tries,
            ..RetrySettings::default()
        }
    }

    pub(crate) fn get_exp_backoff_iterator(&self) -> impl Iterator<Item = Duration> {
        LimitedExponential::from_retry_settings(self)
            //.map(retry::delay::jitter) is kinda meh, I see no reason to jitter for now
            .take(self.max_tries)
    }
}

impl Default for RetrySettings {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(RETRY_INITIAL_DELAY_MILLIS),
            exp_factor: RETRY_EXP_FACTOR,
            max_delay: Duration::from_millis(RETRY_MAX_DELAY_MILLIS),
            max_tries: DEFAULT_MAX_TRIES,
        }
    }
}
