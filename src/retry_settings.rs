use std::time::Duration;

use crate::limited_exponential::LimitedExponential;

const RETRY_EXP_FACTOR: u32 = 2;
const RETRY_INITIAL_DELAY_MILLIS: u64 = 500;
const RETRY_MAX_DELAY_MILLIS: u64 = 10000;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RetrySettings {
    pub initial_delay: Duration,
    pub exp_factor: u32,
    pub max_delay: Duration,
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

    pub fn from_max_tries(max_tries: usize) -> RetrySettings {
        let mut result = RetrySettings::default();
        result.max_tries = max_tries;
        result
    }

    pub(crate) fn to_exp_backoff_iterator(&self) -> impl Iterator<Item = Duration> {
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
            max_tries: 1,
        }
    }
}
