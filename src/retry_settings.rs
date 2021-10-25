use std::time::Duration;

use crate::limited_exponential::LimitedExponential;
use once_cell::sync::Lazy;

const RETRY_EXP_FACTOR: u32 = 2;
const RETRY_INITIAL_DELAY_MILLIS: u64 = 1000;
const RETRY_MAX_DELAY_MILLIS: u64 = 15000;

/// 'No retries' retry settings with [RetrySettings::max_tries] set to 0.
pub static NO_RETRIES: Lazy<RetrySettings> = Lazy::new(RetrySettings::default);

/// Retry settings to retry 5 times with 1, 2, 4, 8 and 15 seconds pause between retries.
pub static STANDARD_RETRIES: Lazy<RetrySettings> = Lazy::new(|| RetrySettings {
    max_tries: 5,
    ..RetrySettings::default()
});

/// Parameters for exponential backoff retry strategy with random jitter. Default instance performs no retries.
///
/// Turn any API query into retriable if needed: call [RetrySettings::retry] for sync operations and
/// [RetrySettings::retry_async] for futures.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RetrySettings {
    /// Initial delay for exponential backoff.
    initial_delay: Duration,

    /// Exponential backoff factor. If set to 0, [max_delay] will always be used as a delay.
    exp_factor: u32,

    /// Max delay for exponential backoff.
    max_delay: Duration,

    /// Amount of retries to perform when something fails. If set to 0, no retries will be made.
    max_tries: usize,
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

    pub(crate) fn get_exp_backoff_iterator(&self) -> impl Iterator<Item = Duration> {
        LimitedExponential::from_retry_settings(self)
            .map(retry::delay::jitter)
            .take(self.max_tries)
    }

    pub async fn retry_async<T, CF, OpErr>(self: &RetrySettings, operation: CF) -> Result<T, OpErr>
    where
        CF: fure::CreateFuture<T, OpErr>,
        OpErr: std::error::Error + Send + Sync,
    {
        let exp_backoff = self.get_exp_backoff_iterator();
        let policy = fure::policies::attempts(fure::policies::backoff(exp_backoff), self.max_tries);
        fure::retry(operation, policy).await
    }

    pub fn retry<O, R, OR, OpErr>(self: &RetrySettings, operation: O) -> Result<R, OpErr>
    where
        O: FnMut() -> OR,
        OR: Into<retry::OperationResult<R, OpErr>>,
        OpErr: std::error::Error + Send + Sync,
    {
        let policy = self.get_exp_backoff_iterator();
        let retry_result = retry::retry(policy, operation);
        retry_result.map_err(|retry_err| match retry_err {
            retry::Error::Operation { error, .. } => error,
            retry::Error::Internal(description) => {
                panic!("Sync retry internal logic failure marker: {}", description)
            }
        })
    }

    /// Get a reference to the initial delay.
    pub fn initial_delay(&self) -> &Duration {
        &self.initial_delay
    }

    /// Get the exponential factor. If set to 0, [RetrySettings::max_delay] will always be used as a delay.
    pub fn exp_factor(&self) -> u32 {
        self.exp_factor
    }

    /// Get a reference to the maximum possible delay for exponential backoff.
    pub fn max_delay(&self) -> &Duration {
        &self.max_delay
    }

    /// Get a reference to the amount of retries to perform when something fails. If set to 0, no retries will be made.
    pub fn max_tries(&self) -> usize {
        self.max_tries
    }
}

impl Default for RetrySettings {
    /// Default instance performs no retries.
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(RETRY_INITIAL_DELAY_MILLIS),
            exp_factor: RETRY_EXP_FACTOR,
            max_delay: Duration::from_millis(RETRY_MAX_DELAY_MILLIS),
            max_tries: 0,
        }
    }
}
