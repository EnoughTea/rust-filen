use crate::retry_settings::RetrySettings;
use std::time::Duration;

/// Each retry increases the delay since the last exponentially, but a maximum delay is limited.
#[derive(Debug)]
pub struct LimitedExponential {
    current: u64,
    factor: f64,
    max: u64,
}

impl LimitedExponential {
    /// Create a new `Exponential` using the given millisecond duration as the initial delay,
    /// a variable multiplication factor and an upper limit for produced durations.
    pub fn new(base: u64, factor: f64, max: u64) -> Self {
        LimitedExponential {
            current: base,
            factor,
            max,
        }
    }

    /// Create a new `Exponential` using the given millisecond duration as the initial delay and an upper limit for
    /// produced durations.
    pub fn from_millis_and_max(base: u64, max: u64) -> Self {
        LimitedExponential {
            current: base,
            factor: base as f64,
            max,
        }
    }

    pub fn from_retry_settings(settings: &RetrySettings) -> LimitedExponential {
        LimitedExponential {
            current: settings.initial_delay().as_millis() as u64,
            factor: settings.exp_factor() as f64,
            max: settings.max_delay().as_millis() as u64,
        }
    }
}

impl Iterator for LimitedExponential {
    type Item = Duration;

    fn next(&mut self) -> Option<Duration> {
        let duration = Duration::from_millis(self.current);

        let next = (self.current as f64) * self.factor;
        self.current = if next > (self.max as f64) {
            self.max
        } else {
            next as u64
        };

        Some(duration)
    }
}
