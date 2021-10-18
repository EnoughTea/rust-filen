//! Contains [RFError], which can be used to discriminate crate's errors.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RFError {
    #[error("{message:?}")]
    BadArgument { message: String },

    #[error("{message:?}")]
    DecryptionFail { message: String },

    #[error("{message:?}")]
    WebRequestFail {
        message: String,
        reqwest_error: reqwest::Error,
    },

    #[error("{message:?}")]
    Unknown { message: String },

    #[error("{message:?}")]
    Unsupported { message: String },
}

pub(crate) fn bad_argument(message: &str) -> RFError {
    RFError::BadArgument {
        message: message.to_owned(),
    }
}

pub(crate) fn decryption_fail(message: &str) -> RFError {
    RFError::DecryptionFail {
        message: message.to_owned(),
    }
}

pub(crate) fn web_request_fail(message: &str, reqwest_error: reqwest::Error) -> RFError {
    RFError::WebRequestFail {
        message: message.to_owned(),
        reqwest_error: reqwest_error,
    }
}

pub(crate) fn unknown(message: &str) -> RFError {
    RFError::Unknown {
        message: message.to_owned(),
    }
}

pub(crate) fn unsupported(message: &str) -> RFError {
    RFError::Unsupported {
        message: message.to_owned(),
    }
}
