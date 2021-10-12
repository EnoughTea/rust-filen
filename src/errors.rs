use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RFError {
    #[error("{message:?}")]
    BadArgument { message: String },

    #[error("{message:?}")]
    DecryptionFail { message: String },

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

pub(crate) fn unsupported(message: &str) -> RFError {
    RFError::Unsupported {
        message: message.to_owned(),
    }
}
