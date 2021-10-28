pub use {
    auth::Error as AuthError, dirs::Error as DirsError, download_dir::Error as DownloadDirError,
    download_file::Error as DownloadFileError, files::Error as FilesError, fs::Error as FsError,
    sync_dir::Error as SyncDirError, upload_file::Error as UploadFileError, usage::Error as UsageError,
};

pub use {
    auth::*, dir_links::*, download_dir::*, download_file::*, files::*, fs::*, keys::*, sync_dir::*, upload_file::*,
    usage::*,
};

use crate::crypto;
use once_cell::sync::Lazy;
use serde::*;

mod auth;
mod dir_links;
mod dirs;
mod download_dir;
mod download_file;
mod files;
mod fs;
mod keys;
mod sync_dir;
mod upload_file;
mod usage;

const METADATA_VERSION: u32 = 1;
const EMPTY_PASSWORD_MARK: &str = "empty";
const PRESENT_PASSWORD_MARK: &str = "notempty";

pub static EMPTY_PASSWORD_HASH: Lazy<String> = Lazy::new(|| crypto::hash_fn(EMPTY_PASSWORD_MARK));

/// Contains just the response status and corresponding message.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PlainApiResponse {
    /// True when API call was successful; false otherwise.
    pub status: bool,

    /// Filen reason for success or failure.
    pub message: Option<String>,
}
crate::utils::display_from_json!(PlainApiResponse);

/// Serves as a flag for password-protection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PasswordState {
    /// "empty" means no password protection is set.
    Empty,
    /// "notempty" means password is present.
    NotEmpty,
}

impl std::fmt::Display for PasswordState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            PasswordState::Empty => write!(f, "{}", EMPTY_PASSWORD_MARK),
            PasswordState::NotEmpty => write!(f, "{}", PRESENT_PASSWORD_MARK),
        }
    }
}

/// This macro generates a struct to parse Filen API response into.
///
/// Filen API uses mostly the same format for all its responses, successfull or not.
/// Status and message fields are always present, while data field can be returned on success,
/// when said success implies getting some data.
///
/// To use, pass generated struct name and contained data type:
/// ```
/// api_response_struct!(
///     /// Response for some endpoint.
///     SomeResponsePayload<Option<SomeResponseData>>
/// );
/// ```
macro_rules! api_response_struct {
    (
        $(#[$meta:meta])*
        $struct_name:ident<$response_data_type:ty>
    ) => {
        $(#[$meta])*
        #[serde_with::skip_serializing_none]
        #[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
        pub struct $struct_name {
            /// True when API call was successful; false otherwise.
            pub status: bool,

            /// Filen reason for success or failure.
            pub message: Option<String>,

            /// Resulting data.
            pub data: $response_data_type,
        }

        crate::utils::display_from_json!($struct_name);
    }
}
pub(crate) use api_response_struct;
