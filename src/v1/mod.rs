pub use {
    auth::Error as AuthError, client::Error as ClientError, crypto::Error as CryptoError,
    dir_links::Error as DirLinksError, dirs::Error as DirsError, download_dir::Error as DownloadDirError,
    download_file::Error as DownloadFileError, events::Error as EventsError, file_links::Error as FileLinksError,
    files::Error as FilesError, fs::Error as FsError, links::Error as LinksError, share::Error as ShareError,
    sync_dir::Error as SyncDirError, upload_file::Error as UploadFileError, usage::Error as UsageError,
    user::Error as UserError, user_keys::Error as UserKeysError, versions::Error as VersionsError,
};

pub use {
    auth::*, client::*, dir_links::*, dirs::*, download_dir::*, download_file::*, events::*, file_links::*, files::*,
    fs::*, links::*, share::*, sync_dir::*, upload_file::*, usage::*, user::*, user_keys::*, versions::*,
};

use crate::{crypto, utils};
use once_cell::sync::Lazy;
use serde::*;
use serde_with::skip_serializing_none;
use snafu::{Backtrace, Snafu};
use strum::{Display, EnumString};
use uuid::Uuid;

mod auth;
mod client;
mod dir_links;
mod dirs;
mod download_dir;
mod download_file;
mod events;
mod file_links;
mod files;
mod fs;
mod links;
mod share;
mod sync_dir;
mod upload_file;
mod usage;
mod user;
mod user_keys;
mod versions;

type Result<T, E = Error> = std::result::Result<T, E>;

const METADATA_VERSION: u32 = 1;

pub static EMPTY_PASSWORD_HASH: Lazy<String> = Lazy::new(|| crypto::hash_fn(&PasswordState::Empty.to_string()));

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Filen response does not contain 'data'"))]
    FilenResponseHasNoData { backtrace: Backtrace },
}

/// Common trait for all Filen API responses.
pub trait HasPlainResponse {
    /// True when API call was successful; false otherwise.
    fn status_ref(&self) -> bool;

    /// Filen reason for success or failure.
    fn message_ref(&self) -> Option<&str>;
}

/// Contains just the response status and corresponding message.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PlainResponsePayload {
    /// True when API call was successful; false otherwise.
    pub status: bool,

    /// Filen reason for success or failure.
    pub message: Option<String>,
}
utils::display_from_json!(PlainResponsePayload);

impl HasPlainResponse for PlainResponsePayload {
    fn status_ref(&self) -> bool {
        self.status
    }

    fn message_ref(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

pub trait HasDataOption<D> {
    fn data_ref(&self) -> Option<&D>;

    fn data_or_err(&self) -> Result<&D> {
        match self.data_ref() {
            Some(data) => Ok(data),
            None => FilenResponseHasNoData {}.fail(),
        }
    }
}

/// Serves as a flag for password-protection.
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
pub enum PasswordState {
    /// "empty" means no password protection is set.
    Empty,
    /// "notempty" means password is present.
    NotEmpty,
}

pub(crate) fn bool_from_string<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let deserialized = String::deserialize(deserializer)?;
    let trimmed_value = deserialized.trim();
    if trimmed_value.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if trimmed_value.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(de::Error::invalid_value(
            de::Unexpected::Str(&deserialized),
            &"\"true\" or \"false\"",
        ))
    }
}

pub(crate) fn bool_to_string<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        true => serializer.serialize_str("true"),
        false => serializer.serialize_str("false"),
    }
}

pub(crate) fn bool_from_int<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let value = i32::deserialize(deserializer)?;
    if value == 0 {
        Ok(false)
    } else {
        Ok(true)
    }
}

pub(crate) fn bool_to_int<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if *value {
        serializer.serialize_i32(1)
    } else {
        serializer.serialize_i32(0)
    }
}

pub(crate) fn optional_uuid_from_empty_string<'de, D>(deserializer: D) -> Result<Option<Uuid>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?.unwrap_or_else(|| "".to_owned());
    if value.is_empty() {
        Ok(None)
    } else {
        match Uuid::parse_str(&value) {
            Ok(uuid) => Ok(Some(uuid)),
            Err(_) => Err(de::Error::invalid_value(
                de::Unexpected::Str(&value),
                &"hyphenated lowercased UUID or empty string",
            )),
        }
    }
}

/// This macro generates a struct used to parse Filen API response.
///
/// Filen API uses mostly the same format for all its responses, successfull or not.
/// Status is always present, message is almost always present, while data field can be returned on success,
/// when said success implies getting some data.
///
/// To use, pass generated struct name and contained data type:
/// ```
/// api_response_struct_option!(
///     /// Response for some endpoint.
///     SomeResponsePayload<SomeOptionalResponseData>
/// );
/// ```
macro_rules! response_payload {
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
            pub data: Option<$response_data_type>,
        }

        impl crate::v1::HasPlainResponse for $struct_name {
            fn status_ref(&self) -> bool {
                self.status
            }

            fn message_ref(&self) -> Option<&str> {
                self.message.as_deref()
            }
        }

        impl HasDataOption<$response_data_type> for $struct_name {
            fn data_ref(&self) -> Option<&$response_data_type> {
                self.data.as_ref()
            }
        }

        crate::utils::display_from_json!($struct_name);
    }
}
pub(crate) use response_payload;
