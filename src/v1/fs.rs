//! Contains structures common for Filen file&folder API.
use crate::{crypto, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_json::json;
use snafu::{Backtrace, ResultExt, Snafu};
use std::{num::ParseIntError, str::FromStr};
use strum::{Display, EnumString};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to deserialize location name: {}", source))]
    DeserializeLocationNameFailed { source: serde_json::Error },

    #[snafu(display("Failed to decrypt file metadata '{}': {}", metadata, source))]
    DecryptFileMetadataFailed { metadata: String, source: files::Error },

    #[snafu(display("Failed to decrypt location name {}: {}", metadata, source))]
    DecryptLocationNameFailed { metadata: String, source: crypto::Error },

    #[snafu(display("Expire duration value '{}' is too short to be valid", value))]
    DurationIsTooShort { value: String, backtrace: Backtrace },

    #[snafu(display("Expire duration unit '{}' is unsupported", unit))]
    DurationUnitUnsupported { unit: String, backtrace: Backtrace },

    #[snafu(display("Expire duration value '{}' is not a number: {}", value, source))]
    DurationValueIsNotNum { value: String, source: ParseIntError },

    #[snafu(display(
        "Expected \"base\" or hyphenated lowercased UUID, got unknown string of length: {}",
        string_length
    ))]
    CannotParseParentKindFromString { string_length: usize, backtrace: Backtrace },
}

/// Public link or file chunk expiration time.
///
/// For defined expiration period, Filen currently uses values "1h", "6h", "1d", "3d", "7d", "14d" and "30d".
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Expire {
    Never,

    Hours(u32),

    Days(u32),
}
utils::display_from_json!(Expire);

impl FromStr for Expire {
    type Err = Error;

    /// Tries to parse [Expire] from given string, which must be either "never" or amount of hours/days,
    /// e.g. "6h" or "30d".
    fn from_str(never_or_duration: &str) -> Result<Self, Self::Err> {
        if never_or_duration.eq_ignore_ascii_case("never") {
            Ok(Expire::Never)
        } else if never_or_duration.len() < 2 {
            DurationIsTooShort {
                value: never_or_duration.to_owned(),
            }
            .fail()
        } else {
            let (raw_value, unit) = never_or_duration.split_at(never_or_duration.len() - 1);
            let value = str::parse::<u32>(raw_value).context(DurationValueIsNotNum {
                value: never_or_duration,
            })?;
            match unit {
                "d" => Ok(Expire::Days(value)),
                "h" => Ok(Expire::Hours(value)),
                other => DurationUnitUnsupported { unit: other.to_owned() }.fail(),
            }
        }
    }
}

impl<'de> Deserialize<'de> for Expire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let never_or_duration_repr = String::deserialize(deserializer)?;
        str::parse::<Expire>(&never_or_duration_repr).map_err(|_| {
            de::Error::invalid_value(
                de::Unexpected::Str(&never_or_duration_repr),
                &"\"never\" or duration with time units, e.g. \"6h\" or \"1d\"",
            )
        })
    }
}

impl Serialize for Expire {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Expire::Never => serializer.serialize_str("never"),
            Expire::Hours(hours) => serializer.serialize_str(&format!("{}h", hours)),
            Expire::Days(days) => serializer.serialize_str(&format!("{}d", days)),
        }
    }
}

/// Identifies whether an item is a file or folder.
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
pub enum ItemKind {
    /// Item is a file.
    File,
    /// Item is a folder.
    Folder,
}

/// Determines where file is stored by Filen.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FileStorageInfo {
    /// Server's bucket where file is stored.
    pub bucket: String,

    /// Server region where file is stored.
    pub region: String,

    /// Amount of chunks file is split into.
    pub chunks: u32,
}

/// Folder data for one of the user folders or for one of the folders in Filen sync folder.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FolderData {
    /// Folder ID, UUID V4 in hyphenated lowercase format.
    pub uuid: Uuid,

    /// Metadata containing folder name.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Either parent folder ID (hyphenated lowercased UUID V4) or "base" when folder is located in the base folder,
    /// also known as 'cloud drive'.
    pub parent: ParentKind,
}
utils::display_from_json!(FolderData);

impl HasLocationName for FolderData {
    /// Decrypts name metadata into a folder name.
    fn name_metadata_ref(&self) -> &str {
        &self.name_metadata
    }
}

/// Identifies location color set by user. Default yellow color is often represented by the absence of specifically set
/// `LocationColor`.
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
pub enum LocationColor {
    /// Default yellow color. Often represented by the absence of specifically set `LocationColor`.
    Default,
    Blue,
    Gray,
    Green,
    Purple,
    Red,
}

/// Identifies location type.
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
pub enum LocationKind {
    /// Location is a folder.
    Folder,
    /// Location is a special Filen Sync folder.
    Sync,
}

/// Typed folder or file name metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct LocationNameMetadata {
    pub name: String,
}

impl LocationNameMetadata {
    /// Puts the given name into Filen-expected JSON and encrypts it into metadata.
    pub fn encrypt_name_to_metadata<S: Into<String>>(name: S, last_master_key: &SecUtf8) -> String {
        let name_json = json!(LocationNameMetadata { name: name.into() }).to_string();
        crypto::encrypt_metadata_str(&name_json, last_master_key.unsecure(), super::METADATA_VERSION).unwrap()
    }

    /// Decrypt name metadata into actual name.
    pub fn decrypt_name_from_metadata(name_metadata: &str, last_master_key: &SecUtf8) -> Result<String> {
        let decrypted_name_result = crypto::decrypt_metadata_str(name_metadata, last_master_key.unsecure()).context(
            DecryptLocationNameFailed {
                metadata: name_metadata.to_owned(),
            },
        );

        decrypted_name_result.and_then(|name_metadata| {
            serde_json::from_str::<LocationNameMetadata>(&name_metadata)
                .context(DeserializeLocationNameFailed {})
                .map(|typed| typed.name)
        })
    }

    /// Returns hashed given location name.
    pub fn name_hashed(name: &str) -> String {
        crypto::hash_fn(&name.to_lowercase())
    }
}

/// Implement this trait to add decryption of a metadata containing Filen's file properties JSON.
pub trait HasFileMetadata {
    /// Gets a reference to file metadata, if present.
    fn file_metadata_ref(&self) -> &str;

    /// Decrypts file metadata string.
    fn decrypt_file_metadata(&self, last_master_key: &SecUtf8) -> Result<FileProperties> {
        FileProperties::decrypt_file_metadata(self.file_metadata_ref(), last_master_key).context(
            DecryptFileMetadataFailed {
                metadata: self.file_metadata_ref().to_owned(),
            },
        )
    }
}

/// Implement this trait to add decryption of a metadata containing Filen's name JSON: { "name": "some name value" }
pub trait HasLocationName {
    /// Returns reference to a string containing metadata with Filen's name JSON.
    fn name_metadata_ref(&self) -> &str;

    /// Decrypts name metadata into a location name.
    fn decrypt_name_metadata(&self, last_master_key: &SecUtf8) -> Result<String> {
        LocationNameMetadata::decrypt_name_from_metadata(self.name_metadata_ref(), last_master_key)
    }
}

/// Used for requests to [DIR_TRASH_PATH] or [FILE_TRASH_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocationTrashRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the folder or file to move to trash, hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(LocationTrashRequestPayload);

/// Used for requests to [DIR_EXISTS_PATH] or [FILE_TRASH_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocationExistsRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Either parent folder ID (hyphenated lowercased UUID V4) or "base" when folder is located in the base folder,
    /// also known as 'cloud drive'.
    pub parent: ParentKind,

    /// Currently hash_fn of lowercased target folder or file name.
    #[serde(rename = "nameHashed")]
    pub name_hashed: String,
}
utils::display_from_json!(LocationExistsRequestPayload);

impl LocationExistsRequestPayload {
    pub fn new(api_key: SecUtf8, target_parent: ParentKind, target_name: &str) -> LocationExistsRequestPayload {
        let name_hashed = LocationNameMetadata::name_hashed(target_name);
        LocationExistsRequestPayload {
            api_key,
            parent: target_parent,
            name_hashed,
        }
    }
}

/// Response data for [DIR_EXISTS_PATH] or [FILE_TRASH_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocationExistsResponseData {
    /// True if folder or file with given name already exists in the parent folder; false otherwise.
    pub exists: bool,

    /// Existing folder or file ID, hyphenated lowercased UUID V4. Empty string if folder or file does not exist.
    #[serde(default)]
    #[serde(deserialize_with = "optional_uuid_from_empty_string")]
    pub uuid: Option<Uuid>,
}
utils::display_from_json!(LocationExistsResponseData);

api_response_struct!(
    /// Response for [DIR_EXISTS_PATH] or [FILE_TRASH_PATH] endpoint.
    LocationExistsResponsePayload<Option<LocationExistsResponseData>>
);

/// Identifies parent eitner by ID or by indirect reference.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ParentKind {
    /// Parent is a base folder.
    Base,
    /// Parent is a folder with the specified UUID.
    Folder(Uuid),
}
utils::display_from_json!(ParentKind);

impl FromStr for ParentKind {
    type Err = Error;

    /// Tries to parse [ParentKind] from given string, which must be either "base" or hyphenated lowercased UUID.
    fn from_str(base_or_id: &str) -> Result<Self, Self::Err> {
        if base_or_id.eq_ignore_ascii_case("base") {
            Ok(ParentKind::Base)
        } else {
            match Uuid::parse_str(base_or_id) {
                Ok(uuid) => Ok(ParentKind::Folder(uuid)),
                Err(_) => CannotParseParentKindFromString {
                    string_length: base_or_id.len(),
                }
                .fail(),
            }
        }
    }
}

impl<'de> Deserialize<'de> for ParentKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let base_or_id = String::deserialize(deserializer)?;

        if base_or_id.eq_ignore_ascii_case("base") {
            Ok(ParentKind::Base)
        } else {
            match Uuid::parse_str(&base_or_id) {
                Ok(uuid) => Ok(ParentKind::Folder(uuid)),
                Err(_) => Err(de::Error::invalid_value(
                    de::Unexpected::Str(&base_or_id),
                    &"\"base\" or hyphenated lowercased UUID",
                )),
            }
        }
    }
}

impl Serialize for ParentKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            ParentKind::Base => serializer.serialize_str("base"),
            ParentKind::Folder(uuid) => serializer.serialize_str(&uuid.to_hyphenated().to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn location_should_be_deserialized_from_empty_string_uuid() {
        let json = r#"{"exists":false, "uuid":""}"#;
        let result = serde_json::from_str::<LocationExistsResponseData>(&json);

        assert!(result.unwrap().uuid.is_none());
    }

    #[test]
    fn expire_time_should_be_deserialized_from_hours() {
        let json = r#""6h""#;
        let expected = Expire::Hours(6);

        let result = serde_json::from_str::<Expire>(&json);

        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn expire_time_should_be_deserialized_from_days() {
        let json = r#""30d""#;
        let expected = Expire::Days(30);

        let result = serde_json::from_str::<Expire>(&json);

        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn expire_time_should_be_deserialized_from_never() {
        let json = r#""never""#;
        let expected = Expire::Never;

        let result = serde_json::from_str::<Expire>(&json);

        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn parent_kind_should_be_deserialized_from_base() {
        let json = r#""base""#;
        let expected = ParentKind::Base;

        let result = serde_json::from_str::<ParentKind>(&json);

        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn parent_kind_should_be_deserialized_from_id() {
        let json = r#""00000000-0000-0000-0000-000000000000""#;
        let expected = ParentKind::Folder(Uuid::nil());

        let result = serde_json::from_str::<ParentKind>(&json);

        assert_eq!(result.unwrap(), expected);
    }
}
