//! Contains structures common for Filen file&folder API.
use crate::{crypto, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_json::json;
use snafu::{Backtrace, ResultExt, Snafu};
use std::{convert::TryFrom, fmt};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to deserialize location name: {}", source))]
    DeserializeLocationNameFailed { source: serde_json::Error },

    #[snafu(display("Failed to decrypt location name {}: {}", metadata, source))]
    DecryptLocationNameFailed { metadata: String, source: crypto::Error },

    #[snafu(display(
        "Expected \"base\" or hyphenated lowercased UUID, got unknown string of length: {}",
        string_length
    ))]
    CannotParseParentIdFromString { string_length: usize, backtrace: Backtrace },
}

/// Identifies linked item.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkTarget {
    /// Linked item is a file.
    File,
    /// Linked item is a folder.
    Folder,
}

impl fmt::Display for LinkTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let link_target_name = match *self {
            LinkTarget::File => "file",
            LinkTarget::Folder => "folder",
        };
        write!(f, "{}", link_target_name)
    }
}

/// Identifies location color set by user. Default yellow color is represented by the absence of specifically set
/// `LocationColor`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LocationColor {
    Blue,
    Gray,
    Green,
    Purple,
    Red,
}

impl fmt::Display for LocationColor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let color_name = match *self {
            LocationColor::Blue => "blue",
            LocationColor::Gray => "gray",
            LocationColor::Green => "green",
            LocationColor::Purple => "purple",
            LocationColor::Red => "red",
        };
        write!(f, "{}", color_name)
    }
}

/// Identifies location type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LocationType {
    /// Location is a folder.
    Folder,
    /// Location is a special Filen Sync folder.
    Sync,
}

impl fmt::Display for LocationType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let location_type_name = match *self {
            LocationType::Folder => "folder",
            LocationType::Sync => "sync",
        };
        write!(f, "{}", location_type_name)
    }
}

/// Identifies parent eitner by ID or by indirect reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParentId {
    /// Parent is a base folder.
    Base,
    /// Parent is a folder with the specified UUID.
    Id(Uuid),
}

impl ParentId {
    /// Tries to parse [IdRef] from given string, which must be either "base" or hyphenated lowercased UUID.
    pub fn try_parse(base_or_id: &str) -> Result<ParentId> {
        if base_or_id.eq_ignore_ascii_case("base") {
            Ok(ParentId::Base)
        } else {
            match Uuid::parse_str(&base_or_id) {
                Ok(uuid) => Ok(ParentId::Id(uuid)),
                Err(_) => CannotParseParentIdFromString {
                    string_length: base_or_id.len(),
                }
                .fail(),
            }
        }
    }
}

impl TryFrom<String> for ParentId {
    type Error = Error;
    fn try_from(base_or_id: String) -> Result<Self, Self::Error> {
        ParentId::try_parse(&base_or_id)
    }
}

impl TryFrom<&str> for ParentId {
    type Error = Error;
    fn try_from(base_or_id: &str) -> Result<Self, Self::Error> {
        ParentId::try_parse(base_or_id)
    }
}

impl fmt::Display for ParentId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParentId::Base => write!(f, "base"),
            ParentId::Id(uuid) => uuid.to_hyphenated().fmt(f),
        }
    }
}

impl<'de> Deserialize<'de> for ParentId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let base_or_id = String::deserialize(deserializer)?;

        if base_or_id.eq_ignore_ascii_case("base") {
            Ok(ParentId::Base)
        } else {
            match Uuid::parse_str(&base_or_id) {
                Ok(uuid) => Ok(ParentId::Id(uuid)),
                Err(_) => Err(de::Error::invalid_value(
                    de::Unexpected::Str(&base_or_id),
                    &"\"base\" or hyphenated lowercased UUID",
                )),
            }
        }
    }
}

impl Serialize for ParentId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            ParentId::Base => serializer.serialize_str("base"),
            ParentId::Id(uuid) => serializer.serialize_str(&uuid.to_hyphenated().to_string()),
        }
    }
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
    pub parent: ParentId,
}
utils::display_from_json!(FolderData);

impl HasLocationName for FolderData {
    /// Decrypts name metadata into a folder name.
    fn name_metadata_ref(&self) -> &str {
        &self.name_metadata
    }
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

    /// Decrypt name metadata into actual folder name.
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

    pub fn name_hashed(name: &str) -> String {
        crypto::hash_fn(&name.to_lowercase())
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

// Used for requests to [DIR_TRASH_PATH] or [FILE_TRASH_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocationTrashRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the folder or file to move to trash, hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(LocationTrashRequestPayload);

// Used for requests to [DIR_EXISTS_PATH] or [FILE_TRASH_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocationExistsRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Either parent folder ID (hyphenated lowercased UUID V4) or "base" when folder is located in the base folder,
    /// also known as 'cloud drive'.
    pub parent: ParentId,

    /// Currently hash_fn of lowercased target folder or file name.
    #[serde(rename = "nameHashed")]
    pub name_hashed: String,
}
utils::display_from_json!(LocationExistsRequestPayload);

impl LocationExistsRequestPayload {
    pub fn new(api_key: SecUtf8, target_parent: ParentId, target_name: &str) -> LocationExistsRequestPayload {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_should_be_deserialized_from_empty_string_uuid() {
        let json = r#"{"exists":false, "uuid":""}"#;
        let result = serde_json::from_str::<LocationExistsResponseData>(&json);

        assert!(result.is_ok());
        assert!(result.unwrap().uuid.is_none());
    }
}
