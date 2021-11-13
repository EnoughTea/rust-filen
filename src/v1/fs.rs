//! Contains structures common for Filen file&folder API.
use crate::{crypto, utils, v1::*};
use secstr::{SecUtf8, SecVec};
use serde::{Deserialize, Serialize};
use serde_json::json;
use snafu::{Backtrace, ResultExt, Snafu};
use std::{fmt, num::ParseIntError, str::FromStr};
use strum::{Display, EnumString};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Caller provided invalid argument: {}", message))]
    BadArgument { message: String, backtrace: Backtrace },

    #[snafu(display("Expected metadata to be base64-encoded, but cannot decode it as such"))]
    CannotDecodeBase64Metadata {
        metadata: String,
        source: base64::DecodeError,
    },

    #[snafu(display(
        "Expected \"base\" or hyphenated lowercased UUID, got unknown string of length: {}",
        string_length
    ))]
    CannotParseParentKindFromString { string_length: usize, backtrace: Backtrace },

    #[snafu(display("Failed to decrypt link key '{}': {}", metadata, source))]
    DecryptLinkKeyFailed { metadata: String, source: crypto::Error },

    #[snafu(display("Failed to decrypt location name {}: {}", metadata, source))]
    DecryptLocationNameFailed { metadata: String, source: crypto::Error },

    #[snafu(display("Failed to deserialize location name: {}", source))]
    DeserializeLocationNameFailed { source: serde_json::Error },

    #[snafu(display("Expire duration value '{}' is too short to be valid", value))]
    DurationIsTooShort { value: String, backtrace: Backtrace },

    #[snafu(display("Expire duration unit '{}' is unsupported", unit))]
    DurationUnitUnsupported { unit: String, backtrace: Backtrace },

    #[snafu(display("Expire duration value '{}' is not a number: {}", value, source))]
    DurationValueIsNotNum { value: String, source: ParseIntError },
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

impl fmt::Display for FileStorageInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{} [{} chunks]", self.region, self.bucket, self.chunks)
    }
}

/// Represents one of the user folders or some folder under Filen sync folder.
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
    pub fn encrypt_name_to_metadata<S: Into<String>>(name: S, key: &SecUtf8) -> String {
        let name_json = json!(LocationNameMetadata { name: name.into() }).to_string();
        crypto::encrypt_metadata_str(&name_json, key, super::METADATA_VERSION).unwrap()
    }

    /// Decrypt name metadata into actual name.
    pub fn decrypt_name_from_metadata(name_metadata: &str, keys: &[SecUtf8]) -> Result<String> {
        if name_metadata.eq_ignore_ascii_case("default") {
            return Ok("Default".to_owned());
        }

        let decrypted_name_result =
            crypto::decrypt_metadata_str_any_key(name_metadata, keys).context(DecryptLocationNameFailed {
                metadata: name_metadata.to_owned(),
            });

        decrypted_name_result.and_then(|name_metadata| {
            LocationNameMetadata::extract_name_from_folder_properties_json(name_metadata.as_bytes())
        })
    }

    /// Decrypts location name from a metadata string using RSA private key.
    /// Assumes given metadata string is base64-encoded.
    pub fn decrypt_name_from_metadata_rsa(name_metadata: &str, rsa_private_key_bytes: &SecVec<u8>) -> Result<String> {
        if name_metadata.eq_ignore_ascii_case("default") {
            return Ok("Default".to_owned());
        }

        let decoded = base64::decode(name_metadata).context(CannotDecodeBase64Metadata {
            metadata: name_metadata.to_owned(),
        })?;
        let decrypted_folder_properties_json = crypto::decrypt_rsa(&decoded, rsa_private_key_bytes.unsecure())
            .context(DecryptLocationNameFailed {
                metadata: name_metadata.to_owned(),
            })?;

        LocationNameMetadata::extract_name_from_folder_properties_json(&decrypted_folder_properties_json)
    }

    /// Encrypts location name to a metadata string using RSA public key of the user with whom item is shared aka receiver.
    /// Returns base64-encoded bytes.
    pub fn encrypt_name_to_metadata_rsa<S: Into<String>>(
        name: S,
        rsa_public_key_bytes: &[u8],
    ) -> Result<String, crypto::Error> {
        let name_json = json!(LocationNameMetadata { name: name.into() }).to_string();
        crypto::encrypt_rsa(name_json.as_bytes(), rsa_public_key_bytes).map(base64::encode)
    }

    /// Returns hashed given location name.
    pub fn name_hashed(name: &str) -> String {
        crypto::hash_fn(&name.to_lowercase())
    }

    pub(crate) fn extract_name_from_folder_properties_json(folder_properties_json_bytes: &[u8]) -> Result<String> {
        serde_json::from_slice::<LocationNameMetadata>(folder_properties_json_bytes)
            .context(DeserializeLocationNameFailed {})
            .map(|typed| typed.name)
    }
}

/// Implement this trait to add decryption of a metadata containing Filen's file properties JSON.
pub trait HasFileMetadata {
    /// Gets a reference to file metadata, if present.
    fn file_metadata_ref(&self) -> &str;

    /// Decrypts file metadata string using user's master keys.
    fn decrypt_file_metadata(&self, master_keys: &[SecUtf8]) -> Result<FileProperties, files::Error> {
        FileProperties::decrypt_file_metadata(self.file_metadata_ref(), master_keys)
    }
}

/// Implement this trait to add decryption of a metadata containing Filen's file properties JSON,
/// encrypted using user's public key.
pub trait HasSharedFileMetadata {
    /// Gets a reference to file metadata, if present.
    fn file_metadata_ref(&self) -> &str;

    /// Decrypts file metadata string using user's RSA private key.
    fn decrypt_file_metadata(&self, rsa_private_key_bytes: &SecVec<u8>) -> Result<FileProperties, files::Error> {
        FileProperties::decrypt_file_metadata_rsa(self.file_metadata_ref(), rsa_private_key_bytes)
    }
}

/// Implement this trait to add decryption of a metadata containing Filen's file properties JSON,
/// encrypted using link key.
pub trait HasLinkedFileMetadata {
    /// Gets a reference to file metadata, if present.
    fn file_metadata_ref(&self) -> &str;

    /// Decrypts file metadata string using link key.
    fn decrypt_file_metadata(&self, link_key: SecUtf8) -> Result<FileProperties, files::Error> {
        FileProperties::decrypt_file_metadata(self.file_metadata_ref(), &[link_key])
    }
}

pub trait HasFileLocation {
    /// Gets a reference to data defining where file is stored by Filen.
    fn file_storage_ref(&self) -> &FileStorageInfo;

    /// Gets a reference to file ID.
    fn uuid_ref(&self) -> &Uuid;

    /// Gets data required to build a URL for a file plus file chunk count.
    fn get_file_location(&self) -> FileLocation {
        let storage = self.file_storage_ref();
        FileLocation::new(&storage.region, &storage.bucket, *self.uuid_ref(), storage.chunks)
    }
}

/// Implement this trait to add decryption of a metadata containing Filen's name JSON: { "name": "some name value" }
pub trait HasLocationName {
    /// Returns reference to a string containing metadata with Filen's name JSON.
    fn name_metadata_ref(&self) -> &str;

    /// Decrypts name metadata into a location name using user's master keys.
    fn decrypt_name_metadata(&self, master_keys: &[SecUtf8]) -> Result<String> {
        LocationNameMetadata::decrypt_name_from_metadata(self.name_metadata_ref(), master_keys)
    }
}

/// Implement this trait to add decryption of a metadata containing Filen's name JSON: { "name": "some name value" },
/// encrypted using user's public key.
pub trait HasSharedLocationName {
    /// Returns reference to a string containing metadata with Filen's name JSON.
    fn name_metadata_ref(&self) -> &str;

    /// Decrypts name metadata into a location name using user's RSA private key.
    fn decrypt_name_metadata(&self, rsa_private_key_bytes: &SecVec<u8>) -> Result<String> {
        LocationNameMetadata::decrypt_name_from_metadata_rsa(self.name_metadata_ref(), rsa_private_key_bytes)
    }
}

/// Implement this trait to add decryption of a metadata containing Filen's name JSON: { "name": "some name value" },
/// encrypted using link key.
pub trait HasLinkedLocationName {
    /// Returns reference to a string containing metadata with Filen's name JSON.
    fn name_metadata_ref(&self) -> &str;

    /// Decrypts name metadata into a location name using link key.
    fn decrypt_name_metadata(&self, link_key: SecUtf8) -> Result<String> {
        LocationNameMetadata::decrypt_name_from_metadata(self.name_metadata_ref(), &[link_key])
    }
}

pub trait HasLinkKey {
    /// Returns reference to a string containing link key metadata.
    fn link_key_metadata_ref(&self) -> Option<&str>;

    /// Decrypts link key using user's master keys.
    fn decrypt_link_key(&self, master_keys: &[SecUtf8]) -> Result<SecUtf8> {
        match self.link_key_metadata_ref() {
            Some(link_key_metadata) => crypto::decrypt_metadata_str_any_key(link_key_metadata, master_keys)
                .context(DecryptLinkKeyFailed {
                    metadata: link_key_metadata.to_owned(),
                })
                .map(SecUtf8::from),
            None => BadArgument {
                message: "link key metadata is absent, cannot decrypt None",
            }
            .fail(),
        }
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

response_payload!(
    /// Response for [DIR_EXISTS_PATH] or [FILE_TRASH_PATH] endpoint.
    LocationExistsResponsePayload<LocationExistsResponseData>
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
