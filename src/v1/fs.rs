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
    CannotParseParentOrBaseFromString { string_length: usize, backtrace: Backtrace },

    #[snafu(display(
        "Expected \"none\" or hyphenated lowercased UUID, got unknown string of length: {}",
        string_length
    ))]
    CannotParseParentOrNoneFromString { string_length: usize, backtrace: Backtrace },

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
/// Otherwise, it's "never".
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
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
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
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FolderData {
    /// Folder ID, UUID V4 in hyphenated lowercase format.
    pub uuid: Uuid,

    /// Metadata containing folder name.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Either parent folder ID (hyphenated lowercased UUID V4) or "base" when folder is located in the base folder,
    /// also known as 'cloud drive'.
    pub parent: ParentOrBase,
}
utils::display_from_json!(FolderData);

impl HasLocationName for FolderData {
    /// Decrypts name metadata into a folder name.
    fn name_metadata_ref(&self) -> &str {
        &self.name_metadata
    }
}

impl HasUuid for FolderData {
    fn uuid_ref(&self) -> &Uuid {
        &self.uuid
    }
}

/// Identifies location color set by user. Default yellow color is often represented by the absence of specifically set
/// `LocationColor`.
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize, PartialOrd, Ord)]
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
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize, Ord, PartialOrd)]
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

/// Implemented to add decryption of a metadata containing Filen's file properties JSON.
pub trait HasFileMetadata {
    /// Gets a reference to file metadata, if present.
    fn file_metadata_ref(&self) -> &str;

    /// Decrypts file metadata string using user's master keys.
    fn decrypt_file_metadata(&self, master_keys: &[SecUtf8]) -> Result<FileProperties, files::Error> {
        FileProperties::decrypt_file_metadata(self.file_metadata_ref(), master_keys)
    }
}

/// Implemented to add decryption of a metadata containing Filen's file properties JSON,
/// encrypted using user's public key.
pub trait HasSharedFileMetadata {
    /// Gets a reference to file metadata, if present.
    fn file_metadata_ref(&self) -> &str;

    /// Decrypts file metadata string using user's RSA private key.
    fn decrypt_file_metadata(&self, rsa_private_key_bytes: &SecVec<u8>) -> Result<FileProperties, files::Error> {
        FileProperties::decrypt_file_metadata_rsa(self.file_metadata_ref(), rsa_private_key_bytes)
    }
}

/// Implemented to add decryption of a metadata containing Filen's file properties JSON,
/// encrypted using link key.
pub trait HasLinkedFileMetadata {
    /// Gets a reference to file metadata, if present.
    fn file_metadata_ref(&self) -> &str;

    /// Decrypts file metadata string using link key.
    fn decrypt_file_metadata(&self, link_key: SecUtf8) -> Result<FileProperties, files::Error> {
        FileProperties::decrypt_file_metadata(self.file_metadata_ref(), &[link_key])
    }
}

/// Implemented for something that has Filen file location.
pub trait HasFileLocation: HasUuid {
    /// Gets a reference to data defining where file is stored by Filen.
    fn file_storage_ref(&self) -> &FileStorageInfo;

    /// Gets data required to build a URL for a file plus file chunk count.
    fn get_file_location(&self) -> FileLocation {
        let storage = self.file_storage_ref();
        FileLocation::new(&storage.region, &storage.bucket, *self.uuid_ref(), storage.chunks)
    }
}

/// Implemented to add file properties decryption and other helper methods.
pub trait HasFiles<T: HasUuid + HasFileMetadata> {
    /// Returns files slice.
    fn files_ref(&self) -> &[T];

    /// Searches for a file with the specified ID in the files slice.
    ///
    /// If you do a lot of searches, build a `BTreeMap<Uuid, file data>` and use it instead.
    fn file_with_uuid(&self, uuid: &Uuid) -> Option<&T> {
        self.files_ref().iter().find(|file_ref| file_ref.uuid_ref() == uuid)
    }

    /// Decrypts all encrypted file properties and associates them with file data.
    fn decrypt_all_file_properties(&self, keys: &[SecUtf8]) -> Result<Vec<(&T, FileProperties)>, files::Error> {
        self.files_ref()
            .iter()
            .map(|data| data.decrypt_file_metadata(keys).map(|properties| (data, properties)))
            .collect::<Result<Vec<_>, files::Error>>()
    }
}

/// Implemented to add folder name decryption and other helper methods.
pub trait HasFolders<T: HasUuid + HasLocationName> {
    /// Returns folders slice.
    fn folders_ref(&self) -> &[T];

    /// Searches for a folder with the specified ID in the folders slice.
    ///
    /// If you do a lot of searches, build a `BTreeMap<Uuid, folder data>` and use it instead.
    fn folder_with_uuid(&self, uuid: &Uuid) -> Option<&T> {
        self.folders_ref()
            .iter()
            .find(|folder_ref| folder_ref.uuid_ref() == uuid)
    }

    /// Decrypts all encrypted folder names and associates them with folder data.
    fn decrypt_all_folder_names(&self, keys: &[SecUtf8]) -> Result<Vec<(&T, String)>, fs::Error> {
        self.folders_ref()
            .iter()
            .map(|data| data.decrypt_name_metadata(keys).map(|name| (data, name)))
            .collect::<Result<Vec<_>, fs::Error>>()
    }
}

/// Implemented to add decryption of a metadata containing Filen's name JSON: { "name": "some name value" }
pub trait HasLocationName {
    /// Returns reference to a string containing metadata with Filen's name JSON.
    fn name_metadata_ref(&self) -> &str;

    /// Decrypts name metadata into a location name using user's master keys.
    fn decrypt_name_metadata(&self, master_keys: &[SecUtf8]) -> Result<String> {
        LocationNameMetadata::decrypt_name_from_metadata(self.name_metadata_ref(), master_keys)
    }
}

/// Implemented to add decryption of a metadata containing Filen's name JSON: { "name": "some name value" },
/// encrypted using user's public key.
pub trait HasSharedLocationName {
    /// Returns reference to a string containing metadata with Filen's name JSON.
    fn name_metadata_ref(&self) -> &str;

    /// Decrypts name metadata into a location name using user's RSA private key.
    fn decrypt_name_metadata(&self, rsa_private_key_bytes: &SecVec<u8>) -> Result<String> {
        LocationNameMetadata::decrypt_name_from_metadata_rsa(self.name_metadata_ref(), rsa_private_key_bytes)
    }
}

/// Implemented to add decryption of a metadata containing Filen's name JSON: { "name": "some name value" },
/// encrypted using link key.
pub trait HasLinkedLocationName {
    /// Returns reference to a string containing metadata with Filen's name JSON.
    fn name_metadata_ref(&self) -> &str;

    /// Decrypts name metadata into a location name using link key.
    fn decrypt_name_metadata(&self, link_key: SecUtf8) -> Result<String> {
        LocationNameMetadata::decrypt_name_from_metadata(self.name_metadata_ref(), &[link_key])
    }
}

/// Implemented for something that has link key metadata.
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

/// Implemented for items that always have UUID.
pub trait HasUuid {
    /// Returns reference to an item's ID.
    fn uuid_ref(&self) -> &Uuid;
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
    pub parent: ParentOrBase,

    /// Currently hash_fn of lowercased target folder or file name.
    #[serde(rename = "nameHashed")]
    pub name_hashed: String,
}
utils::display_from_json!(LocationExistsRequestPayload);

impl LocationExistsRequestPayload {
    pub fn new(api_key: SecUtf8, target_parent: ParentOrBase, target_name: &str) -> LocationExistsRequestPayload {
        let name_hashed = LocationNameMetadata::name_hashed(target_name);
        LocationExistsRequestPayload {
            api_key,
            parent: target_parent,
            name_hashed,
        }
    }
}

/// Response data for [DIR_EXISTS_PATH] or [FILE_TRASH_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
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
pub enum ParentOrBase {
    /// Parent is a base folder.
    Base,
    /// Parent is a folder with the specified UUID.
    Folder(Uuid),
}
utils::display_from_json!(ParentOrBase);

impl ParentOrBase {
    /// Creates [ParentOrNone] corresponding to this value.
    pub fn as_parent_or_none(&self) -> ParentOrNone {
        match self {
            ParentOrBase::Base => ParentOrNone::None,
            ParentOrBase::Folder(id) => ParentOrNone::Folder(*id),
        }
    }
}

impl FromStr for ParentOrBase {
    type Err = Error;

    /// Tries to parse [ParentOrBase] from given string, which must be either "base" or hyphenated lowercased UUID.
    fn from_str(base_or_id: &str) -> Result<Self, Self::Err> {
        if base_or_id.eq_ignore_ascii_case("base") {
            Ok(ParentOrBase::Base)
        } else {
            match Uuid::parse_str(base_or_id) {
                Ok(uuid) => Ok(ParentOrBase::Folder(uuid)),
                Err(_) => CannotParseParentOrBaseFromString {
                    string_length: base_or_id.len(),
                }
                .fail(),
            }
        }
    }
}

impl<'de> Deserialize<'de> for ParentOrBase {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let base_or_id = String::deserialize(deserializer)?;

        if base_or_id.eq_ignore_ascii_case("base") {
            Ok(ParentOrBase::Base)
        } else {
            match Uuid::parse_str(&base_or_id) {
                Ok(uuid) => Ok(ParentOrBase::Folder(uuid)),
                Err(_) => Err(de::Error::invalid_value(
                    de::Unexpected::Str(&base_or_id),
                    &"\"base\" or hyphenated lowercased UUID",
                )),
            }
        }
    }
}

impl Serialize for ParentOrBase {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            ParentOrBase::Base => serializer.serialize_str("base"),
            ParentOrBase::Folder(uuid) => serializer.serialize_str(&uuid.to_hyphenated().to_string()),
        }
    }
}

/// Eitner a parent ID or none.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ParentOrNone {
    /// No parent, which means parent is a base folder.
    None,
    /// Parent is a folder with the specified UUID.
    Folder(Uuid),
}
utils::display_from_json!(ParentOrNone);

impl ParentOrNone {
    /// Creates [ParentOrBase] corresponding to this value.
    pub fn as_parent_or_base(&self) -> ParentOrBase {
        match self {
            ParentOrNone::None => ParentOrBase::Base,
            ParentOrNone::Folder(id) => ParentOrBase::Folder(*id),
        }
    }
}

impl FromStr for ParentOrNone {
    type Err = Error;

    /// Tries to parse [ParentOrNone] from given string, which must be either "none" or hyphenated lowercased UUID.
    fn from_str(none_or_id: &str) -> Result<Self, Self::Err> {
        if none_or_id.eq_ignore_ascii_case("none") {
            Ok(ParentOrNone::None)
        } else {
            match Uuid::parse_str(none_or_id) {
                Ok(uuid) => Ok(ParentOrNone::Folder(uuid)),
                Err(_) => CannotParseParentOrNoneFromString {
                    string_length: none_or_id.len(),
                }
                .fail(),
            }
        }
    }
}

impl<'de> Deserialize<'de> for ParentOrNone {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let none_or_id = String::deserialize(deserializer)?;

        if none_or_id.eq_ignore_ascii_case("none") {
            Ok(ParentOrNone::None)
        } else {
            match Uuid::parse_str(&none_or_id) {
                Ok(uuid) => Ok(ParentOrNone::Folder(uuid)),
                Err(_) => Err(de::Error::invalid_value(
                    de::Unexpected::Str(&none_or_id),
                    &"\"none\" or hyphenated lowercased UUID",
                )),
            }
        }
    }
}

impl Serialize for ParentOrNone {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            ParentOrNone::None => serializer.serialize_str("none"),
            ParentOrNone::Folder(uuid) => serializer.serialize_str(&uuid.to_hyphenated().to_string()),
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
        let expected = ParentOrBase::Base;

        let result = serde_json::from_str::<ParentOrBase>(&json);

        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn parent_kind_should_be_deserialized_from_id() {
        let json = r#""00000000-0000-0000-0000-000000000000""#;
        let expected = ParentOrBase::Folder(Uuid::nil());

        let result = serde_json::from_str::<ParentOrBase>(&json);

        assert_eq!(result.unwrap(), expected);
    }
}
