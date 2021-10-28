//! Contains structures common for Filen file&folder API.
use crate::{crypto, utils, v1::api_response_struct};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_json::json;
use snafu::{ResultExt, Snafu};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to deserialize location name: {}", source))]
    DeserializeLocationNameFailed { source: serde_json::Error },

    #[snafu(display("Failed to decrypt location name {}: {}", metadata, source))]
    DecryptLocationNameFailed { metadata: String, source: crypto::Error },
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

/// Identifies location type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LocationType {
    /// Location is a base folder.
    Base,
    /// Location is a file.
    File,
    /// Location is a folder.
    Folder,
    /// Location is a special Filen Sync folder.
    Sync,
}

impl LocationType {
    pub fn parent_or_base<T: Into<String>>(parent: Option<T>) -> String {
        match parent {
            Some(parent) => parent.into(),
            None => LocationType::Base.to_string(),
        }
    }
}

impl std::fmt::Display for LocationType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            LocationType::Base => write!(f, "base"),
            LocationType::File => write!(f, "file"),
            LocationType::Folder => write!(f, "folder"),
            LocationType::Sync => write!(f, "sync"),
        }
    }
}

/// Folder data for one of the user folders or for one of the folders in Filen sync folder.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FolderData {
    /// Folder ID, UUID V4 in hyphenated lowercase format.
    pub uuid: String,

    /// Metadata containing folder name.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Either parent folder ID or "base" when folder is located in the base folder, also known as 'cloud drive'.
    pub parent: String,
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
    pub fn encrypt_name_to_metadata(name: &str, last_master_key: &SecUtf8) -> String {
        let name_json = json!(LocationNameMetadata { name: name.to_owned() }).to_string();
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
    pub uuid: String,
}
utils::display_from_json!(LocationTrashRequestPayload);

// Used for requests to [DIR_EXISTS_PATH] or [FILE_TRASH_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocationExistsRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Parent folder ID, hyphenated lowercased UUID V4.
    pub parent: String,

    /// Currently hash_fn of lowercased target folder or file name.
    #[serde(rename = "nameHashed")]
    pub name_hashed: String,
}
utils::display_from_json!(LocationExistsRequestPayload);

impl LocationExistsRequestPayload {
    pub fn new(api_key: SecUtf8, target_parent: String, target_name: &str) -> LocationExistsRequestPayload {
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
    pub uuid: String,
}
utils::display_from_json!(LocationExistsResponseData);

api_response_struct!(
    /// Response for [DIR_EXISTS_PATH] or [FILE_TRASH_PATH] endpoint.
    LocationExistsResponsePayload<Option<LocationExistsResponseData>>
);
