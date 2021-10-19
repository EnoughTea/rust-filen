pub use super::{dirs::*, download_dir::*, download_file::*, files::*, sync_dir::*, upload_file::*};
use crate::{crypto, utils, v1::*};
use anyhow::*;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Typed folder or file name metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct LocationNameMetadata {
    pub name: String,
}

impl LocationNameMetadata {
    pub fn encrypt_name_to_metadata(name: &str, last_master_key: &SecUtf8) -> String {
        let name_json = json!(LocationNameMetadata { name: name.to_owned() }).to_string();
        crypto::encrypt_metadata_str(&name_json, last_master_key.unsecure(), super::METADATA_VERSION).unwrap()
    }

    /// Decrypt name metadata into actual folder name.
    pub fn decrypt_name_from_metadata(name_metadata: &str, last_master_key: &SecUtf8) -> Result<String> {
        crypto::decrypt_metadata_str(name_metadata, last_master_key.unsecure()).and_then(|metadata| {
            serde_json::from_str::<LocationNameMetadata>(&metadata)
                .with_context(|| "Cannot deserialize user dir name metadata")
                .map(|typed| typed.name)
        })
    }

    pub fn name_hashed(name: &str) -> String {
        crypto::hash_fn(&name.to_lowercase())
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
        let name_hashed = LocationNameMetadata::name_hashed(&target_name);
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
