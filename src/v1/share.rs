#[cfg(feature = "async")]
use crate::v1::download_dir_request_async;
use crate::{
    queries, utils, v1,
    v1::{
        bool_from_int, bool_to_int, bool_to_string, crypto, download_dir, download_dir_request, files, fs,
        response_payload, Backtrace, CryptoError, DownloadDirRequestPayload, FileProperties, FileStorageInfo,
        HasFileMetadata, HasLocationName, HasPublicKey, HasUuid, ItemKind, LocationColor, LocationNameMetadata,
        ParentOrNone, PlainResponsePayload,
    },
    FilenSettings, SettingsBundle,
};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use snafu::{ResultExt, Snafu};
use std::cmp::Ordering;
use strum::{Display, EnumString};
use uuid::Uuid;

use super::FilenResponse;

type Result<T, E = Error> = std::result::Result<T, E>;

const SHARE_PATH: &str = "/v1/share";
const SHARE_DIR_STATUS_PATH: &str = "/v1/share/dir/status";
const USER_SHARED_IN_PATH: &str = "/v1/user/shared/in";
const USER_SHARED_OUT_PATH: &str = "/v1/user/shared/out";
const USER_SHARED_ITEM_RENAME_PATH: &str = "/v1/user/shared/item/rename";
const USER_SHARED_ITEM_STATUS_PATH: &str = "/v1/user/shared/item/status";
const USER_SHARED_ITEM_IN_REMOVE_PATH: &str = "/v1/user/shared/item/in/remove";
const USER_SHARED_ITEM_OUT_REMOVE_PATH: &str = "/v1/user/shared/item/out/remove";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Filen cannot share file '{}': {}", uuid, message))]
    CannotShareFile {
        uuid: Uuid,
        message: String,
        backtrace: Backtrace,
    },

    #[snafu(display("Filen cannot share folder '{}': {}", uuid, message))]
    CannotShareFolder {
        uuid: Uuid,
        message: String,
        backtrace: Backtrace,
    },

    #[snafu(display("{}", source))]
    CannotGetUserFolderContents { source: v1::Error },

    #[snafu(display("Failed to decrypt file metadata '{}': {}", metadata, source))]
    DecryptFileMetadataFailed { metadata: String, source: files::Error },

    #[snafu(display("Failed to decrypt location name {}: {}", metadata, source))]
    DecryptLocationNameFailed { metadata: String, source: fs::Error },

    #[snafu(display("download_dir_request() failed: {}", source))]
    DownloadDirRequestFailed { source: download_dir::Error },

    #[snafu(display("Failed to encrypt file metadata '{}' using RSA: {}", metadata, source))]
    EncryptFileMetadataRsaFailed { metadata: String, source: files::Error },

    #[snafu(display("Failed to encrypt folder metadata '{}' using RSA: {}", metadata, source))]
    EncryptFolderMetadataRsaFailed { metadata: String, source: crypto::Error },

    #[snafu(display("{} query failed: {}", SHARE_DIR_STATUS_PATH, source))]
    ShareDirStatusQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", SHARE_PATH, source))]
    ShareQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_SHARED_IN_PATH, source))]
    UserSharedInQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_SHARED_OUT_PATH, source))]
    UserSharedOutQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_SHARED_ITEM_IN_REMOVE_PATH, source))]
    UserSharedItemInRemoveQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_SHARED_ITEM_OUT_REMOVE_PATH, source))]
    UserSharedItemOutRemoveQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_SHARED_ITEM_RENAME_PATH, source))]
    UserSharedItemRenameQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_SHARED_ITEM_STATUS_PATH, source))]
    UserSharedItemStatusQueryFailed { source: queries::Error },
}

/// Identifies shared item.
#[derive(Clone, Copy, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
pub enum ShareTarget {
    /// Linked item is a file.
    File,
    /// Linked item is a folder.
    Folder,
}

/// Used for requests to `SHARE_PATH` endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ShareRequestPayload<'share> {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: &'share SecUtf8,

    /// Email to share item with.
    pub email: &'share str,

    /// Base64-encoded RSA-encrypted file or folder properties.
    pub metadata: String,

    /// ID of the parent folder of the shared item.
    pub parent: ParentOrNone,

    /// Determines whether a file or a folder is being shared.
    #[serde(rename = "type")]
    pub share_type: ShareTarget,

    /// ID of the file or folder to share; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json_with_lifetime!('share, ShareRequestPayload);

impl<'share> ShareRequestPayload<'share> {
    pub fn from_file_data<T: HasFileMetadata + HasUuid>(
        api_key: &'share SecUtf8,
        file_data: &T,
        parent: ParentOrNone,
        receiver_email: &'share str,
        receiver_public_key_bytes: &[u8],
        master_keys: &[SecUtf8],
    ) -> Result<Self> {
        let file_properties = file_data
            .decrypt_file_metadata(master_keys)
            .context(DecryptFileMetadataFailedSnafu {
                metadata: file_data.file_metadata_ref().to_owned(),
            })?;
        Self::from_file_properties(
            api_key,
            *file_data.uuid_ref(),
            &file_properties,
            parent,
            receiver_email,
            receiver_public_key_bytes,
        )
        .context(EncryptFileMetadataRsaFailedSnafu {
            metadata: file_data.file_metadata_ref().to_owned(),
        })
    }

    pub fn from_file_properties(
        api_key: &'share SecUtf8,
        file_uuid: Uuid,
        file_properties: &FileProperties,
        parent: ParentOrNone,
        email: &'share str,
        rsa_public_key_bytes: &[u8],
    ) -> Result<Self, files::Error> {
        let metadata = file_properties.to_metadata_rsa_string(rsa_public_key_bytes)?;
        Ok(Self {
            api_key,
            email,
            metadata,
            parent,
            share_type: ShareTarget::File,
            uuid: file_uuid,
        })
    }

    pub fn from_folder_data<T: HasLocationName + HasUuid>(
        api_key: &'share SecUtf8,
        folder_data: &T,
        parent: ParentOrNone,
        receiver_email: &'share str,
        receiver_public_key_bytes: &[u8],
        master_keys: &[SecUtf8],
    ) -> Result<Self> {
        let folder_name = folder_data
            .decrypt_name_metadata(master_keys)
            .context(DecryptLocationNameFailedSnafu {
                metadata: folder_data.name_metadata_ref().to_owned(),
            })?;
        Self::from_folder_name(
            api_key,
            *folder_data.uuid_ref(),
            &folder_name,
            parent,
            receiver_email,
            receiver_public_key_bytes,
        )
        .context(EncryptFolderMetadataRsaFailedSnafu {
            metadata: folder_data.name_metadata_ref().to_owned(),
        })
    }

    pub fn from_folder_name(
        api_key: &'share SecUtf8,
        folder_uuid: Uuid,
        folder_name: &str,
        parent: ParentOrNone,
        email: &'share str,
        rsa_public_key_bytes: &[u8],
    ) -> Result<Self, CryptoError> {
        let metadata = LocationNameMetadata::encrypt_name_to_metadata_rsa(folder_name, rsa_public_key_bytes)?;
        Ok(Self {
            api_key,
            email,
            metadata,
            parent,
            share_type: ShareTarget::Folder,
            uuid: folder_uuid,
        })
    }
}

/// Used for requests to `SHARE_DIR_STATUS_PATH` endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ShareDirStatusRequestPayload<'share_dir_status> {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: &'share_dir_status SecUtf8,

    /// ID of the folder to check; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json_with_lifetime!('share_dir_status, ShareDirStatusRequestPayload);

/// User's email and RSA public key.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserEmailWithPublicKey {
    /// Email.
    pub email: String,

    /// RSA public key.
    #[serde(rename = "publicKey")]
    pub public_key: String,
}
utils::display_from_json!(UserEmailWithPublicKey);

impl HasPublicKey for UserEmailWithPublicKey {
    fn public_key_ref(&self) -> Option<&str> {
        Some(&self.public_key)
    }
}

/// Response data for `SHARE_DIR_STATUS_PATH` endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ShareDirStatusResponseData {
    /// True if the specified folder is shared; false otherwise.
    pub sharing: bool,

    /// Emails and public keys of 'receivers', the users the folder is shared with. Empty if folder is not shared.
    #[serde(default)]
    pub users: Vec<UserEmailWithPublicKey>,
}
utils::display_from_json!(ShareDirStatusResponseData);

response_payload!(
    /// Response for `SHARE_DIR_STATUS_PATH` endpoint.
    ShareDirStatusResponsePayload<ShareDirStatusResponseData>
);

#[derive(Clone, Copy, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[strum(ascii_case_insensitive, serialize_all = "kebab-case")]
pub enum SharedContentKind {
    SharedIn,
    SharedOut,
}

/// Used for requests to `USER_SHARED_IN_PATH` endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UserSharedInRequestPayload<'user_shared_in> {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: &'user_shared_in SecUtf8,

    /// Set to "shared-in" for requests to `USER_SHARED_IN_PATH`, and to "shared-out" for requests to
    /// `USER_SHARED_OUT_PATH`.
    pub uuid: SharedContentKind,

    /// A string containing 'path' to the listed folder as JSON array:
    /// "[\"grand_parent_uuid\", \"parent_uuid\", \"folder_uuid\"]"
    /// If folder has no parents, only 'folder_uuid' needs to be present. Can be empty string: "[\"\"]"
    pub folders: String,

    /// Seems like pagination parameter; currently is always 1.
    pub page: i32,

    // TODO: There is no way to tell its purpose from sources, need to ask Dwynr later.
    /// This flag is always set to true.
    #[serde(serialize_with = "bool_to_string")]
    pub app: bool,
}
utils::display_from_json_with_lifetime!('user_shared_in, UserSharedInRequestPayload);

/// Used for requests to `USER_SHARED_OUT_PATH` endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UserSharedOutRequestPayload<'user_shared_out> {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: &'user_shared_out SecUtf8,

    /// Set to "shared-in" for requests to `USER_SHARED_IN_PATH`, and to "shared-out" for requests to
    /// `USER_SHARED_OUT_PATH`.
    pub uuid: SharedContentKind,

    /// A string containing 'path' to the listed folder as JSON array:
    /// "[\"grand_parent_uuid\", \"parent_uuid\", \"folder_uuid\"]"
    /// If folder has no parents, only 'folder_uuid' needs to be present. Can be empty string: "[\"\"]"
    pub folders: String,

    /// Seems like pagination parameter; currently is always 1.
    pub page: i32,

    /// ID of the user with whom items are shared.
    #[serde(rename = "receiverId")]
    pub receiver_id: u64,

    // TODO: There is no way to tell its purpose from sources, need to ask Dwynr later.
    /// This flag is always set to true.
    #[serde(serialize_with = "bool_to_string")]
    pub app: bool,
}
utils::display_from_json_with_lifetime!('user_shared_out, UserSharedOutRequestPayload);

/// One of the files in response data for `USER_SHARED_IN` or `USER_SHARED_OUT_PATH` endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserSharedFile {
    /// File ID, UUID V4 in hyphenated lowercase format.
    pub uuid: Uuid,

    /// File metadata. For shared-in listings, it is encrypted with RSA public key of the user
    /// this item is being shared with aka receiver, base64-encoded.
    /// For shared-out listings, it is encrypted with current user's last master key, as usual.
    pub metadata: String,

    /// Always set to "file".
    #[serde(rename = "type")]
    pub item_type: ItemKind,

    /// Filen file storage info.
    #[serde(flatten)]
    pub storage: FileStorageInfo,

    /// Determines how file bytes should be encrypted/decrypted.
    /// File is encrypted using roughly the same algorithm as metadata encryption,
    /// use [crypto::encrypt_file_data] and [crypto::decrypt_file_data] for the task.
    pub version: u32,

    /// Parent folder or none.
    pub parent: Option<Uuid>,

    /// Email of the user who shares file, if this file is shared with 'current' user.
    #[serde(rename = "sharerEmail")]
    pub sharer_email: Option<String>,

    /// ID of the user who shares file, if this file is shared with 'current' user.
    #[serde(rename = "sharerId")]
    pub sharer_id: Option<u32>,

    /// Email of the user with whom file is shared, if 'current' user is sharing this file.
    #[serde(rename = "receiverEmail")]
    pub receiver_email: Option<String>,

    /// ID of the user with whom file is shared, if 'current' user is sharing this file.
    #[serde(rename = "receiverId")]
    pub receiver_id: Option<u32>,

    /// 1 if file is accessible for writing; 0 otherwise.
    #[serde(
        rename = "writeAccess",
        deserialize_with = "bool_from_int",
        serialize_with = "bool_to_int"
    )]
    pub write_access: bool,

    /// File creation time, as Unix timestamp in seconds.
    pub timestamp: u64,
}
utils::display_from_json!(UserSharedFile);

/// One of the files in response data for `USER_SHARED_IN` or `USER_SHARED_OUT_PATH` endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserSharedFolder {
    /// Folder ID, UUID V4 in hyphenated lowercase format.
    pub uuid: Uuid,

    /// Folder metadata. For shared-in listings, it is encrypted with RSA public key of the user
    /// this item is being shared with aka receiver, base64-encoded.
    /// For shared-out listings, it is encrypted with current user's last master key, as usual.
    pub metadata: String,

    /// Always set to "folder".
    #[serde(rename = "type")]
    pub item_type: ItemKind,

    /// Seems to be always set to None.
    pub bucket: Option<String>,

    /// Seems to be always set to None.
    pub region: Option<String>,

    /// Seems to be always set to None.
    pub chunks: Option<u32>,

    /// Parent folder or none.
    pub parent: Option<Uuid>,

    /// Email of the user who shares file, if this file is shared with 'current' user.
    #[serde(rename = "sharerEmail")]
    pub sharer_email: Option<String>,

    /// ID of the user who shares file, if this file is shared with 'current' user.
    #[serde(rename = "sharerId")]
    pub sharer_id: Option<u32>,

    /// Email of the user with whom file is shared, if 'current' user is sharing this file.
    #[serde(rename = "receiverEmail")]
    pub receiver_email: Option<String>,

    /// ID of the user with whom file is shared, if 'current' user is sharing this file.
    #[serde(rename = "receiverId")]
    pub receiver_id: Option<u32>,

    /// 1 if folder is accessible for writing; 0 otherwise.
    #[serde(
        rename = "writeAccess",
        deserialize_with = "bool_from_int",
        serialize_with = "bool_to_int"
    )]
    pub write_access: bool,

    /// Folder color name.
    pub color: Option<LocationColor>,

    /// Folder creation time, as Unix timestamp in seconds.
    pub timestamp: u64,

    /// true if this is a default Filen folder; false otherwise.
    #[serde(deserialize_with = "bool_from_int", serialize_with = "bool_to_int")]
    pub is_default: bool,

    /// true if this is a Filen sync folder; false otherwise.
    ///
    /// Filen sync folder is a special unique folder that is created by Filen client to store all synced files.
    /// If user never used Filen client, no sync folder would exist.
    ///
    /// Filen sync folder is always named "Filen Sync" and created with a special type: "sync".
    #[serde(deserialize_with = "bool_from_int", serialize_with = "bool_to_int")]
    pub is_sync: bool,
}
utils::display_from_json!(UserSharedFolder);

/// One of the base folders in response data for `USER_SHARED_IN` or `USER_SHARED_OUT_PATH` endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserSharedFolderInfo {
    /// Base folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Metadata containing JSON with folder name: { "name": <name value> }
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Folder color name; None means default yellow color.
    pub color: Option<LocationColor>,
}
utils::display_from_json!(UserSharedFolderInfo);

/// Response data for `USER_SHARED_IN` or `USER_SHARED_OUT_PATH` endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserSharedInOrOutResponseData {
    /// List of files in the given folder.
    pub uploads: Vec<UserSharedFile>,

    /// List of folders in the given folder.
    pub folders: Vec<UserSharedFolder>,

    /// Info for folders passed in [UserSharedInRequestPayload::folders] or [UserSharedOutRequestPayload::folders].
    #[serde(rename = "foldersInfo")]
    pub folders_info: Vec<UserSharedFolderInfo>,

    /// Number of files in the current folder.
    #[serde(rename = "totalUploads")]
    pub total_uploads: u64,

    /// Seems like pagination parameter; currently is always 999999999.
    #[serde(rename = "perPage")]
    pub per_page: u32,

    /// Seems like pagination parameter; currently is always 1.
    pub page: u32,
}
utils::display_from_json!(UserSharedInOrOutResponseData);

response_payload!(
    /// Response for `USER_SHARED_IN` or `USER_SHARED_OUT_PATH` endpoint.
    UserSharedInOrOutResponsePayload<UserSharedInOrOutResponseData>
);

/// Used for requests to `USER_SHARED_ITEM_RENAME_PATH` endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UserSharedItemRenameRequestPayload<'user_shared_item_rename> {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: &'user_shared_item_rename SecUtf8,

    /// Folder or file ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// ID of the user with whom item is shared.
    /// Set to 0 when renaming is done from the perspective of the user with whom item is shared aka receiver.
    #[serde(rename = "receiverId")]
    pub receiver_id: u64,

    /// Folder or file properties, encrypted with RSA public key of the user with whom item is shared aka receiver,
    /// base64-encoded.
    pub metadata: String,
}
utils::display_from_json_with_lifetime!('user_shared_item_rename, UserSharedItemRenameRequestPayload);

impl<'user_shared_item_rename> UserSharedItemRenameRequestPayload<'user_shared_item_rename> {
    pub fn from_file_properties(
        api_key: &'user_shared_item_rename SecUtf8,
        receiver_id: u64,
        file_uuid: Uuid,
        file_properties: &FileProperties,
        rsa_public_key_bytes: &[u8],
    ) -> Result<Self, files::Error> {
        let metadata = file_properties.to_metadata_rsa_string(rsa_public_key_bytes)?;
        Ok(Self {
            api_key,
            uuid: file_uuid,
            receiver_id,
            metadata,
        })
    }

    pub fn from_folder_name(
        api_key: &'user_shared_item_rename SecUtf8,
        receiver_id: u64,
        folder_uuid: Uuid,
        folder_name: &str,
        rsa_public_key_bytes: &[u8],
    ) -> Result<Self, CryptoError> {
        let metadata = LocationNameMetadata::encrypt_name_to_metadata_rsa(folder_name, rsa_public_key_bytes)?;
        Ok(Self {
            api_key,
            uuid: folder_uuid,
            receiver_id,
            metadata,
        })
    }
}

/// Used for requests to `USER_SHARED_ITEM_IN_REMOVE_PATH` and `USER_SHARED_ITEM_OUT_REMOVE_PATH` endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UserSharedItemRemoveRequestPayload<'user_shared_item_remove> {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: &'user_shared_item_remove SecUtf8,

    /// ID of the user this item is being shared with.
    /// Set to 0 when removing is done from the perspective of the user with whom item is shared aka receiver.
    #[serde(rename = "receiverId")]
    pub receiver_id: u64,

    /// ID of the shared item; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json_with_lifetime!('user_shared_item_remove, UserSharedItemRemoveRequestPayload);

/// Used for requests to `USER_SHARED_ITEM_STATUS_PATH` endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UserSharedItemStatusRequestPayload<'user_shared_item_status> {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: &'user_shared_item_status SecUtf8,

    /// ID of the item to check; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json_with_lifetime!('user_shared_item_status, UserSharedItemStatusRequestPayload);

/// User's id and RSA public key.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserIdWithPublicKey {
    /// User ID.
    pub id: u32,

    /// RSA public key.
    #[serde(rename = "publicKey")]
    pub public_key: String,
}
utils::display_from_json!(UserIdWithPublicKey);

impl HasPublicKey for UserIdWithPublicKey {
    fn public_key_ref(&self) -> Option<&str> {
        Some(&self.public_key)
    }
}

impl Ord for UserIdWithPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialOrd for UserIdWithPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Response data for `USER_SHARED_ITEM_STATUS_PATH` endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserSharedItemStatusResponseData {
    /// True if the specified folder is shared; false otherwise.
    pub sharing: bool,

    /// Emails and public keys of the users the folder is shared with. Empty if folder is not shared.
    ///
    /// Note that if folder is shared, there might be multiple copies of the same user data here.
    #[serde(default)]
    pub users: Vec<UserIdWithPublicKey>,
}
utils::display_from_json!(UserSharedItemStatusResponseData);

response_payload!(
    /// Response for `USER_SHARED_ITEM_STATUS_PATH` endpoint.
    UserSharedItemStatusResponsePayload<UserSharedItemStatusResponseData>
);

/// Calls `SHARE_DIR_STATUS_PATH` endpoint. Used to check if given folder is shared and return 'receivers',
/// the users the folder is shared with, if any.
pub fn share_dir_status_request(
    payload: &ShareDirStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<ShareDirStatusResponsePayload> {
    queries::query_filen_api(SHARE_DIR_STATUS_PATH, payload, filen_settings).context(ShareDirStatusQueryFailedSnafu {})
}

/// Calls `SHARE_DIR_STATUS_PATH` endpoint asynchronously. Used to check if given folder is shared and return 'receivers',
/// the users the folder is shared with, if any.
#[cfg(feature = "async")]
pub async fn share_dir_status_request_async(
    payload: &ShareDirStatusRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<ShareDirStatusResponsePayload> {
    queries::query_filen_api_async(SHARE_DIR_STATUS_PATH, payload, filen_settings)
        .await
        .context(ShareDirStatusQueryFailedSnafu {})
}

/// Calls `SHARE_PATH` endpoint. Used to share a file or folder.
pub fn share_request(payload: &ShareRequestPayload, filen_settings: &FilenSettings) -> Result<PlainResponsePayload> {
    queries::query_filen_api(SHARE_PATH, payload, filen_settings).context(ShareQueryFailedSnafu {})
}

/// Calls `SHARE_PATH` endpoint asynchronously. Used to share a file or folder.
#[cfg(feature = "async")]
pub async fn share_request_async(
    payload: &ShareRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(SHARE_PATH, payload, filen_settings)
        .await
        .context(ShareQueryFailedSnafu {})
}

/// Calls `USER_SHARED_IN_PATH` endpoint.
/// Used to list shared content from the perspective of the user with whom item is shared aka receiver.
pub fn user_shared_in_request(
    payload: &UserSharedInRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserSharedInOrOutResponsePayload> {
    queries::query_filen_api(USER_SHARED_IN_PATH, payload, filen_settings).context(UserSharedInQueryFailedSnafu {})
}

/// Calls `USER_SHARED_IN_PATH` endpoint asynchronously.
/// Used to list shared content from the perspective of the user with whom item is shared aka receiver.
#[cfg(feature = "async")]
pub async fn user_shared_in_request_async(
    payload: &UserSharedInRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<UserSharedInOrOutResponsePayload> {
    queries::query_filen_api_async(USER_SHARED_IN_PATH, payload, filen_settings)
        .await
        .context(UserSharedInQueryFailedSnafu {})
}

/// Calls `USER_SHARED_OUT_PATH` endpoint.
/// Used to list shared content from the perspective of the user who shares files, aka sharer.
pub fn user_shared_out_request(
    payload: &UserSharedOutRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserSharedInOrOutResponsePayload> {
    queries::query_filen_api(USER_SHARED_OUT_PATH, payload, filen_settings).context(UserSharedOutQueryFailedSnafu {})
}

/// Calls `USER_SHARED_OUT_PATH` endpoint asynchronously.
/// Used to list shared content from the perspective of the user who shares files, aka sharer.
#[cfg(feature = "async")]
pub async fn user_shared_out_request_async(
    payload: &UserSharedOutRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<UserSharedInOrOutResponsePayload> {
    queries::query_filen_api_async(USER_SHARED_OUT_PATH, payload, filen_settings)
        .await
        .context(UserSharedOutQueryFailedSnafu {})
}

/// Calls `USER_SHARED_ITEM_IN_REMOVE_PATH` endpoint.
/// Used to remove shared item from the perspective of the user with whom item is shared aka receiver.
pub fn user_shared_item_in_remove_request(
    payload: &UserSharedItemRemoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(USER_SHARED_ITEM_IN_REMOVE_PATH, payload, filen_settings)
        .context(UserSharedItemInRemoveQueryFailedSnafu {})
}

/// Calls `USER_SHARED_ITEM_IN_REMOVE_PATH` endpoint asynchronously.
/// Used to remove shared item from the perspective of the user with whom item is shared aka receiver.
#[cfg(feature = "async")]
pub async fn user_shared_item_in_rename_request_async(
    payload: &UserSharedItemRemoveRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(USER_SHARED_ITEM_IN_REMOVE_PATH, payload, filen_settings)
        .await
        .context(UserSharedItemInRemoveQueryFailedSnafu {})
}

/// Calls `USER_SHARED_ITEM_OUT_REMOVE_PATH` endpoint.
/// Used to remove shared item from the perspective of an item's owner aka sharer: to stop sharing the item.
pub fn user_shared_item_out_remove_request(
    payload: &UserSharedItemRemoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(USER_SHARED_ITEM_OUT_REMOVE_PATH, payload, filen_settings)
        .context(UserSharedItemOutRemoveQueryFailedSnafu {})
}

/// Calls `USER_SHARED_ITEM_OUT_REMOVE_PATH` endpoint asynchronously.
/// Used to remove shared item from the perspective of an item's owner aka sharer: to stop sharing the item.
#[cfg(feature = "async")]
pub async fn user_shared_item_out_remove_request_async(
    payload: &UserSharedItemRemoveRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(USER_SHARED_ITEM_OUT_REMOVE_PATH, payload, filen_settings)
        .await
        .context(UserSharedItemOutRemoveQueryFailedSnafu {})
}

/// Calls `USER_SHARED_ITEM_RENAME_PATH` endpoint.
pub fn user_shared_item_rename_request(
    payload: &UserSharedItemRenameRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(USER_SHARED_ITEM_RENAME_PATH, payload, filen_settings)
        .context(UserSharedItemRenameQueryFailedSnafu {})
}

/// Calls `USER_SHARED_ITEM_RENAME_PATH` endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn user_shared_item_rename_request_async(
    payload: &UserSharedItemRenameRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(USER_SHARED_ITEM_RENAME_PATH, payload, filen_settings)
        .await
        .context(UserSharedItemRenameQueryFailedSnafu {})
}

/// Calls `USER_SHARED_ITEM_STATUS_PATH` endpoint.
pub fn user_shared_item_status_request(
    payload: &UserSharedItemStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserSharedItemStatusResponsePayload> {
    queries::query_filen_api(USER_SHARED_ITEM_STATUS_PATH, payload, filen_settings)
        .context(UserSharedItemStatusQueryFailedSnafu {})
}

/// Calls `USER_SHARED_ITEM_STATUS_PATH` endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn user_shared_item_status_request_async(
    payload: &UserSharedItemStatusRequestPayload<'_>,
    filen_settings: &FilenSettings,
) -> Result<UserSharedItemStatusResponsePayload> {
    queries::query_filen_api_async(USER_SHARED_ITEM_STATUS_PATH, payload, filen_settings)
        .await
        .context(UserSharedItemStatusQueryFailedSnafu {})
}

/// Helper which shares given file with the specified user.
pub fn share_file<T: HasFileMetadata + HasUuid>(
    api_key: &SecUtf8,
    file_data: &T,
    parent: ParentOrNone,
    receiver_email: &str,
    receiver_public_key_bytes: &[u8],
    master_keys: &[SecUtf8],
    filen_settings: &FilenSettings,
) -> Result<String> {
    let file_properties = file_data
        .decrypt_file_metadata(master_keys)
        .context(DecryptFileMetadataFailedSnafu {
            metadata: file_data.file_metadata_ref().to_owned(),
        })?;
    let share_payload = ShareRequestPayload::from_file_properties(
        api_key,
        *file_data.uuid_ref(),
        &file_properties,
        parent,
        receiver_email,
        receiver_public_key_bytes,
    )
    .context(EncryptFileMetadataRsaFailedSnafu {
        metadata: file_data.file_metadata_ref().to_owned(),
    })?;
    let response = share_request(&share_payload, filen_settings)?;
    if response.status {
        Ok(response.message.unwrap_or_default())
    } else {
        CannotShareFileSnafu {
            uuid: *file_data.uuid_ref(),
            message: format!("{:?}", response.message),
        }
        .fail()
    }
}

/// Helper which shares given file with the specified user; asynchronous.
#[cfg(feature = "async")]
pub async fn share_file_async<T: HasFileMetadata + HasUuid + Sync>(
    api_key: &SecUtf8,
    file_data: &T,
    parent: ParentOrNone,
    receiver_email: &str,
    receiver_public_key_bytes: &[u8],
    master_keys: &[SecUtf8],
    filen_settings: &FilenSettings,
) -> Result<String> {
    let share_payload = ShareRequestPayload::from_file_data(
        api_key,
        file_data,
        parent,
        receiver_email,
        receiver_public_key_bytes,
        master_keys,
    )?;
    let response = share_request_async(&share_payload, filen_settings).await?;
    if response.status {
        Ok(response.message.unwrap_or_default())
    } else {
        CannotShareFileSnafu {
            uuid: *file_data.uuid_ref(),
            message: format!("{:?}", response.message),
        }
        .fail()
    }
}

/// Helper which shares just the given folder without its files and sub-folders.
pub fn share_folder<T: HasLocationName + HasUuid>(
    api_key: &SecUtf8,
    folder_data: &T,
    parent: ParentOrNone,
    receiver_email: &str,
    receiver_public_key_bytes: &[u8],
    master_keys: &[SecUtf8],
    filen_settings: &FilenSettings,
) -> Result<String> {
    let share_payload = ShareRequestPayload::from_folder_data(
        api_key,
        folder_data,
        parent,
        receiver_email,
        receiver_public_key_bytes,
        master_keys,
    )?;
    let response = share_request(&share_payload, filen_settings)?;
    if response.status {
        Ok(response.message.unwrap_or_default())
    } else {
        CannotShareFolderSnafu {
            uuid: *folder_data.uuid_ref(),
            message: format!("{:?}", response.message),
        }
        .fail()
    }
}

/// Helper which shares just the given folder without its files and sub-folders; asynchronous.
#[cfg(feature = "async")]
pub async fn share_folder_async<T: HasLocationName + HasUuid + Sync>(
    api_key: &SecUtf8,
    folder_data: &T,
    parent: ParentOrNone,
    receiver_email: &str,
    receiver_public_key_bytes: &[u8],
    master_keys: &[SecUtf8],
    filen_settings: &FilenSettings,
) -> Result<String> {
    let share_payload = ShareRequestPayload::from_folder_data(
        api_key,
        folder_data,
        parent,
        receiver_email,
        receiver_public_key_bytes,
        master_keys,
    )?;
    let response = share_request_async(&share_payload, filen_settings).await?;
    if response.status {
        Ok(response.message.unwrap_or_default())
    } else {
        CannotShareFolderSnafu {
            uuid: *folder_data.uuid_ref(),
            message: format!("{:?}", response.message),
        }
        .fail()
    }
}

/// Helper which shares the given folder and all its sub-folders recursively, with files.
pub fn share_folder_recursively(
    api_key: &SecUtf8,
    folder_uuid: Uuid,
    receiver_email: &str,
    receiver_public_key_bytes: &[u8],
    master_keys: &[SecUtf8],
    settings: &SettingsBundle,
) -> Result<()> {
    let content_payload = DownloadDirRequestPayload {
        api_key,
        uuid: folder_uuid,
    };
    let contents_response = settings
        .retry
        .call(|| download_dir_request(&content_payload, &settings.filen))
        .context(DownloadDirRequestFailedSnafu {})?;
    let contents = contents_response
        .data_ref_or_err()
        .context(CannotGetUserFolderContentsSnafu {})?;
    // Share this folder and all sub-folders:
    contents
        .folders
        .iter()
        .map(|folder| {
            settings.retry.call(|| {
                share_folder(
                    api_key,
                    folder,
                    folder.parent.as_parent_or_none(),
                    receiver_email,
                    receiver_public_key_bytes,
                    master_keys,
                    &settings.filen,
                )
                .map(|_| ())
            })
        })
        .collect::<Result<Vec<()>>>()?;
    // Share all files.
    contents
        .files
        .iter()
        .map(|file| {
            settings.retry.call(|| {
                share_file(
                    api_key,
                    file,
                    ParentOrNone::Folder(file.parent),
                    receiver_email,
                    receiver_public_key_bytes,
                    master_keys,
                    &settings.filen,
                )
                .map(|_| ())
            })
        })
        .collect::<Result<Vec<()>>>()?;

    Ok(())
}

/// Helper which shares the given folder and all its sub-folders recursively, with files.
#[cfg(feature = "async")]
pub async fn share_folder_recursively_async(
    api_key: &SecUtf8,
    folder_uuid: Uuid,
    receiver_email: &str,
    receiver_public_key_bytes: &[u8],
    master_keys: &[SecUtf8],
    settings: &SettingsBundle,
) -> Result<()> {
    let content_payload = DownloadDirRequestPayload {
        api_key,
        uuid: folder_uuid,
    };
    let contents_response = settings
        .retry
        .call_async(|| download_dir_request_async(&content_payload, &settings.filen))
        .await
        .context(DownloadDirRequestFailedSnafu {})?;
    let contents = contents_response
        .data_ref_or_err()
        .context(CannotGetUserFolderContentsSnafu {})?;
    // Share this folder and all sub-folders:
    let folder_futures = contents.folders.iter().map(|folder| {
        settings.retry.call_async(move || async move {
            share_folder_async(
                api_key,
                folder,
                folder.parent.as_parent_or_none(),
                receiver_email,
                receiver_public_key_bytes,
                master_keys,
                &settings.filen,
            )
            .await
            .map(|_| ())
        })
    });
    futures::future::try_join_all(folder_futures).await?;

    // Share all files:
    let file_futures = contents.files.iter().map(|file| {
        settings.retry.call_async(move || async move {
            share_file_async(
                api_key,
                file,
                ParentOrNone::Folder(file.parent),
                receiver_email,
                receiver_public_key_bytes,
                master_keys,
                &settings.filen,
            )
            .await
            .map(|_| ())
        })
    });
    futures::future::try_join_all(file_futures).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::validate_contract;
    #[cfg(feature = "async")]
    use crate::test_utils::validate_contract_async;
    use once_cell::sync::Lazy;
    use secstr::SecUtf8;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"));

    #[test]
    fn share_dir_status_request_should_have_proper_contract_for_shared_folder() {
        let request_payload = ShareDirStatusRequestPayload {
            api_key: &API_KEY,
            uuid: Uuid::nil(),
        };
        validate_contract(
            SHARE_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/share_dir_status.json",
            |request_payload, filen_settings| share_dir_status_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn share_dir_status_request_async_should_have_proper_contract_for_shared_folder() {
        let request_payload = ShareDirStatusRequestPayload {
            api_key: &API_KEY,
            uuid: Uuid::nil(),
        };
        validate_contract_async(
            SHARE_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/share_dir_status.json",
            |request_payload, filen_settings| async move {
                share_dir_status_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn share_dir_status_request_should_have_proper_contract_for_non_shared_folder() {
        let request_payload = ShareDirStatusRequestPayload {
            api_key: &API_KEY,
            uuid: Uuid::nil(),
        };
        validate_contract(
            SHARE_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/share_dir_status_not_shared.json",
            |request_payload, filen_settings| share_dir_status_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn share_dir_status_request_async_should_have_proper_contract_for_non_shared_folder() {
        let request_payload = ShareDirStatusRequestPayload {
            api_key: &API_KEY,
            uuid: Uuid::nil(),
        };
        validate_contract_async(
            SHARE_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/share_dir_status_not_shared.json",
            |request_payload, filen_settings| async move {
                share_dir_status_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn user_shared_in_request_should_have_proper_contract() {
        let request_payload = UserSharedInRequestPayload {
            api_key: &API_KEY,
            uuid: SharedContentKind::SharedIn,
            folders: "[\"5c86494b-36ec-4d39-a839-9f391474ad00\"]".to_owned(),
            page: 1,
            app: true,
        };
        validate_contract(
            USER_SHARED_IN_PATH,
            request_payload,
            "tests/resources/responses/user_shared_in.json",
            |request_payload, filen_settings| user_shared_in_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn user_shared_in_request_async_should_have_proper_contract() {
        let request_payload = UserSharedInRequestPayload {
            api_key: &API_KEY,
            uuid: SharedContentKind::SharedIn,
            folders: "[\"5c86494b-36ec-4d39-a839-9f391474ad00\"]".to_owned(),
            page: 1,
            app: true,
        };
        validate_contract_async(
            USER_SHARED_IN_PATH,
            request_payload,
            "tests/resources/responses/user_shared_in.json",
            |request_payload, filen_settings| async move {
                user_shared_in_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn user_shared_out_request_should_have_proper_contract() {
        let request_payload = UserSharedOutRequestPayload {
            api_key: &API_KEY,
            uuid: SharedContentKind::SharedOut,
            folders: "[\"5c86494b-36ec-4d39-a839-9f391474ad00\"]".to_owned(),
            page: 1,
            receiver_id: 4947,
            app: true,
        };
        validate_contract(
            USER_SHARED_OUT_PATH,
            request_payload,
            "tests/resources/responses/user_shared_out.json",
            |request_payload, filen_settings| user_shared_out_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn user_shared_out_request_async_should_have_proper_contract() {
        let request_payload = UserSharedOutRequestPayload {
            api_key: &API_KEY,
            uuid: SharedContentKind::SharedOut,
            folders: "[\"5c86494b-36ec-4d39-a839-9f391474ad00\"]".to_owned(),
            page: 1,
            receiver_id: 4947,
            app: true,
        };
        validate_contract_async(
            USER_SHARED_OUT_PATH,
            request_payload,
            "tests/resources/responses/user_shared_out.json",
            |request_payload, filen_settings| async move {
                user_shared_out_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn user_shared_item_status_request_should_have_proper_contract_for_shared_folder() {
        let request_payload = UserSharedItemStatusRequestPayload {
            api_key: &API_KEY,
            uuid: Uuid::nil(),
        };
        validate_contract(
            USER_SHARED_ITEM_STATUS_PATH,
            request_payload,
            "tests/resources/responses/user_shared_item_status.json",
            |request_payload, filen_settings| user_shared_item_status_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn user_shared_item_status_request_async_should_have_proper_contract_for_shared_folder() {
        let request_payload = UserSharedItemStatusRequestPayload {
            api_key: &API_KEY,
            uuid: Uuid::nil(),
        };
        validate_contract_async(
            USER_SHARED_ITEM_STATUS_PATH,
            request_payload,
            "tests/resources/responses/user_shared_item_status.json",
            |request_payload, filen_settings| async move {
                user_shared_item_status_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }
}
