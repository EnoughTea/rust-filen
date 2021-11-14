use crate::{filen_settings::*, queries, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

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
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
pub enum ShareTarget {
    /// Linked item is a file.
    File,
    /// Linked item is a folder.
    Folder,
}

/// Used for requests to [SHARE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShareRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Email to share item with.
    pub email: String,

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
utils::display_from_json!(ShareRequestPayload);

impl ShareRequestPayload {
    pub fn from_file_properties(
        api_key: SecUtf8,
        file_uuid: Uuid,
        parent: ParentOrNone,
        file_properties: &FileProperties,
        email: String,
        rsa_public_key_bytes: &[u8],
    ) -> Result<ShareRequestPayload, files::Error> {
        let metadata = file_properties.to_metadata_rsa_string(rsa_public_key_bytes)?;
        Ok(ShareRequestPayload {
            api_key,
            email,
            metadata,
            parent,
            share_type: ShareTarget::File,
            uuid: file_uuid,
        })
    }

    pub fn from_folder_name(
        api_key: SecUtf8,
        folder_uuid: Uuid,
        parent: ParentOrNone,
        folder_name: &str,
        email: String,
        rsa_public_key_bytes: &[u8],
    ) -> Result<ShareRequestPayload, CryptoError> {
        let metadata = LocationNameMetadata::encrypt_name_to_metadata_rsa(folder_name, rsa_public_key_bytes)?;
        Ok(ShareRequestPayload {
            api_key,
            email,
            metadata,
            parent,
            share_type: ShareTarget::Folder,
            uuid: folder_uuid,
        })
    }
}

/// Used for requests to [SHARE_DIR_STATUS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShareDirStatusRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the folder to check; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(ShareDirStatusRequestPayload);

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

/// Response data for [SHARE_DIR_STATUS_PATH] endpoint.
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
    /// Response for [SHARE_DIR_STATUS_PATH] endpoint.
    ShareDirStatusResponsePayload<ShareDirStatusResponseData>
);

#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[strum(ascii_case_insensitive, serialize_all = "kebab-case")]
pub enum SharedContentKind {
    SharedIn,
    SharedOut,
}

/// Used for requests to [USER_SHARED_IN_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSharedInRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Set to "shared-in" for requests to [USER_SHARED_IN_PATH], and to "shared-out" for requests to
    /// [USER_SHARED_OUT_PATH].
    pub uuid: SharedContentKind,

    /// A string containing 'path' to the listed folder as JSON array:
    /// "[\"grand_parent_uuid\", \"parent_uuid\", \"folder_uuid\"]"
    /// If folder has no parents, only 'folder_uuid' needs to be present. Can be empty string: "[\"\"]"
    pub folders: String,

    /// Seems like pagination parameter; currently is always 1.
    pub page: i32,

    // TODO: There is no way to tell its purpose from sources, need to ask Dwynr later.
    /// This flag is always set to true.
    #[serde(deserialize_with = "bool_from_string", serialize_with = "bool_to_string")]
    pub app: bool,
}
utils::display_from_json!(UserSharedInRequestPayload);

/// Used for requests to [USER_SHARED_OUT_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSharedOutRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Set to "shared-in" for requests to [USER_SHARED_IN_PATH], and to "shared-out" for requests to
    /// [USER_SHARED_OUT_PATH].
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
    #[serde(deserialize_with = "bool_from_string", serialize_with = "bool_to_string")]
    pub app: bool,
}
utils::display_from_json!(UserSharedOutRequestPayload);

/// One of the files in response data for [USER_SHARED_IN] or [USER_SHARED_OUT_PATH] endpoint.
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

/// One of the files in response data for [USER_SHARED_IN] or [USER_SHARED_OUT_PATH] endpoint.
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

/// One of the base folders in response data for [USER_SHARED_IN] or [USER_SHARED_OUT_PATH] endpoint.
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

/// Response data for [USER_SHARED_IN] or [USER_SHARED_OUT_PATH] endpoint.
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
    /// Response for [USER_SHARED_IN] or [USER_SHARED_OUT_PATH] endpoint.
    UserSharedInOrOutResponsePayload<UserSharedInOrOutResponseData>
);

/// Used for requests to [USER_SHARED_ITEM_RENAME_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSharedItemRenameRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

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
utils::display_from_json!(UserSharedItemRenameRequestPayload);

impl UserSharedItemRenameRequestPayload {
    pub fn from_file_properties(
        api_key: SecUtf8,
        receiver_id: u64,
        file_uuid: Uuid,
        file_properties: &FileProperties,
        rsa_public_key_bytes: &[u8],
    ) -> Result<UserSharedItemRenameRequestPayload, files::Error> {
        let metadata = file_properties.to_metadata_rsa_string(rsa_public_key_bytes)?;
        Ok(UserSharedItemRenameRequestPayload {
            api_key,
            uuid: file_uuid,
            receiver_id,
            metadata,
        })
    }

    pub fn from_folder_name(
        api_key: SecUtf8,
        receiver_id: u64,
        folder_uuid: Uuid,
        folder_name: &str,
        rsa_public_key_bytes: &[u8],
    ) -> Result<UserSharedItemRenameRequestPayload, CryptoError> {
        let metadata = LocationNameMetadata::encrypt_name_to_metadata_rsa(folder_name, rsa_public_key_bytes)?;
        Ok(UserSharedItemRenameRequestPayload {
            api_key,
            uuid: folder_uuid,
            receiver_id,
            metadata,
        })
    }
}

/// Used for requests to [USER_SHARED_ITEM_IN_REMOVE_PATH] and [USER_SHARED_ITEM_OUT_REMOVE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSharedItemRemoveRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the user this item is being shared with.
    /// Set to 0 when removing is done from the perspective of the user with whom item is shared aka receiver.
    #[serde(rename = "receiverId")]
    pub receiver_id: u64,

    /// ID of the shared item; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(UserSharedItemRemoveRequestPayload);

/// Used for requests to [USER_SHARED_ITEM_STATUS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSharedItemStatusRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the item to check; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(UserSharedItemStatusRequestPayload);

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

/// Response data for [USER_SHARED_ITEM_STATUS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserSharedItemStatusResponseData {
    /// True if the specified folder is shared; false otherwise.
    pub sharing: bool,

    /// Emails and public keys of the users the folder is shared with. Empty if folder is not shared.
    #[serde(default)]
    pub users: Vec<UserIdWithPublicKey>,
}
utils::display_from_json!(UserSharedItemStatusResponseData);

response_payload!(
    /// Response for [USER_SHARED_ITEM_STATUS_PATH] endpoint.
    UserSharedItemStatusResponsePayload<UserSharedItemStatusResponseData>
);

/// Calls [SHARE_DIR_STATUS_PATH] endpoint. Used to check if given folder is shared and return 'receivers',
/// the users the folder is shared with, if any.
pub fn share_dir_status_request(
    payload: &ShareDirStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<ShareDirStatusResponsePayload> {
    queries::query_filen_api(SHARE_DIR_STATUS_PATH, payload, filen_settings).context(ShareDirStatusQueryFailed {})
}

/// Calls [SHARE_DIR_STATUS_PATH] endpoint asynchronously. Used to check if given folder is shared and return 'receivers',
/// the users the folder is shared with, if any.
#[cfg(feature = "async")]
pub async fn share_dir_status_request_async(
    payload: &ShareDirStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<ShareDirStatusResponsePayload> {
    queries::query_filen_api_async(SHARE_DIR_STATUS_PATH, payload, filen_settings)
        .await
        .context(ShareDirStatusQueryFailed {})
}

/// Calls [SHARE_PATH] endpoint. Used to share a file or folder.
pub fn share_request(payload: &ShareRequestPayload, filen_settings: &FilenSettings) -> Result<PlainResponsePayload> {
    queries::query_filen_api(SHARE_PATH, payload, filen_settings).context(ShareQueryFailed {})
}

/// Calls [SHARE_PATH] endpoint asynchronously. Used to share a file or folder.
#[cfg(feature = "async")]
pub async fn share_request_async(
    payload: &ShareRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(SHARE_PATH, payload, filen_settings)
        .await
        .context(ShareQueryFailed {})
}

/// Calls [USER_SHARED_IN_PATH] endpoint.
/// Used to list shared content from the perspective of the user with whom item is shared aka receiver.
pub fn user_shared_in_request(
    payload: &UserSharedInRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserSharedInOrOutResponsePayload> {
    queries::query_filen_api(USER_SHARED_IN_PATH, payload, filen_settings).context(UserSharedInQueryFailed {})
}

/// Calls [USER_SHARED_IN_PATH] endpoint asynchronously.
/// Used to list shared content from the perspective of the user with whom item is shared aka receiver.
#[cfg(feature = "async")]
pub async fn user_shared_in_request_async(
    payload: &UserSharedInRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserSharedInOrOutResponsePayload> {
    queries::query_filen_api_async(USER_SHARED_IN_PATH, payload, filen_settings)
        .await
        .context(UserSharedInQueryFailed {})
}

/// Calls [USER_SHARED_OUT_PATH] endpoint.
/// Used to list shared content from the perspective of the user who shares files, aka sharer.
pub fn user_shared_out_request(
    payload: &UserSharedOutRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserSharedInOrOutResponsePayload> {
    queries::query_filen_api(USER_SHARED_OUT_PATH, payload, filen_settings).context(UserSharedOutQueryFailed {})
}

/// Calls [USER_SHARED_OUT_PATH] endpoint asynchronously.
/// Used to list shared content from the perspective of the user who shares files, aka sharer.
#[cfg(feature = "async")]
pub async fn user_shared_out_request_async(
    payload: &UserSharedOutRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserSharedInOrOutResponsePayload> {
    queries::query_filen_api_async(USER_SHARED_OUT_PATH, payload, filen_settings)
        .await
        .context(UserSharedOutQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_IN_REMOVE_PATH] endpoint.
/// Used to remove shared item from the perspective of the user with whom item is shared aka receiver.
pub fn user_shared_item_in_remove_request(
    payload: &UserSharedItemRemoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(USER_SHARED_ITEM_IN_REMOVE_PATH, payload, filen_settings)
        .context(UserSharedItemInRemoveQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_IN_REMOVE_PATH] endpoint asynchronously.
/// Used to remove shared item from the perspective of the user with whom item is shared aka receiver.
#[cfg(feature = "async")]
pub async fn user_shared_item_in_rename_request_async(
    payload: &UserSharedItemRemoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(USER_SHARED_ITEM_IN_REMOVE_PATH, payload, filen_settings)
        .await
        .context(UserSharedItemInRemoveQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_OUT_REMOVE_PATH] endpoint.
/// Used to remove shared item from the perspective of an item's owner aka sharer: to stop sharing the item.
pub fn user_shared_item_out_remove_request(
    payload: &UserSharedItemRemoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(USER_SHARED_ITEM_OUT_REMOVE_PATH, payload, filen_settings)
        .context(UserSharedItemOutRemoveQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_OUT_REMOVE_PATH] endpoint asynchronously.
/// Used to remove shared item from the perspective of an item's owner aka sharer: to stop sharing the item.
#[cfg(feature = "async")]
pub async fn user_shared_item_out_remove_request_async(
    payload: &UserSharedItemRemoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(USER_SHARED_ITEM_OUT_REMOVE_PATH, payload, filen_settings)
        .await
        .context(UserSharedItemOutRemoveQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_RENAME_PATH] endpoint.
pub fn user_shared_item_rename_request(
    payload: &UserSharedItemRenameRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(USER_SHARED_ITEM_RENAME_PATH, payload, filen_settings)
        .context(UserSharedItemRenameQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_RENAME_PATH] endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn user_shared_item_rename_request_async(
    payload: &UserSharedItemRenameRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(USER_SHARED_ITEM_RENAME_PATH, payload, filen_settings)
        .await
        .context(UserSharedItemRenameQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_STATUS_PATH] endpoint.
pub fn user_shared_item_status_request(
    payload: &UserSharedItemStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserSharedItemStatusResponsePayload> {
    queries::query_filen_api(USER_SHARED_ITEM_STATUS_PATH, payload, filen_settings)
        .context(UserSharedItemStatusQueryFailed {})
}

/// Calls [USER_SHARED_ITEM_STATUS_PATH] endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn user_shared_item_status_request_async(
    payload: &UserSharedItemStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserSharedItemStatusResponsePayload> {
    queries::query_filen_api_async(USER_SHARED_ITEM_STATUS_PATH, payload, filen_settings)
        .await
        .context(UserSharedItemStatusQueryFailed {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use once_cell::sync::Lazy;
    use secstr::SecUtf8;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"));

    #[test]
    fn share_dir_status_request_should_have_proper_contract_for_shared_folder() {
        let request_payload = ShareDirStatusRequestPayload {
            api_key: API_KEY.clone(),
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
            api_key: API_KEY.clone(),
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
            api_key: API_KEY.clone(),
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
            api_key: API_KEY.clone(),
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
            api_key: API_KEY.clone(),
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
            api_key: API_KEY.clone(),
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
            api_key: API_KEY.clone(),
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
            api_key: API_KEY.clone(),
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
            api_key: API_KEY.clone(),
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
            api_key: API_KEY.clone(),
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
