use crate::{filen_settings::FilenSettings, queries, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::*;
use snafu::{Backtrace, ResultExt, Snafu};
use uuid::Uuid;

#[allow(dead_code)]
type Result<T, E = Error> = std::result::Result<T, E>;

pub const FILEN_SYNC_FOLDER_NAME: &str = "Filen Sync";

const USER_BASE_FOLDERS_PATH: &str = "/v1/user/baseFolders";
const USER_DIRS_PATH: &str = "/v1/user/dirs";
const DIR_CONTENT_PATH: &str = "/v1/dir/content";
const DIR_CREATE_PATH: &str = "/v1/dir/create";
const DIR_EXISTS_PATH: &str = "/v1/dir/exists";
const DIR_MOVE_PATH: &str = "/v1/dir/move";
const DIR_RENAME_PATH: &str = "/v1/dir/rename";
const DIR_TRASH_PATH: &str = "/v1/dir/trash";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Caller provided invalid argument: {}", message))]
    BadArgument { message: String, backtrace: Backtrace },

    #[snafu(display("{} query failed: {}", USER_BASE_FOLDERS_PATH, source))]
    UserBaseFoldersQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_DIRS_PATH, source))]
    UserDirsQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", DIR_CONTENT_PATH, source))]
    DirContentQueryFailed {
        payload: DirContentRequestPayload,
        source: queries::Error,
    },

    #[snafu(display("{} query failed: {}", DIR_CREATE_PATH, source))]
    DirCreateQueryFailed {
        payload: DirCreateRequestPayload,
        source: queries::Error,
    },

    #[snafu(display("{} query failed: {}", DIR_EXISTS_PATH, source))]
    DirExistsQueryFailed {
        payload: LocationExistsRequestPayload,
        source: queries::Error,
    },

    #[snafu(display("{} query failed: {}", DIR_MOVE_PATH, source))]
    DirMoveQueryFailed {
        payload: DirMoveRequestPayload,
        source: queries::Error,
    },

    #[snafu(display("{} query failed: {}", DIR_RENAME_PATH, source))]
    DirRenameQueryFailed {
        payload: DirRenameRequestPayload,
        source: queries::Error,
    },

    #[snafu(display("{} query failed: {}", DIR_TRASH_PATH, source))]
    DirTrashQueryFailed {
        payload: LocationTrashRequestPayload,
        source: queries::Error,
    },
}

// Used for requests to [USER_BASE_FOLDERS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserBaseFoldersRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// This field seems not to do anything, but Filen web manager sets it to "true".
    #[serde(
        rename = "includeDefault",
        deserialize_with = "bool_from_string",
        serialize_with = "bool_to_string"
    )]
    pub include_default: bool,
}
utils::display_from_json!(UserBaseFoldersRequestPayload);

/// One of the folders in response data for [USER_BASE_FOLDERS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserBaseFolder {
    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Metadata containing JSON with folder name: { "name": <name value> }
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Folder color name; None means default yellow color.
    pub color: Option<LocationColor>,

    /// Folder creation time, as Unix timestamp in seconds.
    pub timestamp: u64,

    /// true if user has marked folder as favorite; false otherwise.
    #[serde(deserialize_with = "bool_from_int", serialize_with = "bool_to_int")]
    pub favorited: bool,

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
utils::display_from_json!(UserBaseFolder);

impl HasLocationName for UserBaseFolder {
    /// Decrypts name metadata into a folder name.
    fn name_metadata_ref(&self) -> &str {
        &self.name_metadata
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserBaseFoldersResponseData {
    pub folders: Vec<UserBaseFolder>,
}

api_response_struct!(
    /// Response for [USER_BASE_FOLDERS_PATH] endpoint.
    UserBaseFoldersResponsePayload<Option<UserBaseFoldersResponseData>>
);

// Used for requests to [USER_DIRS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserDirsRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,
}
utils::display_from_json!(UserDirsRequestPayload);

/// One of the folders in response data for [USER_DIRS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserDirData {
    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Metadata containing JSON with folder name: { "name": <name value> }
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Parent folder; None means this folder is a base folder, also known as 'cloud drive'.
    pub parent: Option<Uuid>,

    /// True if this is a default Filen folder; false otherwise.
    pub default: bool,

    /// True if this is a Filen sync folder; false otherwise.
    ///
    /// Filen sync folder is a special unique folder that is created by Filen client to store all synced files.
    /// If user never used Filen client, no sync folder would exist.
    ///
    /// Filen sync folder is always named "Filen Sync" and created with a special type: "sync".
    pub sync: bool,

    /// Seems like `default` field double, only with numeric type.
    pub is_default: u32,

    /// Seems like `sync` field double, only with numeric type.
    pub is_sync: u32,

    /// Folder color name; None means default yellow color.
    pub color: Option<LocationColor>,
}
utils::display_from_json!(UserDirData);

impl HasLocationName for UserDirData {
    /// Decrypts name metadata into a folder name.
    fn name_metadata_ref(&self) -> &str {
        &self.name_metadata
    }
}

api_response_struct!(
    /// Response for [USER_DIRS_PATH] endpoint.
    UserDirsResponsePayload<Vec<UserDirData>>
);

impl UserDirsResponsePayload {
    pub fn find_default_folder(&self) -> Option<UserDirData> {
        self.data.iter().find(|dir_data| dir_data.default).cloned()
    }
}

// Used for requests to [DIR_CONTENT_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirContentRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// A string containing 'path' to the listed folder as JSON array:
    /// "[\"grand_parent_uuid\", \"parent_uuid\", \"folder_uuid\"]"
    /// If folder has no parents, only 'folder_uuid' needs to be present.
    pub folders: String,

    /// Seems like pagination parameter; currently is always 1.
    pub page: i32,

    // TODO: There is no way to tell its purpose from sources, need to ask Dwynr later.
    /// This flag is always set to true.
    #[serde(deserialize_with = "bool_from_string", serialize_with = "bool_to_string")]
    pub app: bool,
}
utils::display_from_json!(DirContentRequestPayload);

/// One of the files in response data for [DIR_CONTENT_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirContentFile {
    /// File ID, UUID V4 in hyphenated lowercase format.
    pub uuid: Uuid,

    /// File metadata.
    pub metadata: String,

    /// Random alphanumeric string associated with the file.
    pub rm: String,

    /// Amount of chunks file is split into.
    pub chunks: u32,

    /// Server's bucket where file is stored.
    pub bucket: String,

    /// Server region.
    pub region: String,

    /// 1 if expire was set when uploading file; 0 otherwise.
    #[serde(
        rename = "expireSet",
        deserialize_with = "bool_from_int",
        serialize_with = "bool_to_int"
    )]
    pub expire_set: bool,

    /// Timestamp when file will be considired expired.
    #[serde(rename = "expireTimestamp")]
    pub expire_timestamp: u64,

    /// Timestamp when file will be deleted.
    #[serde(rename = "deleteTimestamp")]
    pub delete_timestamp: u64,

    /// File creation time, as Unix timestamp in seconds.
    pub timestamp: u64,

    /// ID of the folder which contains this file.
    pub parent: Uuid,

    /// Determines how file bytes should be encrypted/decrypted.
    /// File is encrypted using roughly the same algorithm as metadata encryption,
    /// use [crypto::encrypt_file_data] and [crypto::decrypt_file_data] for the task.
    pub version: u32,

    /// True if user has marked file as favorite; false otherwise.
    #[serde(deserialize_with = "bool_from_int", serialize_with = "bool_to_int")]
    pub favorited: bool,
}
utils::display_from_json!(DirContentFile);

/// One of the non-base folders in response data for [DIR_CONTENT_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirContentFolder {
    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Metadata containing JSON with folder name: { "name": <name value> }
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Parent folder; always present, since base folders are returned in separate `folders_info` array.
    pub parent: Uuid,

    /// Folder color name; None means default yellow color.
    pub color: Option<LocationColor>,

    /// Folder creation time, as Unix timestamp in seconds.
    pub timestamp: u64,

    /// True if user has marked folder as favorite; false otherwise.
    #[serde(deserialize_with = "bool_from_int", serialize_with = "bool_to_int")]
    pub favorited: bool,

    /// True if this is a default Filen folder; false otherwise.
    #[serde(deserialize_with = "bool_from_int", serialize_with = "bool_to_int")]
    pub is_default: bool,

    /// True if this is a Filen sync folder; false otherwise.
    ///
    /// Filen sync folder is a special unique folder that is created by Filen client to store all synced files.
    /// If user never used Filen client, no sync folder would exist.
    ///
    /// Filen sync folder is always named "Filen Sync" and created with a special type: "sync".
    #[serde(deserialize_with = "bool_from_int", serialize_with = "bool_to_int")]
    pub is_sync: bool,
}
utils::display_from_json!(DirContentFolder);

/// One of the base folders in response data for [DIR_CONTENT_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirContentFolderInfo {
    /// Base folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Metadata containing JSON with folder name: { "name": <name value> }
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Folder color name; None means default yellow color.
    pub color: Option<LocationColor>,
}
utils::display_from_json!(DirContentFolderInfo);

/// Response data for [USER_DIRS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirContentResponseData {
    pub uploads: Vec<DirContentFile>,

    pub folders: Vec<DirContentFolder>,

    /// Info for folders passed in [DirContentRequestPayload::folders].
    #[serde(rename = "foldersInfo")]
    pub folders_info: Vec<DirContentFolder>,

    /// Number of files in the current folder.
    #[serde(rename = "totalUploads")]
    pub total_uploads: u64,

    /// Seems like pagination parameter; currently is always 0.
    #[serde(rename = "startAt")]
    pub start_at: u32,

    /// Seems like pagination parameter; currently is always 999999999.
    #[serde(rename = "perPage")]
    pub per_page: u32,

    /// Seems like pagination parameter; currently is always 1.
    pub page: u32,
}
utils::display_from_json!(DirContentResponseData);

api_response_struct!(
    /// Response for [USER_DIRS_PATH] endpoint.
    DirContentResponsePayload<Option<DirContentResponseData>>
);

// Used for requests to [DIR_CREATE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirCreateRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Metadata containing JSON with format: { "name": <name value> }
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Currently hash_fn of lowercased folder name.
    #[serde(rename = "nameHashed")]
    pub name_hashed: String,

    /// Should always be "folder", with "sync" reserved for Filen client sync folder.
    #[serde(rename = "type")]
    pub dir_type: LocationType,
}
utils::display_from_json!(DirCreateRequestPayload);

impl DirCreateRequestPayload {
    /// Payload used for creation of the special Filen sync folder that is created by Filen client
    /// to store all synced files.
    /// You should only use this if you are writing your own replacement client.
    pub fn payload_for_sync_folder_creation(api_key: SecUtf8, last_master_key: &SecUtf8) -> DirCreateRequestPayload {
        let mut payload = DirCreateRequestPayload::new(api_key, FILEN_SYNC_FOLDER_NAME, last_master_key);
        payload.dir_type = LocationType::Sync;
        payload
    }

    /// Payload to create a new folder with the specified name.
    pub fn new(api_key: SecUtf8, name: &str, last_master_key: &SecUtf8) -> DirCreateRequestPayload {
        let name_metadata = LocationNameMetadata::encrypt_name_to_metadata(name, last_master_key);
        let name_hashed = LocationNameMetadata::name_hashed(name);
        DirCreateRequestPayload {
            api_key,
            uuid: Uuid::new_v4(),
            name_metadata,
            name_hashed,
            dir_type: LocationType::Folder,
        }
    }
}

// Used for requests to [DIR_MOVE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirMoveRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the parent folder where target folder will be moved; hyphenated lowercased UUID V4.
    #[serde(rename = "folderUUID")]
    pub folder_uuid: Uuid,

    /// ID of the folder to move, hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(DirMoveRequestPayload);

// Used for requests to [DIR_RENAME_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirRenameRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the folder to rename, hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Metadata with a new name.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Currently hash_fn of a lowercased new name.
    #[serde(rename = "nameHashed")]
    pub name_hashed: String,
}
utils::display_from_json!(DirRenameRequestPayload);

impl DirRenameRequestPayload {
    pub fn new(
        api_key: SecUtf8,
        folder_uuid: Uuid,
        new_folder_name: &str,
        last_master_key: &SecUtf8,
    ) -> DirRenameRequestPayload {
        let name_metadata = LocationNameMetadata::encrypt_name_to_metadata(new_folder_name, last_master_key);
        let name_hashed = LocationNameMetadata::name_hashed(new_folder_name);
        DirRenameRequestPayload {
            api_key,
            uuid: folder_uuid,
            name_metadata,
            name_hashed,
        }
    }
}

/// Calls [USER_BASE_FOLDERS_PATH] endpoint. Used to get a list of user's *base* folders, also known as 'cloud drives'.
/// Note the difference from [user_dirs_request], which returns a set of all user folders, cloud drives or not.
/// Includes Filen "Default" folder.
pub fn user_base_folders_request(
    payload: &UserBaseFoldersRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserBaseFoldersResponsePayload> {
    queries::query_filen_api(USER_BASE_FOLDERS_PATH, payload, filen_settings).context(UserBaseFoldersQueryFailed {})
}

/// Calls [USER_BASE_FOLDERS_PATH] endpoint asynchronously.
/// Used to get a list of user's *base* folders, also known as 'cloud drives'.
/// Note the difference from [user_dirs_request], which returns a set of all user folders, cloud drives or not.
/// Includes Filen "Default" folder.
#[cfg(feature = "async")]
pub async fn user_base_folders_request_async(
    payload: &UserBaseFoldersRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserBaseFoldersResponsePayload> {
    queries::query_filen_api_async(USER_BASE_FOLDERS_PATH, payload, filen_settings)
        .await
        .context(UserBaseFoldersQueryFailed {})
}

/// Calls [USER_DIRS_PATH] endpoint. Used to get a list of user's folders.
/// Always includes Filen "Default" folder, and may possibly include special "Filen Sync" folder,
/// created by Filen's client.
pub fn user_dirs_request(
    payload: &UserDirsRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserDirsResponsePayload> {
    queries::query_filen_api(USER_DIRS_PATH, payload, filen_settings).context(UserDirsQueryFailed {})
}

/// Calls [USER_DIRS_PATH] endpoint asynchronously. Used to get a list of user's folders.
/// Always includes Filen "Default" folder, and may possibly include special "Filen Sync" folder,
/// created by Filen's client.
#[cfg(feature = "async")]
pub async fn user_dirs_request_async(
    payload: &UserDirsRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserDirsResponsePayload> {
    queries::query_filen_api_async(USER_DIRS_PATH, payload, filen_settings)
        .await
        .context(UserDirsQueryFailed {})
}

/// Calls [DIR_CONTENT_PATH] endpoint. Used to get a paginated set of user's files and folders in a way
/// suited for presentation.
pub fn dir_content_request(
    payload: &DirContentRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DirContentResponsePayload> {
    queries::query_filen_api(DIR_CONTENT_PATH, payload, filen_settings).context(DirContentQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [DIR_CONTENT_PATH] endpoint asynchronously. Used to get a paginated set of user's files and folders in a way
/// suited for presentation.
#[cfg(feature = "async")]
pub async fn dir_content_request_async(
    payload: &DirContentRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DirContentResponsePayload> {
    queries::query_filen_api_async(DIR_CONTENT_PATH, payload, filen_settings)
        .await
        .context(DirContentQueryFailed {
            payload: payload.clone(),
        })
}

/// Calls [DIR_CREATE_PATH] endpoint. Creates parentless folder that you need to move yourself later.
pub fn dir_create_request(
    payload: &DirCreateRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(DIR_CREATE_PATH, payload, filen_settings).context(DirCreateQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [DIR_CREATE_PATH] endpoint asynchronously. Creates parentless folder that you need to move yourself later.
#[cfg(feature = "async")]
pub async fn dir_create_request_async(
    payload: &DirCreateRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(DIR_CREATE_PATH, payload, filen_settings)
        .await
        .context(DirCreateQueryFailed {
            payload: payload.clone(),
        })
}

/// Calls [DIR_EXISTS_PATH] endpoint.
/// Checks if folder with the given name exists within the specified parent folder.
pub fn dir_exists_request(
    payload: &LocationExistsRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LocationExistsResponsePayload> {
    queries::query_filen_api(DIR_EXISTS_PATH, payload, filen_settings).context(DirExistsQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [DIR_EXISTS_PATH] endpoint asynchronously.
/// Checks if folder with the given name exists within the specified parent folder.
#[cfg(feature = "async")]
pub async fn dir_exists_request_async(
    payload: &LocationExistsRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LocationExistsResponsePayload> {
    queries::query_filen_api_async(DIR_EXISTS_PATH, payload, filen_settings)
        .await
        .context(DirExistsQueryFailed {
            payload: payload.clone(),
        })
}

/// Calls [DIR_MOVE_PATH] endpoint.
/// Moves folder with the given uuid to the specified parent folder. It is a good idea to check first if folder
/// with the same name already exists within the parent folder.
///
/// If folder is moved into a linked and/or shared folder, don't forget to call [dir_link_add_request]
/// and/or [share_request] after a successfull move.
pub fn dir_move_request(payload: &DirMoveRequestPayload, filen_settings: &FilenSettings) -> Result<PlainApiResponse> {
    queries::query_filen_api(DIR_MOVE_PATH, payload, filen_settings).context(DirMoveQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [DIR_MOVE_PATH] endpoint asynchronously.
/// Moves folder with the given uuid to the specified parent folder. It is a good idea to check first if folder
/// with the same name already exists within the parent folder.
///
/// If folder is moved into a linked and/or shared folder, don't forget to call [dir_link_add_request]
/// and/or [share_request] after a successfull move.
#[cfg(feature = "async")]
pub async fn dir_move_request_async(
    payload: &DirMoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(DIR_MOVE_PATH, payload, filen_settings)
        .await
        .context(DirMoveQueryFailed {
            payload: payload.clone(),
        })
}

/// Calls [DIR_RENAME_PATH] endpoint.
/// Changes name of the folder with given UUID to the specified name. It is a good idea to check first if folder
/// with the new name already exists within the parent folder.
pub fn dir_rename_request(
    payload: &DirRenameRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(DIR_RENAME_PATH, payload, filen_settings).context(DirRenameQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [DIR_RENAME_PATH] endpoint asynchronously.
/// Changes name of the folder with given UUID to the specified name. It is a good idea to check first if folder
/// with the new name already exists within the parent folder.
#[cfg(feature = "async")]
pub async fn dir_rename_request_async(
    payload: &DirRenameRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(DIR_RENAME_PATH, payload, filen_settings)
        .await
        .context(DirRenameQueryFailed {
            payload: payload.clone(),
        })
}

/// Calls [DIR_TRASH_PATH] endpoint.
/// Moves folder with given UUID to trash. Note that folder's UUID will still be considired existing,
/// so you cannot create a new folder with it.
pub fn dir_trash_request(
    payload: &LocationTrashRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(DIR_TRASH_PATH, payload, filen_settings).context(DirTrashQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [DIR_TRASH_PATH] endpoint asynchronously.
/// Moves folder with given UUID to trash. Note that folder's UUID will still be considired existing,
/// so you cannot create a new folder with it.
#[cfg(feature = "async")]
pub async fn dir_trash_request_async(
    payload: &LocationTrashRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(DIR_TRASH_PATH, payload, filen_settings)
        .await
        .context(DirTrashQueryFailed {
            payload: payload.clone(),
        })
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::*;
    use crate::test_utils::*;
    use once_cell::sync::Lazy;
    use pretty_assertions::assert_eq;
    use secstr::SecUtf8;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"));
    const NAME: &str = "test_folder";
    const NAME_METADATA: &str = "U2FsdGVkX19d09wR+Ti+qMO7o8habxXkS501US7uv96+zbHHZwDDPbnq1di1z0/S";
    const NAME_HASHED: &str = "19d24c63b1170a0b1b40520a636a25235735f39f";

    #[test]
    fn dir_create_request_payload_should_be_created_correctly_from_name() {
        let m_key = SecUtf8::from("b49cadfb92e1d7d54e9dd9d33ba9feb2af1f10ae");
        let payload = DirCreateRequestPayload::new(API_KEY.clone(), NAME, &m_key);

        let decrypted_name = LocationNameMetadata::decrypt_name_from_metadata(&payload.name_metadata, &m_key).unwrap();

        assert_eq!(payload.api_key, *API_KEY);
        assert_eq!(decrypted_name, NAME);
        assert_eq!(payload.name_hashed, NAME_HASHED);
        assert_eq!(payload.dir_type, LocationType::Folder);
    }

    #[test]
    fn user_dirs_request_should_have_proper_contract() {
        let request_payload = UserDirsRequestPayload {
            api_key: API_KEY.clone(),
        };
        validate_contract(
            USER_DIRS_PATH,
            request_payload,
            "tests/resources/responses/user_dirs_default.json",
            |request_payload, filen_settings| user_dirs_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn user_dirs_request_async_should_have_proper_contract() {
        let request_payload = UserDirsRequestPayload {
            api_key: API_KEY.clone(),
        };
        validate_contract_async(
            USER_DIRS_PATH,
            request_payload,
            "tests/resources/responses/user_dirs_default.json",
            |request_payload, filen_settings| async move {
                user_dirs_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn dir_create_request_should_have_proper_contract() {
        let request_payload = DirCreateRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::parse_str("80f678c0-56ce-4b81-b4ef-f2a9c0c737c4").unwrap(),
            name_metadata: NAME_METADATA.to_owned(),
            name_hashed: NAME_HASHED.to_owned(),
            dir_type: LocationType::Folder,
        };
        validate_contract(
            DIR_CREATE_PATH,
            request_payload,
            "tests/resources/responses/dir_create.json",
            |request_payload, filen_settings| dir_create_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn dir_create_request_async_should_have_proper_contract() {
        let request_payload = DirCreateRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::parse_str("80f678c0-56ce-4b81-b4ef-f2a9c0c737c4").unwrap(),
            name_metadata: NAME_METADATA.to_owned(),
            name_hashed: NAME_HASHED.to_owned(),
            dir_type: LocationType::Folder,
        };
        validate_contract_async(
            DIR_CREATE_PATH,
            request_payload,
            "tests/resources/responses/dir_create.json",
            |request_payload, filen_settings| async move {
                dir_create_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn dir_exists_request_should_have_proper_contract() {
        let request_payload = LocationExistsRequestPayload {
            api_key: API_KEY.clone(),
            parent: ParentId::try_from("80f678c0-56ce-4b81-b4ef-f2a9c0c737c4").unwrap(),
            name_hashed: NAME_HASHED.to_owned(),
        };
        validate_contract(
            DIR_EXISTS_PATH,
            request_payload,
            "tests/resources/responses/dir_exists.json",
            |request_payload, filen_settings| dir_exists_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn dir_exists_request_async_should_have_proper_contract() {
        let request_payload = LocationExistsRequestPayload {
            api_key: API_KEY.clone(),
            parent: ParentId::try_from("80f678c0-56ce-4b81-b4ef-f2a9c0c737c4").unwrap(),
            name_hashed: NAME_HASHED.to_owned(),
        };
        validate_contract_async(
            DIR_EXISTS_PATH,
            request_payload,
            "tests/resources/responses/dir_exists.json",
            |request_payload, filen_settings| async move {
                dir_exists_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn dir_move_request_should_have_proper_contract() {
        let request_payload = DirMoveRequestPayload {
            api_key: API_KEY.clone(),
            folder_uuid: Uuid::parse_str("80f678c0-56ce-4b81-b4ef-f2a9c0c737c4").unwrap(),
            uuid: Uuid::parse_str("80f678c0-56ce-4b81-b4ef-f2a9c0c737c4").unwrap(),
        };
        validate_contract(
            DIR_MOVE_PATH,
            request_payload,
            "tests/resources/responses/dir_move.json",
            |request_payload, filen_settings| dir_move_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn dir_move_request_async_should_have_proper_contract() {
        let request_payload = DirMoveRequestPayload {
            api_key: API_KEY.clone(),
            folder_uuid: Uuid::parse_str("80f678c0-56ce-4b81-b4ef-f2a9c0c737c4").unwrap(),
            uuid: Uuid::parse_str("80f678c0-56ce-4b81-b4ef-f2a9c0c737c4").unwrap(),
        };
        validate_contract_async(
            DIR_MOVE_PATH,
            request_payload,
            "tests/resources/responses/dir_move.json",
            |request_payload, filen_settings| async move { dir_move_request_async(&request_payload, &filen_settings).await },
        ).await;
    }

    #[test]
    fn dir_rename_request_should_have_proper_contract() {
        let request_payload = DirRenameRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::parse_str("80f678c0-56ce-4b81-b4ef-f2a9c0c737c4").unwrap(),
            name_metadata: NAME_METADATA.to_owned(),
            name_hashed: NAME_HASHED.to_owned(),
        };
        validate_contract(
            DIR_RENAME_PATH,
            request_payload,
            "tests/resources/responses/dir_rename.json",
            |request_payload, filen_settings| dir_rename_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn dir_rename_request_async_should_have_proper_contract() {
        let request_payload = DirRenameRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::parse_str("80f678c0-56ce-4b81-b4ef-f2a9c0c737c4").unwrap(),
            name_metadata: NAME_METADATA.to_owned(),
            name_hashed: NAME_HASHED.to_owned(),
        };
        validate_contract_async(
            DIR_RENAME_PATH,
            request_payload,
            "tests/resources/responses/dir_rename.json",
            |request_payload, filen_settings| async move {
                dir_rename_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }
}
