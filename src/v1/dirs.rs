use crate::{
    crypto,
    filen_settings::FilenSettings,
    queries, utils,
    v1::fs::*,
    v1::{api_response_struct, PlainApiResponse},
};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::*;
use snafu::{Backtrace, ResultExt, Snafu};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

pub const FILEN_FOLDER_TYPE: &str = "folder";
pub const FILEN_SYNC_FOLDER_NAME: &str = "Filen Sync";

const USER_DIRS_PATH: &str = "/v1/user/dirs";
const DIR_CREATE_PATH: &str = "/v1/dir/create";
const DIR_EXISTS_PATH: &str = "/v1/dir/exists";
const DIR_MOVE_PATH: &str = "/v1/dir/move";
const DIR_RENAME_PATH: &str = "/v1/dir/rename";
const DIR_TRASH_PATH: &str = "/v1/dir/trash";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Caller provided invalid argument: {}", message))]
    BadArgument { message: String, backtrace: Backtrace },

    #[snafu(display("Failed to decrypt name metadata: {}", source))]
    DecryptNameMetadataFailed {
        metadata: String,
        source: crate::v1::fs::Error,
    },

    #[snafu(display("{} query failed: {}", USER_DIRS_PATH, source))]
    UserDirsQueryFailed {
        payload: UserDirsRequestPayload,
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
    pub uuid: String,

    /// Metadata containing folder name.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Parent folder; None means this folder is a root, also known as 'cloud drive'.
    pub parent: Option<String>,

    /// True if this is a default Filen folder; false otherwise.
    pub default: bool,

    /// True if this is a Filen sync folder; false otherwise.
    ///
    /// Filen sync folder is a special unique folder that is created by Filen client to store all synced files.
    /// If user never used Filen client, no sync folder would exist.
    ///
    /// Filen sync folder is always named "Filen Sync" and created with a special type: "sync".
    pub sync: bool,

    /// Seems like [UserDirData::default] field double, only with integer type instead of bool.
    pub is_default: i32,

    /// Seems like [UserDirData::sync] field double, only with integer type instead of bool.
    pub is_sync: i32,

    /// Folder color name; None means default yellow color. Possible colors: "blue", "green", "purple", "red", "gray".
    pub color: Option<String>,
}
utils::display_from_json!(UserDirData);

impl UserDirData {
    /// Decrypt name metadata into actual folder name.
    pub fn decrypt_name_metadata(&self, last_master_key: &SecUtf8) -> Result<String> {
        LocationNameMetadata::decrypt_name_from_metadata(&self.name_metadata, last_master_key).context(
            DecryptNameMetadataFailed {
                metadata: self.name_metadata.clone(),
            },
        )
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

// Used for requests to [DIR_CREATE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirCreateRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: String,

    /// Metadata containing json with format: { "name": <name value> }
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Currently hash_fn of lowercased folder name.
    #[serde(rename = "nameHashed")]
    pub name_hashed: String,

    /// Should always be "folder", with "sync" reserved for Filen client sync folder.
    #[serde(rename = "type")]
    pub dir_type: String,
}
utils::display_from_json!(DirCreateRequestPayload);

impl DirCreateRequestPayload {
    /// Payload used for creation of the special Filen sync folder that is created by Filen client to store all synced files.
    /// You should only use this if you are writing your own replacement client.
    pub fn payload_for_sync_folder_creation(api_key: &SecUtf8, last_master_key: &SecUtf8) -> DirCreateRequestPayload {
        let mut payload = DirCreateRequestPayload::new(FILEN_SYNC_FOLDER_NAME, api_key, last_master_key);
        payload.dir_type = FILEN_SYNC_FOLDER_TYPE.to_owned();
        payload
    }

    /// Payload to create a new folder with the specified name.
    pub fn new(name: &str, api_key: &SecUtf8, last_master_key: &SecUtf8) -> DirCreateRequestPayload {
        let name_metadata = LocationNameMetadata::encrypt_name_to_metadata(name, last_master_key);
        let name_hashed = crypto::hash_fn(&name.to_lowercase());
        DirCreateRequestPayload {
            api_key: api_key.clone(),
            uuid: Uuid::new_v4().to_hyphenated().to_string(),
            name_metadata,
            name_hashed,
            dir_type: FILEN_FOLDER_TYPE.to_owned(),
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
    pub folder_uuid: String,

    /// ID of the folder to move, hyphenated lowercased UUID V4.
    pub uuid: String,
}
utils::display_from_json!(DirMoveRequestPayload);

// Used for requests to [DIR_RENAME_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirRenameRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the folder to rename, hyphenated lowercased UUID V4.
    pub uuid: String,

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
        folder_uuid: String,
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

/// Calls [USER_DIRS_PATH] endpoint. Used to get a list of user's folders.
/// Always includes Filen "Default" folder, and may possibly include special "Filen Sync" folder, created by Filen's client.
pub fn user_dirs_request(
    payload: &UserDirsRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserDirsResponsePayload> {
    queries::query_filen_api(USER_DIRS_PATH, payload, filen_settings).context(UserDirsQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [USER_DIRS_PATH] endpoint asynchronously. Used to get a list of user's folders.
/// Always includes Filen "Default" folder, and may possibly include special "Filen Sync" folder, created by Filen's client.
pub async fn user_dirs_request_async(
    payload: &UserDirsRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserDirsResponsePayload> {
    queries::query_filen_api_async(USER_DIRS_PATH, payload, filen_settings)
        .await
        .context(UserDirsQueryFailed {
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
pub fn dir_move_request(payload: &DirMoveRequestPayload, filen_settings: &FilenSettings) -> Result<PlainApiResponse> {
    queries::query_filen_api(DIR_MOVE_PATH, payload, filen_settings).context(DirMoveQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [DIR_MOVE_PATH] endpoint asynchronously.
/// Moves folder with the given uuid to the specified parent folder. It is a good idea to check first if folder
/// with the same name already exists within the parent folder.
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
    use closure::closure;
    use once_cell::sync::Lazy;
    use secstr::SecUtf8;
    use tokio::task::spawn_blocking;

    use crate::test_utils::*;

    use super::*;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"));
    const NAME: &str = "test_folder";
    const NAME_METADATA: &str = "U2FsdGVkX19d09wR+Ti+qMO7o8habxXkS501US7uv96+zbHHZwDDPbnq1di1z0/S";
    const NAME_HASHED: &str = "19d24c63b1170a0b1b40520a636a25235735f39f";

    #[test]
    fn dir_create_request_payload_should_be_created_correctly_from_name() {
        let m_key = SecUtf8::from("b49cadfb92e1d7d54e9dd9d33ba9feb2af1f10ae");
        let payload = DirCreateRequestPayload::new(NAME, &API_KEY.clone(), &m_key);
        let decrypted_name = LocationNameMetadata::decrypt_name_from_metadata(&payload.name_metadata, &m_key).unwrap();
        let parsed_uuid = Uuid::parse_str(&payload.uuid);

        assert_eq!(payload.api_key, *API_KEY);
        assert!(parsed_uuid.is_ok());
        assert_eq!(decrypted_name, NAME);
        assert_eq!(payload.name_hashed, NAME_HASHED);
        assert_eq!(payload.dir_type, "folder");
    }

    #[tokio::test]
    async fn user_dirs_request_and_async_should_work() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = UserDirsRequestPayload {
            api_key: API_KEY.clone(),
        };
        let expected_response: UserDirsResponsePayload =
            deserialize_from_file("tests/resources/responses/user_dirs_default.json");
        let mock = setup_json_mock(USER_DIRS_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { user_dirs_request(&request_payload, &filen_settings) }),
        ).await.unwrap()?;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = user_dirs_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }

    #[tokio::test]
    async fn dir_create_request_and_async_should_work() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = DirCreateRequestPayload {
            api_key: API_KEY.clone(),
            uuid: "80f678c0-56ce-4b81-b4ef-f2a9c0c737c4".to_owned(),
            name_metadata: NAME_METADATA.to_owned(),
            name_hashed: NAME_HASHED.to_owned(),
            dir_type: "folder".to_owned(),
        };
        let expected_response: PlainApiResponse = deserialize_from_file("tests/resources/responses/dir_create.json");
        let mock = setup_json_mock(DIR_CREATE_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { dir_create_request(&request_payload, &filen_settings) }),
        ).await.unwrap()?;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = dir_create_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }

    #[tokio::test]
    async fn dir_exists_request_and_async_should_work() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = LocationExistsRequestPayload {
            api_key: API_KEY.clone(),
            parent: "80f678c0-56ce-4b81-b4ef-f2a9c0c737c4".to_owned(),
            name_hashed: NAME_HASHED.to_owned(),
        };
        let expected_response: LocationExistsResponsePayload =
            deserialize_from_file("tests/resources/responses/dir_exists.json");
        let mock = setup_json_mock(DIR_EXISTS_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { dir_exists_request(&request_payload, &filen_settings) }),
        ).await.unwrap()?;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = dir_exists_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }

    #[tokio::test]
    async fn dir_move_request_and_async_should_work() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = DirMoveRequestPayload {
            api_key: API_KEY.clone(),
            folder_uuid: "80f678c0-56ce-4b81-b4ef-f2a9c0c737c4".to_owned(),
            uuid: "80f678c0-56ce-4b81-b4ef-f2a9c0c737c4".to_owned(),
        };
        let expected_response: PlainApiResponse = deserialize_from_file("tests/resources/responses/dir_move.json");
        let mock = setup_json_mock(DIR_MOVE_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { dir_move_request(&request_payload, &filen_settings) }),
        ).await.unwrap()?;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = dir_move_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }

    #[tokio::test]
    async fn dir_rename_request_and_async_should_work() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = DirRenameRequestPayload {
            api_key: API_KEY.clone(),
            uuid: "80f678c0-56ce-4b81-b4ef-f2a9c0c737c4".to_owned(),
            name_metadata: NAME_METADATA.to_owned(),
            name_hashed: NAME_HASHED.to_owned(),
        };
        let expected_response: PlainApiResponse = deserialize_from_file("tests/resources/responses/dir_rename.json");
        let mock = setup_json_mock(DIR_RENAME_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { dir_rename_request(&request_payload, &filen_settings) }),
        ).await.unwrap()?;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = dir_rename_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }
}
