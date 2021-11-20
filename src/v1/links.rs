#[cfg(feature = "async")]
use crate::v1::{dir_link_add_request_async, download_dir_request_async, link_edit_request_async};
use crate::{
    queries, secstr, utils, uuid, v1,
    v1::{
        crypto, dir_link_add_request, dir_links, download_dir, download_dir_request, file_links, link_edit_request,
        response_payload, Backtrace, DirLinkAddRequestPayload, DownloadBtnState, DownloadDirRequestPayload, Expire,
        FileProperties, FilenResponse, HasFileMetadata, HasLinkKey, HasLocationName, HasUuid, LinkEditRequestPayload,
        LocationNameMetadata, ParentOrBase, PlainResponsePayload, METADATA_VERSION,
    },
    FilenSettings, SettingsBundle,
};

use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

const LINK_DIR_ITEM_RENAME_PATH: &str = "/v1/link/dir/item/rename";
const LINK_DIR_ITEM_STATUS_PATH: &str = "/v1/link/dir/item/status";
const LINK_DIR_STATUS_PATH: &str = "/v1/link/dir/status";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Caller provided invalid argument: {}", message))]
    BadArgument { message: String, backtrace: Backtrace },

    #[snafu(display("{}", message))]
    CannotDisableFileLink { message: String, backtrace: Backtrace },

    #[snafu(display("{}", message))]
    CannotEnableFileLink { message: String, backtrace: Backtrace },

    #[snafu(display("{}", message))]
    CannotEnableFolderLink { message: String, backtrace: Backtrace },

    #[snafu(display("{}", source))]
    CannotGetUserFolderContents { source: v1::Error },

    #[snafu(display("{}", source))]
    DirLinkAddRequestPayloadCreationFailed { source: dir_links::Error },

    #[snafu(display("{}", source))]
    DirLinkAddQueryFailed { source: dir_links::Error },

    #[snafu(display("download_dir_request() failed: {}", source))]
    DownloadDirRequestFailed { source: download_dir::Error },

    #[snafu(display("{} query failed: {}", LINK_DIR_ITEM_RENAME_PATH, source))]
    LinkDirItemRenameQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", LINK_DIR_ITEM_STATUS_PATH, source))]
    LinkDirItemStatusQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", LINK_DIR_STATUS_PATH, source))]
    LinkDirStatusQueryFailed { source: queries::Error },

    #[snafu(display("{}", source))]
    LinkEditQueryFailed { source: file_links::Error },
}

/// Used for requests to `LINK_DIR_ITEM_RENAME_PATH` endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkDirItemRenameRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Folder or file ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Link ID; hyphenated lowercased UUID V4.
    #[serde(rename = "linkUUID")]
    pub link_uuid: Uuid,

    /// Folder or file properties, encrypted with link key.
    pub metadata: String,
}
utils::display_from_json!(LinkDirItemRenameRequestPayload);

impl LinkDirItemRenameRequestPayload {
    #[must_use]
    pub fn from_file_properties(
        api_key: SecUtf8,
        link_uuid: Uuid,
        file_uuid: Uuid,
        file_properties: &FileProperties,
        link_key: &SecUtf8,
    ) -> Self {
        let metadata = file_properties.to_metadata_string(link_key);
        Self {
            api_key,
            metadata,
            link_uuid,
            uuid: file_uuid,
        }
    }

    #[must_use]
    pub fn from_folder_name(
        api_key: SecUtf8,
        link_uuid: Uuid,
        folder_uuid: Uuid,
        folder_name: &str,
        link_key: &SecUtf8,
    ) -> Self {
        let metadata = LocationNameMetadata::encrypt_name_to_metadata(folder_name, link_key);
        Self {
            api_key,
            metadata,
            link_uuid,
            uuid: folder_uuid,
        }
    }
}

/// Used for requests to `LINK_DIR_ITEM_STATUS_PATH` endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkDirItemStatusRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Item ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(LinkDirItemStatusRequestPayload);

/// Response data for `LINK_DIR_ITEM_STATUS_PATH` endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct LinkDirItemStatusResponseData {
    /// True if at least one link for the specified item exists; false otherwise.
    pub link: bool,

    /// Found links. Empty if given item is not linked.
    #[serde(default)]
    pub links: Vec<LinkIdWithKey>,
}
utils::display_from_json!(LinkDirItemStatusResponseData);

response_payload!(
    /// Response for `LINK_DIR_ITEM_STATUS_PATH` endpoint.
    LinkDirItemStatusResponsePayload<LinkDirItemStatusResponseData>
);

/// Used for requests to `LINK_DIR_STATUS_PATH` endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkDirStatusRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(LinkDirStatusRequestPayload);

/// Link UUID with link key.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct LinkIdWithKey {
    /// Link key metadata.
    /// Used to decrypt linked item metadata instead of user's master keys.
    #[serde(rename = "linkKey")]
    pub link_key_metadata: String,

    /// Link ID; hyphenated lowercased UUID V4.
    #[serde(rename = "linkUUID")]
    pub link_uuid: Uuid,
}
utils::display_from_json!(LinkIdWithKey);

impl HasLinkKey for LinkIdWithKey {
    fn link_key_metadata_ref(&self) -> Option<&str> {
        Some(&self.link_key_metadata)
    }
}

impl LinkIdWithKey {
    /// Generates a new link uuid and a link key metadata.
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn generate(last_master_key: &SecUtf8) -> Self {
        let (link_uuid, link_key_plain) = Self::generate_unencrypted();
        // Cannot panic due to the way encrypt_metadata_str is implemented.
        let link_key_metadata =
            crypto::encrypt_metadata_str(link_key_plain.unsecure(), last_master_key, METADATA_VERSION).unwrap();
        Self {
            link_key_metadata,
            link_uuid,
        }
    }

    /// Generates a new link uuid and a link key.
    #[must_use]
    pub fn generate_unencrypted() -> (Uuid, SecUtf8) {
        (Uuid::new_v4(), SecUtf8::from(utils::random_alphanumeric_string(32)))
    }
}

/// Response data for `LINK_DIR_STATUS_PATH` endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct LinkDirStatusResponseData {
    /// True if at least one link for the specified folder exists; false otherwise.
    pub link: bool,

    /// Found links. Empty if given folder is not linked.
    #[serde(default)]
    pub links: Vec<LinkIdWithKey>,
}
utils::display_from_json!(LinkDirStatusResponseData);

response_payload!(
    /// Response for `LINK_DIR_STATUS_PATH` endpoint.
    LinkDirStatusResponsePayload<LinkDirStatusResponseData>
);

/// Calls `LINK_DIR_ITEM_RENAME_PATH` endpoint.
pub fn link_dir_item_rename_request(
    payload: &LinkDirItemRenameRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(LINK_DIR_ITEM_RENAME_PATH, payload, filen_settings)
        .context(LinkDirItemRenameQueryFailed {})
}

/// Calls `LINK_DIR_ITEM_RENAME_PATH` endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn link_dir_item_rename_request_async(
    payload: &LinkDirItemRenameRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(LINK_DIR_ITEM_RENAME_PATH, payload, filen_settings)
        .await
        .context(LinkDirItemRenameQueryFailed {})
}

/// Calls `LINK_DIR_ITEM_STATUS_PATH` endpoint.
pub fn link_dir_item_status_request(
    payload: &LinkDirItemStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LinkDirStatusResponsePayload> {
    queries::query_filen_api(LINK_DIR_ITEM_STATUS_PATH, payload, filen_settings)
        .context(LinkDirItemStatusQueryFailed {})
}

/// Calls `LINK_DIR_ITEM_STATUS_PATH` endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn link_dir_item_status_request_async(
    payload: &LinkDirItemStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LinkDirStatusResponsePayload> {
    queries::query_filen_api_async(LINK_DIR_ITEM_STATUS_PATH, payload, filen_settings)
        .await
        .context(LinkDirItemStatusQueryFailed {})
}

/// Calls `LINK_DIR_STATUS_PATH` endpoint. Used to check if given folder has links and return them, if any.
pub fn link_dir_status_request(
    payload: &LinkDirStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LinkDirStatusResponsePayload> {
    queries::query_filen_api(LINK_DIR_STATUS_PATH, payload, filen_settings).context(LinkDirStatusQueryFailed {})
}

/// Calls `LINK_DIR_STATUS_PATH` endpoint asynchronously.
/// Used to check if given folder has links and return them, if any.
#[cfg(feature = "async")]
pub async fn link_dir_status_request_async(
    payload: &LinkDirStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<LinkDirStatusResponsePayload> {
    queries::query_filen_api_async(LINK_DIR_STATUS_PATH, payload, filen_settings)
        .await
        .context(LinkDirStatusQueryFailed {})
}

/// Helper used to disable link on the given file.
///
/// File links are "global": they are always present and not attached to any linked folder,
/// but can be disabled or enabled. At any given time only one file link can be enabled, so it is not possible
/// to link the same file two times with different expiration, for example.
pub fn disable_file_link(
    api_key: SecUtf8,
    file_uuid: Uuid,
    link_uuid: Uuid,
    filen_settings: &FilenSettings,
) -> Result<String> {
    let link_disable_payload = LinkEditRequestPayload::disabled(api_key, file_uuid, link_uuid);
    let link_disable_response =
        link_edit_request(&link_disable_payload, filen_settings).context(LinkEditQueryFailed {})?;
    let message = link_disable_response.message_ref().unwrap_or_default().to_owned();
    if link_disable_response.status {
        Ok(message)
    } else {
        CannotDisableFileLink { message }.fail()
    }
}

/// Helper used to disable link on the given file asynchronously.
///
/// File links are "global": they are always present and not attached to any linked folder,
/// but can be disabled or enabled. At any given time only one file link can be enabled, so it is not possible
/// to link the same file two times with different expiration, for example.
#[cfg(feature = "async")]
pub async fn disable_file_link_async(
    api_key: SecUtf8,
    file_uuid: Uuid,
    link_uuid: Uuid,
    filen_settings: &FilenSettings,
) -> Result<String> {
    let link_disable_payload = LinkEditRequestPayload::disabled(api_key, file_uuid, link_uuid);
    let link_disable_response = link_edit_request_async(&link_disable_payload, filen_settings)
        .await
        .context(LinkEditQueryFailed {})?;
    let message = link_disable_response.message_ref().unwrap_or_default().to_owned();
    if link_disable_response.status {
        Ok(message)
    } else {
        CannotDisableFileLink { message }.fail()
    }
}

/// Helper used to enable link on the given file.
///
/// File links are "global": they are always present and not attached to any linked folder,
/// but can be disabled or enabled. At any given time only one file link can be enabled, so it is not possible
/// to link the same file two times with different expiration, for example.
pub fn enable_file_link(
    api_key: SecUtf8,
    file_uuid: Uuid,
    download_button_state: DownloadBtnState,
    expiration: Expire,
    link_plain_password: Option<&SecUtf8>,
    filen_settings: &FilenSettings,
) -> Result<Uuid> {
    let link_enable_payload = LinkEditRequestPayload::enabled(
        api_key,
        file_uuid,
        download_button_state,
        expiration,
        None,
        link_plain_password,
    );
    let link_enable_response =
        link_edit_request(&link_enable_payload, filen_settings).context(LinkEditQueryFailed {})?;
    let message = link_enable_response.message_ref().unwrap_or_default().to_owned();
    if link_enable_response.status {
        Ok(link_enable_payload.uuid)
    } else {
        CannotEnableFileLink { message }.fail()
    }
}

/// Helper used to enable link on the given file asynchronously.
///
/// File links are "global": they are always present and not attached to any linked folder,
/// but can be disabled or enabled. At any given time only one file link can be enabled, so it is not possible
/// to link the same file two times with different expiration, for example.
#[cfg(feature = "async")]
pub async fn enable_file_link_async(
    api_key: SecUtf8,
    file_uuid: Uuid,
    download_button_state: DownloadBtnState,
    expiration: Expire,
    link_plain_password: Option<&SecUtf8>,
    filen_settings: &FilenSettings,
) -> Result<Uuid> {
    let link_enable_payload = LinkEditRequestPayload::enabled(
        api_key,
        file_uuid,
        download_button_state,
        expiration,
        None,
        link_plain_password,
    );
    let link_enable_response = link_edit_request_async(&link_enable_payload, filen_settings)
        .await
        .context(LinkEditQueryFailed {})?;
    let message = link_enable_response.message_ref().unwrap_or_default().to_owned();
    if link_enable_response.status {
        Ok(link_enable_payload.uuid)
    } else {
        CannotEnableFileLink { message }.fail()
    }
}

/// Helper which adds given file to existing folder link.
pub fn add_file_to_link<T: HasFileMetadata + HasUuid, S: Into<String>>(
    api_key: SecUtf8,
    file_data: &T,
    parent: ParentOrBase,
    link_uuid: Uuid,
    link_key_metadata: S,
    master_keys: &[SecUtf8],
    filen_settings: &FilenSettings,
) -> Result<String> {
    let dir_link_add_payload =
        DirLinkAddRequestPayload::from_file_data(api_key, file_data, parent, link_uuid, link_key_metadata, master_keys)
            .context(DirLinkAddRequestPayloadCreationFailed {})?;
    let dir_link_add_response =
        dir_link_add_request(&dir_link_add_payload, filen_settings).context(DirLinkAddQueryFailed {})?;
    let message = dir_link_add_response.message_ref().unwrap_or_default().to_owned();
    if dir_link_add_response.status {
        Ok(message)
    } else {
        CannotEnableFileLink { message }.fail()
    }
}

/// Helper which adds given file to existing folder link; asynchronous.
#[cfg(feature = "async")]
pub async fn add_file_to_link_async<T: HasFileMetadata + HasUuid + Sync, S: Into<String> + Send>(
    api_key: SecUtf8,
    file_data: &T,
    parent: ParentOrBase,
    link_uuid: Uuid,
    link_key_metadata: S,
    master_keys: &[SecUtf8],
    filen_settings: &FilenSettings,
) -> Result<String> {
    let dir_link_add_payload =
        DirLinkAddRequestPayload::from_file_data(api_key, file_data, parent, link_uuid, link_key_metadata, master_keys)
            .context(DirLinkAddRequestPayloadCreationFailed {})?;
    let dir_link_add_response = dir_link_add_request_async(&dir_link_add_payload, filen_settings)
        .await
        .context(DirLinkAddQueryFailed {})?;
    let message = dir_link_add_response.message_ref().unwrap_or_default().to_owned();
    if dir_link_add_response.status {
        Ok(message)
    } else {
        CannotEnableFileLink { message }.fail()
    }
}

/// Helper which adds given folder to existing folder link.
pub fn add_folder_to_link<T: HasLocationName + HasUuid, S: Into<String>>(
    api_key: SecUtf8,
    folder_data: &T,
    parent: ParentOrBase,
    link_uuid: Uuid,
    link_key_metadata: S,
    master_keys: &[SecUtf8],
    filen_settings: &FilenSettings,
) -> Result<String> {
    let dir_link_add_payload = DirLinkAddRequestPayload::from_folder_data(
        api_key,
        folder_data,
        parent,
        link_uuid,
        link_key_metadata,
        master_keys,
    )
    .context(DirLinkAddRequestPayloadCreationFailed {})?;
    let dir_link_add_response =
        dir_link_add_request(&dir_link_add_payload, filen_settings).context(DirLinkAddQueryFailed {})?;
    let message = dir_link_add_response.message_ref().unwrap_or_default().to_owned();
    if dir_link_add_response.status {
        Ok(message)
    } else {
        CannotEnableFolderLink { message }.fail()
    }
}

/// Helper which adds given folder to existing folder link; asynchronous.
#[cfg(feature = "async")]
pub async fn add_folder_to_link_async<T: HasLocationName + HasUuid + Sync, S: Into<String> + Send>(
    api_key: SecUtf8,
    folder_data: &T,
    parent: ParentOrBase,
    link_uuid: Uuid,
    link_key_metadata: S,
    master_keys: &[SecUtf8],
    filen_settings: &FilenSettings,
) -> Result<String> {
    let dir_link_add_payload = DirLinkAddRequestPayload::from_folder_data(
        api_key,
        folder_data,
        parent,
        link_uuid,
        link_key_metadata,
        master_keys,
    )
    .context(DirLinkAddRequestPayloadCreationFailed {})?;
    let dir_link_add_response = dir_link_add_request_async(&dir_link_add_payload, filen_settings)
        .await
        .context(DirLinkAddQueryFailed {})?;
    let message = dir_link_add_response.message_ref().unwrap_or_default().to_owned();
    if dir_link_add_response.status {
        Ok(message)
    } else {
        CannotEnableFolderLink { message }.fail()
    }
}

/// Helper which creates a new link to the given folder and adds to this new link all given folder's
/// sub-folders recursively, with files.
///
/// Unlike file links, folder links are not global and multiple links can be created to the same folder.
pub fn link_folder_recursively(
    api_key: &SecUtf8,
    folder_uuid: Uuid,
    master_keys: &[SecUtf8],
    settings: &SettingsBundle,
) -> Result<LinkIdWithKey> {
    let last_master_key = match master_keys.last() {
        Some(key) => key,
        None => BadArgument {
            message: "master keys cannot be empty",
        }
        .fail()?,
    };

    let content_payload = DownloadDirRequestPayload {
        api_key: api_key.clone(),
        uuid: folder_uuid,
    };
    let contents_response = settings
        .retry
        .call(|| download_dir_request(&content_payload, &settings.filen))
        .context(DownloadDirRequestFailed {})?;
    let contents = contents_response
        .data_or_err()
        .context(CannotGetUserFolderContents {})?;

    // TODO: add_(file|folder)_to_link will decrypt link_key_metadata inside,
    // and it is possible to generate unencrypted metadata here with LinkIdWithKey::generate_unencrypted()
    // So implement overloads for add_(file|folder)_to_link for an unencrypted link key?
    let link_id_with_key = LinkIdWithKey::generate(last_master_key);
    let link_metadata = &link_id_with_key.link_key_metadata;

    // Share this folder and all sub-folders:
    contents
        .folders
        .iter()
        .map(|folder| {
            settings.retry.call(|| {
                let parent = if folder.uuid == folder_uuid {
                    ParentOrBase::Base
                } else {
                    folder.parent.clone()
                };
                add_folder_to_link(
                    api_key.clone(),
                    folder,
                    parent,
                    link_id_with_key.link_uuid,
                    link_metadata,
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
                add_file_to_link(
                    api_key.clone(),
                    file,
                    ParentOrBase::Folder(file.parent),
                    link_id_with_key.link_uuid,
                    link_metadata,
                    master_keys,
                    &settings.filen,
                )
                .map(|_| ())
            })
        })
        .collect::<Result<Vec<()>>>()?;

    Ok(link_id_with_key)
}

/// Helper which creates a new link to the given folder and adds to this new link all given folder's
/// sub-folders recursively, with files; asynchronous.
///
/// Unlike file links, folder links are not global and multiple links can be created to the same folder.
#[cfg(feature = "async")]
pub async fn link_folder_recursively_async(
    api_key: &SecUtf8,
    folder_uuid: Uuid,
    master_keys: &[SecUtf8],
    settings: &SettingsBundle,
) -> Result<LinkIdWithKey> {
    let last_master_key = match master_keys.last() {
        Some(key) => key,
        None => BadArgument {
            message: "master keys cannot be empty",
        }
        .fail()?,
    };

    let content_payload = DownloadDirRequestPayload {
        api_key: api_key.clone(),
        uuid: folder_uuid,
    };
    let contents_response = settings
        .retry
        .call_async(|| download_dir_request_async(&content_payload, &settings.filen))
        .await
        .context(DownloadDirRequestFailed {})?;
    let contents = contents_response
        .data_or_err()
        .context(CannotGetUserFolderContents {})?;

    let link_id_with_key = LinkIdWithKey::generate(last_master_key);
    let link_uuid = link_id_with_key.link_uuid;
    let link_metadata = &link_id_with_key.link_key_metadata;

    // Share this folder and all sub-folders:
    let folder_futures = contents.folders.iter().map(|folder| {
        settings.retry.call_async(|| async {
            let parent = if folder.uuid == folder_uuid {
                ParentOrBase::Base
            } else {
                folder.parent.clone()
            };
            add_folder_to_link_async(
                api_key.clone(),
                folder,
                parent,
                link_uuid,
                link_metadata,
                master_keys,
                &settings.filen,
            )
            .await
            .map(|_| ())
        })
    });
    futures::future::try_join_all(folder_futures).await?;

    // Link all files.
    let file_futures = contents.files.iter().map(|file| {
        settings.retry.call_async(|| async {
            add_file_to_link_async(
                api_key.clone(),
                file,
                ParentOrBase::Folder(file.parent),
                link_uuid,
                link_metadata,
                master_keys,
                &settings.filen,
            )
            .await
            .map(|_| ())
        })
    });
    futures::future::try_join_all(file_futures).await?;

    Ok(link_id_with_key)
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
    fn link_dir_status_request_should_have_proper_contract_for_no_link() {
        let request_payload = LinkDirStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract(
            LINK_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/link_dir_status_no_link.json",
            |request_payload, filen_settings| link_dir_status_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn link_dir_status_request_async_should_have_proper_contract_for_no_link() {
        let request_payload = LinkDirStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract_async(
            LINK_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/link_dir_status_no_link.json",
            |request_payload, filen_settings| async move {
                link_dir_status_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn link_dir_status_request_should_have_proper_contract_for_a_link() {
        let request_payload = LinkDirStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract(
            LINK_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/link_dir_status.json",
            |request_payload, filen_settings| link_dir_status_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn link_dir_status_request_async_should_have_proper_contract_for_a_link() {
        let request_payload = LinkDirStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract_async(
            LINK_DIR_STATUS_PATH,
            request_payload,
            "tests/resources/responses/link_dir_status.json",
            |request_payload, filen_settings| async move {
                link_dir_status_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }
}
