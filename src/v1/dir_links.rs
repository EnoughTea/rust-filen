use crate::{
    crypto, queries, utils,
    v1::{
        files, fs, response_payload, Expire, FileProperties, HasFileMetadata, HasLinkKey, HasLocationName, HasUuid,
        ItemKind, Lazy, LocationNameMetadata, ParentOrBase, PasswordState, PlainResponsePayload,
    },
    FilenSettings,
};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use serde_with::skip_serializing_none;
use snafu::{ResultExt, Snafu};
use strum::{Display, EnumString};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

pub static LINK_EMPTY_PASSWORD_VALUE: Lazy<String> = Lazy::new(|| PasswordState::Empty.to_string());
pub static LINK_EMPTY_PASSWORD_HASH: Lazy<String> = Lazy::new(|| crypto::hash_fn(LINK_EMPTY_PASSWORD_VALUE.clone()));
pub static SEC_LINK_EMPTY_PASSWORD_VALUE: Lazy<SecUtf8> =
    Lazy::new(|| SecUtf8::from(LINK_EMPTY_PASSWORD_VALUE.as_str()));

const DIR_LINK_ADD_PATH: &str = "/v1/dir/link/add";
const DIR_LINK_EDIT_PATH: &str = "/v1/dir/link/edit";
const DIR_LINK_REMOVE_PATH: &str = "/v1/dir/link/remove";
const DIR_LINK_STATUS_PATH: &str = "/v1/dir/link/status";

#[allow(clippy::enum_variant_names)]
#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to decrypt link key metadata '{}': {}", metadata, source))]
    DecryptLinkKeyMetadataFailed { metadata: String, source: crypto::Error },

    #[snafu(display("{}", source))]
    DecryptLocationNameFailed { source: fs::Error },

    #[snafu(display("{}", source))]
    DecryptFileMetadataFailed { source: files::Error },

    #[snafu(display("{} query failed: {}", DIR_LINK_ADD_PATH, source))]
    DirLinkAddQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", DIR_LINK_EDIT_PATH, source))]
    DirLinkEditQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", DIR_LINK_REMOVE_PATH, source))]
    DirLinkRemoveQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", DIR_LINK_STATUS_PATH, source))]
    DirLinkStatusQueryFailed { source: queries::Error },
}

/// State of the 'Enable download button' GUI toggle represented as a string.
/// It is the toggle you can see at the bottom of modal popup when creating or sharing an item.
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
pub enum DownloadBtnState {
    /// 'Enable download button' checkbox is disabled.
    Disable,
    /// 'Enable download button' checkbox is enabled.
    Enable,
}

/// State of the 'Enable download button' GUI toggle represented as a 0|1 flag.
/// It is the toggle you can see at the bottom of modal popup when creating or sharing an item.
#[derive(Clone, Debug, Deserialize_repr, Display, EnumString, Eq, Hash, PartialEq, Serialize_repr)]
#[repr(u8)]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
pub enum DownloadBtnStateByte {
    Disable = 0,
    Enable = 1,
}

/// Used for requests to `DIR_LINK_ADD_PATH` endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirLinkAddRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Filen sets this to "enable" by default.
    #[serde(rename = "downloadBtn")]
    pub download_btn: DownloadBtnState,

    /// Link expiration time in text form. Usually has value "never".
    pub expiration: Expire,

    /// Link key, encrypted.
    #[serde(rename = "key")]
    pub key_metadata: String,

    /// Link ID; hyphenated lowercased UUID V4.
    #[serde(rename = "linkUUID")]
    pub link_uuid: Uuid,

    /// Linked item metadata.
    pub metadata: String,

    /// ID of the linked parent of the linked item, hyphenated lowercased UUID V4.
    /// Use "base" if linked item's parent is not linked.
    pub parent: ParentOrBase,

    /// Filen always uses "empty" when adding links.
    pub password: PasswordState,

    /// Output of hash_fn for the link's password.
    #[serde(rename = "passwordHashed")]
    pub password_hashed: String,

    /// Determines whether a file or a folder is being linked.
    #[serde(rename = "type")]
    pub link_type: ItemKind,

    /// Linked item ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(DirLinkAddRequestPayload);

impl DirLinkAddRequestPayload {
    pub fn from_file_data<T: HasFileMetadata + HasUuid, S: Into<String>>(
        api_key: SecUtf8,
        file_data: &T,
        parent: ParentOrBase,
        link_uuid: Uuid,
        link_key_metadata: S,
        master_keys: &[SecUtf8],
    ) -> Result<Self> {
        let file_properties = file_data
            .decrypt_file_metadata(master_keys)
            .context(DecryptFileMetadataFailed {})?;
        Self::from_file_properties(
            api_key,
            *file_data.uuid_ref(),
            &file_properties,
            parent,
            link_uuid,
            link_key_metadata,
            master_keys,
        )
    }

    pub fn from_file_properties<S: Into<String>>(
        api_key: SecUtf8,
        file_uuid: Uuid,
        file_properties: &FileProperties,
        parent: ParentOrBase,
        link_uuid: Uuid,
        link_key_metadata: S,
        master_keys: &[SecUtf8],
    ) -> Result<Self> {
        let key_metadata: String = link_key_metadata.into();
        let link_key = SecUtf8::from(
            crypto::decrypt_metadata_str_any_key(&key_metadata, master_keys).context(DecryptLinkKeyMetadataFailed {
                metadata: key_metadata.clone(),
            })?,
        );
        let metadata = file_properties.to_metadata_string(&link_key);
        Ok(Self {
            api_key,
            download_btn: DownloadBtnState::Enable,
            expiration: Expire::Never,
            key_metadata,
            link_uuid,
            metadata,
            parent,
            password: PasswordState::Empty,
            password_hashed: LINK_EMPTY_PASSWORD_HASH.clone(),
            link_type: ItemKind::File,
            uuid: file_uuid,
        })
    }

    pub fn from_folder_data<T: HasLocationName + HasUuid, S: Into<String>>(
        api_key: SecUtf8,
        folder_data: &T,
        parent: ParentOrBase,
        link_uuid: Uuid,
        link_key_metadata: S,
        master_keys: &[SecUtf8],
    ) -> Result<Self> {
        let folder_name = folder_data
            .decrypt_name_metadata(master_keys)
            .context(DecryptLocationNameFailed {})?;
        Self::from_folder_name(
            api_key,
            *folder_data.uuid_ref(),
            &folder_name,
            parent,
            link_uuid,
            link_key_metadata,
            master_keys,
        )
    }

    pub fn from_folder_name<S: Into<String>>(
        api_key: SecUtf8,
        folder_uuid: Uuid,
        folder_name: &str,
        parent: ParentOrBase,
        link_uuid: Uuid,
        link_key_metadata: S,
        master_keys: &[SecUtf8],
    ) -> Result<Self> {
        let key_metadata: String = link_key_metadata.into();
        let link_key = SecUtf8::from(
            crypto::decrypt_metadata_str_any_key(&key_metadata, master_keys).context(DecryptLinkKeyMetadataFailed {
                metadata: key_metadata.clone(),
            })?,
        );
        let metadata = LocationNameMetadata::encrypt_name_to_metadata(folder_name, &link_key);
        Ok(Self {
            api_key,
            download_btn: DownloadBtnState::Enable,
            expiration: Expire::Never,
            key_metadata,
            link_uuid,
            metadata,
            parent,
            password: PasswordState::Empty,
            password_hashed: LINK_EMPTY_PASSWORD_HASH.clone(),
            link_type: ItemKind::Folder,
            uuid: folder_uuid,
        })
    }
}

/// Used for requests to `DIR_LINK_EDIT_PATH` endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirLinkEditRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Filen sets this to "enable" by default. If user toggled off the 'Enable download button' checkbox,
    /// then this is set to "disable".
    #[serde(rename = "downloadBtn")]
    pub download_btn: DownloadBtnState,

    /// Link expiration time in text form. Usually has value "never".
    pub expiration: Expire,

    /// "empty" means no password protection, "notempty" means password is present.
    pub password: PasswordState,

    /// Hashed link's password, output of [crypto::derive_key_from_password_512] with 32 random bytes of salt;
    /// converted to a hex string.
    #[serde(rename = "passwordHashed")]
    pub password_hashed: String,

    /// Salt used to make hashed password.
    pub salt: String,

    /// Linked item ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(DirLinkEditRequestPayload);

impl DirLinkEditRequestPayload {
    fn new<S: Into<String>>(
        api_key: SecUtf8,
        download_btn: DownloadBtnState,
        item_uuid: Uuid,
        expiration: Expire,
        link_plain_password: Option<&SecUtf8>,
    ) -> Self {
        let (password_hashed, salt) = link_plain_password.map_or_else(
            || crypto::encrypt_to_link_password_and_salt(&SEC_LINK_EMPTY_PASSWORD_VALUE),
            |password| crypto::encrypt_to_link_password_and_salt(password),
        );
        Self {
            api_key,
            download_btn,
            expiration,
            password: link_plain_password.map_or(PasswordState::Empty, |_| PasswordState::NotEmpty),
            password_hashed,
            salt,
            uuid: item_uuid,
        }
    }
}

/// Used for requests to `DIR_LINK_REMOVE_PATH` endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirLinkRemoveRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Linked folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(DirLinkRemoveRequestPayload);

/// Used for requests to `DIR_LINK_STATUS_PATH` endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirLinkStatusRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the item whose link should be checked; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}
utils::display_from_json!(DirLinkStatusRequestPayload);

/// Response data for `DIR_LINK_STATUS_PATH` endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct DirLinkStatusResponseData {
    /// True if link exists; false if link for the given item ID cannot be found.
    pub exists: bool,

    /// Found link ID; hyphenated lowercased UUID V4. None if no link was found.
    pub uuid: Option<Uuid>,

    /// Link key metadata. None if no link was found.
    pub key: Option<String>,

    /// Link expiration time, as Unix timestamp in seconds. None if no link was found.
    pub expiration: Option<u64>,

    /// Link expiration time in text form. None if no link was found.
    #[serde(rename = "expirationText")]
    pub expiration_text: Option<Expire>,

    /// None if no link was found.
    #[serde(rename = "downloadBtn")]
    pub download_btn: Option<DownloadBtnStateByte>,

    /// Link password hash in hex string form, or None if no password was set by user or if no link was found.
    pub password: Option<String>,
}
utils::display_from_json!(DirLinkStatusResponseData);

impl HasLinkKey for DirLinkStatusResponseData {
    fn link_key_metadata_ref(&self) -> Option<&str> {
        self.key.as_deref()
    }
}

response_payload!(
    /// Response for `DIR_LINK_STATUS_PATH` endpoint.
    DirLinkStatusResponsePayload<DirLinkStatusResponseData>
);

/// Calls `DIR_LINK_ADD_PATH` endpoint. Used to add a folder or a file to a folder link.
///
/// Filen always creates a link without password first, and optionally sets password later using `dir_link_edit_request`.
pub fn dir_link_add_request(
    payload: &DirLinkAddRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(DIR_LINK_ADD_PATH, payload, filen_settings).context(DirLinkAddQueryFailed {})
}

/// Calls `DIR_LINK_ADD_PATH` endpoint asynchronously. Used to add a folder or a file to a folder link.
///
/// Filen always creates a link without password first, and optionally sets password later using `dir_link_edit_request`.
#[cfg(feature = "async")]
pub async fn dir_link_add_request_async(
    payload: &DirLinkAddRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(DIR_LINK_ADD_PATH, payload, filen_settings)
        .await
        .context(DirLinkAddQueryFailed {})
}

/// Calls `DIR_LINK_EDIT_PATH` endpoint. Used to edit given folder link.
///
/// Filen always creates a link without password first, and optionally sets password later using this query.
pub fn dir_link_edit_request(
    payload: &DirLinkEditRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(DIR_LINK_EDIT_PATH, payload, filen_settings).context(DirLinkEditQueryFailed {})
}

/// Calls `DIR_LINK_EDIT_PATH` endpoint asynchronously. Used to edit given folder link.
///
/// Filen always creates a link without password first, and optionally sets password later using this query.
#[cfg(feature = "async")]
pub async fn dir_link_edit_request_async(
    payload: &DirLinkEditRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(DIR_LINK_EDIT_PATH, payload, filen_settings)
        .await
        .context(DirLinkEditQueryFailed {})
}

/// Calls `DIR_LINK_REMOVE_PATH` endpoint. Used to remove given folder link.
pub fn dir_link_remove_request(
    payload: &DirLinkRemoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api(DIR_LINK_REMOVE_PATH, payload, filen_settings).context(DirLinkRemoveQueryFailed {})
}

/// Calls `DIR_LINK_REMOVE_PATH` endpoint asynchronously. Used to remove given folder link.
#[cfg(feature = "async")]
pub async fn dir_link_remove_request_async(
    payload: &DirLinkRemoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainResponsePayload> {
    queries::query_filen_api_async(DIR_LINK_REMOVE_PATH, payload, filen_settings)
        .await
        .context(DirLinkRemoveQueryFailed {})
}

/// Calls `DIR_LINK_STATUS_PATH` endpoint. Used to check folder link status.
pub fn dir_link_status_request(
    payload: &DirLinkStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DirLinkStatusResponsePayload> {
    queries::query_filen_api(DIR_LINK_STATUS_PATH, payload, filen_settings).context(DirLinkStatusQueryFailed {})
}

/// Calls `DIR_LINK_STATUS_PATH` endpoint asynchronously. Used to check folder link status.
#[cfg(feature = "async")]
pub async fn dir_link_status_request_async(
    payload: &DirLinkStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DirLinkStatusResponsePayload> {
    queries::query_filen_api_async(DIR_LINK_STATUS_PATH, payload, filen_settings)
        .await
        .context(DirLinkStatusQueryFailed {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{validate_contract, validate_contract_async};
    use once_cell::sync::Lazy;
    use secstr::SecUtf8;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"));

    #[test]
    fn dir_link_status_request_should_have_proper_contract_for_no_link() {
        let request_payload = DirLinkStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract(
            DIR_LINK_STATUS_PATH,
            request_payload,
            "tests/resources/responses/dir_link_status_no_link.json",
            |request_payload, filen_settings| dir_link_status_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn dir_link_status_request_async_should_have_proper_contract_for_no_link() {
        let request_payload = DirLinkStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract_async(
            DIR_LINK_STATUS_PATH,
            request_payload,
            "tests/resources/responses/dir_link_status_no_link.json",
            |request_payload, filen_settings| async move {
                dir_link_status_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn dir_link_status_request_should_have_proper_contract_for_link_without_password() {
        let request_payload = DirLinkStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract(
            DIR_LINK_STATUS_PATH,
            request_payload,
            "tests/resources/responses/dir_link_status_no_password.json",
            |request_payload, filen_settings| dir_link_status_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn dir_link_status_request_async_should_have_proper_contract_for_link_without_password() {
        let request_payload = DirLinkStatusRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract_async(
            DIR_LINK_STATUS_PATH,
            request_payload,
            "tests/resources/responses/dir_link_status_no_password.json",
            |request_payload, filen_settings| async move {
                dir_link_status_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }
}
