use crate::{crypto, filen_settings::*, queries, utils, v1::*};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_repr::*;
use serde_with::*;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

const DIR_LINK_ADD_PATH: &str = "/v1/dir/link/add";
const DIR_LINK_EDIT_PATH: &str = "/v1/dir/link/edit";
const DIR_LINK_REMOVE_PATH: &str = "/v1/dir/link/remove";
const DIR_LINK_STATUS_PATH: &str = "/v1/dir/link/status";

const DEFAULT_EXPIRE: &str = "never";

#[allow(clippy::enum_variant_names)]
#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("{} query failed: {}", DIR_LINK_ADD_PATH, source))]
    DirLinkAddQueryFailed {
        payload: DirLinkAddRequestPayload,
        source: queries::Error,
    },

    #[snafu(display("{} query failed: {}", DIR_LINK_EDIT_PATH, source))]
    DirLinkEditQueryFailed {
        payload: DirLinkEditRequestPayload,
        source: queries::Error,
    },

    #[snafu(display("{} query failed: {}", DIR_LINK_REMOVE_PATH, source))]
    DirLinkRemoveQueryFailed { link_uuid: String, source: queries::Error },

    #[snafu(display("{} query failed: {}", DIR_LINK_STATUS_PATH, source))]
    DirLinkStatusQueryFailed { link_uuid: String, source: queries::Error },
}

/// 'Download' state represented as a string.
/// TODO: Probably controls the availability of "Download" action in Filen web manager?
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DownloadBtnState {
    /// 'Download' is disabled.
    Disable,
    /// 'Download' is enabled.
    Enable,
}

/// 'Download' state represented as a 0|1 flag.
/// TODO: Probably controls the availability of "Download" action in Filen web manager?
#[derive(Clone, Debug, Deserialize_repr, Eq, PartialEq, Serialize_repr)]
#[repr(u8)]
pub enum DownloadBtnStateByte {
    Disable = 0,
    Enable = 1,
}

impl std::fmt::Display for DownloadBtnStateByte {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            DownloadBtnStateByte::Disable => write!(f, "disable"),
            DownloadBtnStateByte::Enable => write!(f, "enable"),
        }
    }
}

/// Used for requests to [DIR_LINK_ADD_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirLinkAddRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Usually has "enable" value for links without passwords, and "disable" for password-protected links.
    #[serde(rename = "downloadBtn")]
    pub download_btn: DownloadBtnState,

    /// Link expiration time in text form. Usually has value "never".
    pub expiration: String,

    /// Link key, encrypted.
    #[serde(rename = "key")]
    pub key_metadata: String,

    /// Link ID; hyphenated lowercased UUID V4.
    #[serde(rename = "linkUUID")]
    pub link_uuid: String,

    /// Linked folder metadata.
    pub metadata: String,

    /// ID of the parent of the linked folder, hyphenated lowercased UUID V4.
    /// Use "base" if the linked folder is located in the root folder.
    pub parent: String,

    /// Filen always uses "empty" when adding links.
    pub password: PasswordState,

    /// Output of hash_fn for the password.
    pub password_hashed: String,

    /// Should be "folder".
    #[serde(rename = "type")]
    pub link_type: LocationType,

    /// Linked folder ID; hyphenated lowercased UUID V4.
    pub uuid: String,
}
utils::display_from_json!(DirLinkAddRequestPayload);

impl DirLinkAddRequestPayload {
    pub fn new<S: Into<String>>(
        api_key: SecUtf8,
        linked_folder_uuid: S,
        linked_folder_metadata: S,
        linked_folder_parent_uuid: Option<S>,
        last_master_key: &SecUtf8,
    ) -> DirLinkAddRequestPayload {
        let link_uuid = Uuid::new_v4().to_hyphenated().to_string();
        let link_key = utils::random_alphanumeric_string(32);
        let key_metadata = // Should never panic...
            crypto::encrypt_metadata_str(&link_key, last_master_key.unsecure(), METADATA_VERSION).unwrap();
        DirLinkAddRequestPayload {
            api_key,
            download_btn: DownloadBtnState::Enable,
            expiration: DEFAULT_EXPIRE.to_owned(),
            key_metadata,
            link_uuid,
            metadata: linked_folder_metadata.into(),
            parent: LocationType::parent_or_base(linked_folder_parent_uuid),
            password: PasswordState::Empty,
            password_hashed: EMPTY_PASSWORD_HASH.clone(),
            link_type: LocationType::Folder,
            uuid: linked_folder_uuid.into(),
        }
    }
}

/// Used for requests to [DIR_LINK_EDIT_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirLinkEditRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Usually has "enable" value for links without passwords, and "disable" for password-protected links.
    #[serde(rename = "downloadBtn")]
    pub download_btn: DownloadBtnState,

    /// Link expiration time in text form. Usually has value "never".
    pub expiration: String,

    /// Link key, encrypted.
    #[serde(rename = "key")]
    pub key_metadata: String,

    /// Link ID; hyphenated lowercased UUID V4.
    #[serde(rename = "linkUUID")]
    pub link_uuid: String,

    /// Folder metadata.
    pub metadata: String,

    /// ID of the parent of the linked folder, hyphenated lowercased UUID V4.
    /// Use "base" if linked folder is located in the root folder.
    pub parent: String,

    /// "empty" means no password protection, "notempty" means password is present.
    pub password: PasswordState,

    /// Output of [crypto::derive_key_from_password_512] for user's plain text password with 32 random bytes of salt,
    /// converted to a hex string.
    pub password_hashed: String,

    /// Should be "folder".
    #[serde(rename = "type")]
    pub target_type: LocationType,

    /// Linked folder ID; hyphenated lowercased UUID V4.
    pub uuid: String,
}
utils::display_from_json!(DirLinkEditRequestPayload);

impl DirLinkEditRequestPayload {
    fn from_no_password<S: Into<String>>(
        api_key: SecUtf8,
        download_btn: DownloadBtnState,
        link_uuid: S,
        link_key_metadata: S,
        linked_folder_uuid: S,
        linked_folder_metadata: S,
        linked_folder_parent_uuid: Option<S>,
    ) -> DirLinkEditRequestPayload {
        DirLinkEditRequestPayload {
            api_key,
            download_btn,
            expiration: DEFAULT_EXPIRE.to_owned(),
            key_metadata: link_key_metadata.into(),
            link_uuid: link_uuid.into(),
            metadata: linked_folder_metadata.into(),
            parent: LocationType::parent_or_base(linked_folder_parent_uuid),
            password: PasswordState::Empty,
            password_hashed: EMPTY_PASSWORD_HASH.clone(),
            target_type: LocationType::Folder,
            uuid: linked_folder_uuid.into(),
        }
    }

    fn from_plain_text_password<S: Into<String>>(
        api_key: SecUtf8,
        download_btn: DownloadBtnState,
        link_uuid: S,
        link_key_metadata: S,
        linked_folder_uuid: S,
        linked_folder_metadata: S,
        linked_folder_parent: Option<S>,
        plain_text_password: &SecUtf8,
    ) -> DirLinkEditRequestPayload {
        let password = PasswordState::NotEmpty;
        let salt = utils::random_alphanumeric_string(32);
        let password_hashed = utils::bytes_to_hex_string(&crypto::derive_key_from_password_512(
            plain_text_password.unsecure().as_bytes(),
            salt.as_bytes(),
            200_000,
        ));

        DirLinkEditRequestPayload {
            api_key,
            download_btn,
            expiration: DEFAULT_EXPIRE.to_owned(),
            key_metadata: link_key_metadata.into(),
            link_uuid: link_uuid.into(),
            metadata: linked_folder_metadata.into(),
            parent: LocationType::parent_or_base(linked_folder_parent),
            password,
            password_hashed,
            target_type: LocationType::Folder,
            uuid: linked_folder_uuid.into(),
        }
    }
}

/// Used for requests to [DIR_LINK_REMOVE_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirLinkRemoveRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Link ID; hyphenated lowercased UUID V4.
    pub uuid: String,
}
utils::display_from_json!(DirLinkRemoveRequestPayload);

/// Used for requests to [DIR_LINK_STATUS_PATH] endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirLinkStatusRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// ID of the folder having link on; hyphenated lowercased UUID V4.
    pub uuid: String,
}
utils::display_from_json!(DirLinkStatusRequestPayload);

/// Response data for [DIR_LINK_STATUS_PATH] endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirLinkStatusResponseData {
    /// True if link exists; false if link for the given folder UUID cannot be found.
    pub exists: bool,

    /// Found link ID; hyphenated lowercased UUID V4. None if no link was found.
    pub uuid: Option<String>,

    /// Link key. None if no link was found.
    pub key: Option<String>,

    /// Link expiration time, as Unix timestamp in seconds. None if no link was found.
    pub expiration: Option<u64>,

    /// Link expiration time in text form. None if no link was found.
    /// Usually has value "never".
    #[serde(rename = "expirationText")]
    pub expiration_text: Option<String>,

    /// None if no link was found.
    #[serde(rename = "downloadBtn")]
    pub download_btn: Option<DownloadBtnStateByte>,

    /// Link password hash in hex string form, or None if no password was set by user or if no link was found.
    pub password: Option<String>,
}
utils::display_from_json!(DirLinkStatusResponseData);

api_response_struct!(
    /// Response for [AUTH_INFO_PATH] endpoint.
    DirLinkStatusResponsePayload<Option<DirLinkStatusResponseData>>
);

/// Calls [DIR_LINK_ADD_PATH] endpoint. Used to create public link for a folder.
/// Filen always creates a link without password first, and optionally sets password later using [dir_link_edit].
pub fn dir_link_add_request(
    payload: &DirLinkAddRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(DIR_LINK_ADD_PATH, payload, filen_settings).context(DirLinkAddQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [DIR_LINK_ADD_PATH] endpoint asynchronously. Used to create public link for a folder.
/// Filen always creates a link without password first, and optionally sets password later using [dir_link_edit].
pub async fn dir_link_add_request_async(
    payload: &DirLinkAddRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(DIR_LINK_ADD_PATH, payload, filen_settings)
        .await
        .context(DirLinkAddQueryFailed {
            payload: payload.clone(),
        })
}

/// Calls [DIR_LINK_EDIT_PATH] endpoint. Used to edit public link properties.
/// Filen always creates a link without password first, and optionally sets password later using [dir_link_edit].
pub fn dir_link_edit_request(
    payload: &DirLinkEditRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(DIR_LINK_EDIT_PATH, payload, filen_settings).context(DirLinkEditQueryFailed {
        payload: payload.clone(),
    })
}

/// Calls [DIR_LINK_EDIT_PATH] endpoint asynchronously. Used to edit public link properties.
/// Filen always creates a link without password first, and optionally sets password later using [dir_link_edit].
pub async fn dir_link_edit_request_async(
    payload: &DirLinkEditRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(DIR_LINK_EDIT_PATH, payload, filen_settings)
        .await
        .context(DirLinkEditQueryFailed {
            payload: payload.clone(),
        })
}

/// Calls [DIR_LINK_REMOVE_PATH] endpoint. Used to delete public link for a folder.
pub fn dir_link_remove_request(
    payload: &DirLinkRemoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api(DIR_LINK_REMOVE_PATH, payload, filen_settings).context(DirLinkRemoveQueryFailed {
        link_uuid: payload.uuid.clone(),
    })
}

/// Calls [DIR_LINK_REMOVE_PATH] endpoint asynchronously. Used to create public link for a folder.
pub async fn dir_link_remove_request_async(
    payload: &DirLinkRemoveRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<PlainApiResponse> {
    queries::query_filen_api_async(DIR_LINK_REMOVE_PATH, payload, filen_settings)
        .await
        .context(DirLinkRemoveQueryFailed {
            link_uuid: payload.uuid.clone(),
        })
}

/// Calls [DIR_LINK_STATUS_PATH] endpoint. Used to delete public link for a folder.
pub fn dir_link_status_request(
    payload: &DirLinkStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DirLinkStatusResponsePayload> {
    queries::query_filen_api(DIR_LINK_STATUS_PATH, payload, filen_settings).context(DirLinkStatusQueryFailed {
        link_uuid: payload.uuid.clone(),
    })
}

/// Calls [DIR_LINK_STATUS_PATH] endpoint asynchronously. Used to create public link for a folder.
pub async fn dir_link_status_request_async(
    payload: &DirLinkStatusRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<DirLinkStatusResponsePayload> {
    queries::query_filen_api_async(DIR_LINK_STATUS_PATH, payload, filen_settings)
        .await
        .context(DirLinkStatusQueryFailed {
            link_uuid: payload.uuid.clone(),
        })
}
