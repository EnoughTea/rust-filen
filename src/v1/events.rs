#![allow(clippy::redundant_pub_crate)]

use crate::{
    queries, utils,
    v1::{
        bool_from_int, bool_to_int, files, fs, response_payload, FileProperties, FileStorageInfo, HasFileLocation,
        HasFileMetadata, HasLocationName, HasUuid, ItemKind, LocationColor, LocationNameMetadata,
    },
    FilenSettings,
};
use secstr::SecUtf8;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, skip_serializing_none, DisplayFromStr};
use snafu::{Backtrace, ResultExt, Snafu};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use strum::{Display, EnumString};
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

const USER_EVENTS_PATH: &str = "/v1/user/events";
const USER_EVENTS_GET_PATH: &str = "/v1/user/events/get";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display(
        "Expected \"all\" or specific event type, got unknown string of length: {}",
        string_length
    ))]
    CannotParseUserEventFilterFromString { string_length: usize, backtrace: Backtrace },

    #[snafu(display("{} query failed: {}", USER_EVENTS_PATH, source))]
    UserEventsQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_EVENTS_GET_PATH, source))]
    UserEventsGetQueryFailed { source: queries::Error },
}

/// Type of an user event.
#[derive(Clone, Debug, Display, EnumString, Eq, Hash, PartialEq)]
#[strum(ascii_case_insensitive, serialize_all = "camelCase")]
pub enum UserEventKind {
    BaseFolderCreated,
    CodeRedeemed,
    DeleteAll,
    DeleteUnfinished,
    DeleteVersioned,
    Disabled2FA,
    EmailChangeAttempt,
    EmailChanged,
    Enabled2FA,
    FileLinkEdited,
    FileMoved,
    FileRenamed,
    FileRestored,
    FileRm,
    FileShared,
    FileTrash,
    FileUploaded,
    FileVersioned,
    FolderColorChanged,
    FolderLinkEdited,
    FolderMoved,
    FolderRenamed,
    FolderRestored,
    FolderShared,
    FolderTrash,
    ItemFavorite,
    Login,
    PasswordChanged,
    RemovedSharedInItems,
    RemovedSharedOutItems,
    SubFolderCreated,
    RequestAccountDeletion,
    TrashEmptied,
    VersionedFileRestored,
    #[strum(default)]
    Unknown(String),
}

impl<'de> Deserialize<'de> for UserEventKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from_str(&s).unwrap_or_else(|_| Self::Unknown(s)))
    }
}

impl Serialize for UserEventKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            UserEventKind::Unknown(value) => serializer.serialize_str(value),
            other => serializer.serialize_str(&other.to_string()),
        }
    }
}

/// Determines which events to filter out.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum UserEventFilter {
    /// All events are fine.
    All,
    /// Only specific event type is fine.
    Specific(UserEventKind),
}

impl FromStr for UserEventFilter {
    type Err = Error;

    fn from_str(all_or_event_kind: &str) -> Result<Self, Self::Err> {
        if all_or_event_kind.eq_ignore_ascii_case("all") {
            Ok(Self::All)
        } else {
            match UserEventKind::from_str(all_or_event_kind) {
                Ok(user_event_kind) => Ok(Self::Specific(user_event_kind)),
                Err(_) => CannotParseUserEventFilterFromString {
                    string_length: all_or_event_kind.len(),
                }
                .fail(),
            }
        }
    }
}

impl fmt::Display for UserEventFilter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UserEventFilter::All => write!(f, "all"),
            UserEventFilter::Specific(user_event_kind) => user_event_kind.fmt(f),
        }
    }
}

impl<'de> Deserialize<'de> for UserEventFilter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let all_or_event_kind = String::deserialize(deserializer)?;

        if all_or_event_kind.eq_ignore_ascii_case("all") {
            Ok(Self::All)
        } else {
            match UserEventKind::from_str(&all_or_event_kind) {
                Ok(user_event_kind) => Ok(Self::Specific(user_event_kind)),
                Err(_) => Err(de::Error::invalid_value(
                    de::Unexpected::Str(&all_or_event_kind),
                    &"\"all\" or specific event type",
                )),
            }
        }
    }
}

impl Serialize for UserEventFilter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            UserEventFilter::All => serializer.serialize_str("all"),
            UserEventFilter::Specific(user_event_kind) => user_event_kind.serialize(serializer),
        }
    }
}

/// Holds IP and User-Agent.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserFingerprint {
    #[serde_as(as = "DisplayFromStr")]
    pub ip: Ipv4Addr,

    #[serde(rename = "userAgent")]
    pub user_agent: String,
}

user_event_struct!(
    /// General event for event infos containing only IP and user agent.
    PlainUserEvent<UserFingerprint>
);

/// Generic file event data for a downloadable file.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct DownloadableFileEventInfo {
    /// File ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Filen file storage info.
    #[serde(flatten)]
    pub storage: FileStorageInfo,

    /// File metadata.
    pub metadata: String,

    /// Random alphanumeric string associated with the file. Used for deleting and versioning.
    pub rm: String,

    /// File creation time, as Unix timestamp in seconds.
    pub timestamp: u64,

    /// ID of the folder which contains this file.
    pub parent: Uuid,

    /// Determines how file bytes should be encrypted/decrypted.
    /// File is encrypted using roughly the same algorithm as metadata encryption,
    /// use [crypto::encrypt_file_data] and [crypto::decrypt_file_data] for the task.
    pub version: u32,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(DownloadableFileEventInfo);

impl HasFileMetadata for DownloadableFileEventInfo {
    fn file_metadata_ref(&self) -> &str {
        &self.metadata
    }
}

impl HasFileLocation for DownloadableFileEventInfo {
    fn file_storage_ref(&self) -> &FileStorageInfo {
        &self.storage
    }
}

impl HasUuid for DownloadableFileEventInfo {
    fn uuid_ref(&self) -> &Uuid {
        &self.uuid
    }
}

/// Generic file event data.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FileParentlessEventInfo {
    /// File ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// File metadata.
    pub metadata: String,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(FileParentlessEventInfo);

impl HasFileMetadata for FileParentlessEventInfo {
    fn file_metadata_ref(&self) -> &str {
        &self.metadata
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FolderEventInfo {
    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Folder name metadata.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Parent folder ID; hyphenated lowercased UUID V4.
    pub parent: Uuid,

    /// Folder creation time, as Unix timestamp in seconds.
    pub timestamp: u64,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(FolderEventInfo);

impl HasLocationName for FolderEventInfo {
    fn name_metadata_ref(&self) -> &str {
        &self.name_metadata
    }
}

impl HasUuid for FolderEventInfo {
    fn uuid_ref(&self) -> &Uuid {
        &self.uuid
    }
}

/// Used for requests to `USER_EVENTS_PATH` endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserEventsRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    pub id: u64,

    /// Determines which events to return.
    pub filter: UserEventFilter,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct BaseFolderCreatedEventInfo {
    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Folder name metadata.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Folder creation time, as Unix timestamp in seconds.
    pub timestamp: u64,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(BaseFolderCreatedEventInfo);

impl HasLocationName for BaseFolderCreatedEventInfo {
    fn name_metadata_ref(&self) -> &str {
        &self.name_metadata
    }
}

impl HasUuid for BaseFolderCreatedEventInfo {
    fn uuid_ref(&self) -> &Uuid {
        &self.uuid
    }
}

user_event_struct!(
    /// Event emitted after a base folder was created.
    BaseFolderCreatedUserEvent<BaseFolderCreatedEventInfo>
);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct CodeRedeemedEventInfo {
    /// Redeemed code.
    pub code: String,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(CodeRedeemedEventInfo);

user_event_struct!(
    /// Event emitted after user has redeemed a promocode.
    CodeRedeemedUserEvent<CodeRedeemedEventInfo>
);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct EmailChangeAttemptInfo {
    /// New email.
    pub email: String,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(EmailChangeAttemptInfo);

user_event_struct!(
    /// Event emitted after email change was requested, but before the new email was confirmed.
    EmailChangeAttemptUserEvent<EmailChangeAttemptInfo>
);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct EmailChangedInfo {
    /// New email.
    pub email: String,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(EmailChangedInfo);

user_event_struct!(
    /// Event emitted after the new email was confirmed.
    EmailChangedUserEvent<EmailChangedInfo>
);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FileLinkEditedInfo {
    /// File ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Link ID; hyphenated lowercased UUID V4.
    #[serde(rename = "linkUUID")]
    pub link_uuid: Uuid,

    /// File metadata.
    pub metadata: String,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(FileLinkEditedInfo);

impl HasFileMetadata for FileLinkEditedInfo {
    fn file_metadata_ref(&self) -> &str {
        &self.metadata
    }
}

user_event_struct!(
    /// Event emitted after a file link was edited.
    FileLinkEditedUserEvent<FileLinkEditedInfo>
);

user_event_struct!(
    /// Event emitted after a file was moved.
    FileMovedUserEvent<DownloadableFileEventInfo>
);

user_event_struct!(
    /// Event emitted after a file was restored from 'trash'.
    FileRestoredUserEvent<DownloadableFileEventInfo>
);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FileRenamedInfo {
    /// File ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// File metadata.
    pub metadata: String,

    /// Previous file metadata.
    #[serde(rename = "oldMetadata")]
    pub old_metadata: String,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(FileRenamedInfo);

impl FileRenamedInfo {
    /// Decrypts old file metadata string.
    fn decrypt_old_file_metadata(&self, master_keys: &[SecUtf8]) -> Result<FileProperties, files::Error> {
        FileProperties::decrypt_file_metadata(&self.old_metadata, master_keys)
    }
}

impl HasFileMetadata for FileRenamedInfo {
    fn file_metadata_ref(&self) -> &str {
        &self.metadata
    }
}

user_event_struct!(
    /// Event emitted after a file was renamed.
    FileRenamedUserEvent<FileRenamedInfo>
);

user_event_struct!(
    /// Event emitted after a file was deleted.
    FileRmUserEvent<FileParentlessEventInfo>
);

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FileSharedInfo {
    /// File ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Email of the user the file is shared with.
    #[serde(rename = "receiverEmail")]
    pub receiver_email: String,

    /// File metadata.
    pub metadata: String,

    /// Parent folder ID; hyphenated lowercased UUID V4.
    pub parent: Option<Uuid>,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(FileSharedInfo);

impl HasFileMetadata for FileSharedInfo {
    fn file_metadata_ref(&self) -> &str {
        &self.metadata
    }
}

user_event_struct!(
    /// Event emitted after a file was shared.
    FileSharedUserEvent<FileSharedInfo>
);

user_event_struct!(
    /// Event emitted after a file was versioned.
    FileVersionedUserEvent<FileParentlessEventInfo>
);

user_event_struct!(
    /// Event emitted after a file was moved to 'trash'.
    FileTrashUserEvent<FileParentlessEventInfo>
);

user_event_struct!(
    /// Event emitted after a file was uploaded.
    FileUploadedUserEvent<DownloadableFileEventInfo>
);

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FolderColorChangedInfo {
    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Folder name metadata.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Folder color name.
    pub color: LocationColor,

    /// Previous folder color name. None means default yellow color.
    #[serde(rename = "oldColor")]
    pub old_color: Option<LocationColor>,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(FolderColorChangedInfo);

impl HasLocationName for FolderColorChangedInfo {
    fn name_metadata_ref(&self) -> &str {
        &self.name_metadata
    }
}

impl HasUuid for FolderColorChangedInfo {
    fn uuid_ref(&self) -> &Uuid {
        &self.uuid
    }
}

user_event_struct!(
    /// Event emitted after a folder color was changed.
    FolderColorChangedUserEvent<FolderColorChangedInfo>
);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FolderLinkEditedInfo {
    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Link ID; hyphenated lowercased UUID V4.
    #[serde(rename = "linkUUID")]
    pub link_uuid: Uuid,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(FolderLinkEditedInfo);

user_event_struct!(
    /// Event emitted after a folder link was edited.
    FolderLinkEditedUserEvent<FolderLinkEditedInfo>
);

user_event_struct!(
    /// Event emitted after a folder was moved.
    FolderMovedUserEvent<FolderEventInfo>
);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FolderRenamedInfo {
    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Folder name metadata.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Previous folder name metadata.
    #[serde(rename = "oldName")]
    pub old_name_metadata: String,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(FolderRenamedInfo);

impl FolderRenamedInfo {
    /// Decrypts old name metadata into a location name.
    fn decrypt_old_name_metadata(&self, master_keys: &[SecUtf8]) -> Result<String, fs::Error> {
        LocationNameMetadata::decrypt_name_from_metadata(&self.old_name_metadata, master_keys)
    }
}

impl HasLocationName for FolderRenamedInfo {
    fn name_metadata_ref(&self) -> &str {
        &self.name_metadata
    }
}

impl HasUuid for FolderRenamedInfo {
    fn uuid_ref(&self) -> &Uuid {
        &self.uuid
    }
}

user_event_struct!(
    /// Event emitted after a folder was renamed.
    FolderRenamedUserEvent<FolderRenamedInfo>
);

user_event_struct!(
    /// Event emitted after a folder was restored.
    FolderRestoredUserEvent<FolderEventInfo>
);

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FolderSharedEventInfo {
    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Email of the user the folder is shared with.
    #[serde(rename = "receiverEmail")]
    pub receiver_email: String,

    /// Folder name metadata.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Parent folder ID; hyphenated lowercased UUID V4.
    pub parent: Option<Uuid>,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(FolderSharedEventInfo);

impl HasLocationName for FolderSharedEventInfo {
    fn name_metadata_ref(&self) -> &str {
        &self.name_metadata
    }
}

impl HasUuid for FolderSharedEventInfo {
    fn uuid_ref(&self) -> &Uuid {
        &self.uuid
    }
}

user_event_struct!(
    /// Event emitted after a folder was shared.
    FolderSharedUserEvent<FolderSharedEventInfo>
);

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FolderTrashEventInfo {
    /// Folder ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// Folder name metadata.
    #[serde(rename = "name")]
    pub name_metadata: String,

    /// Parent folder ID; hyphenated lowercased UUID V4.
    pub parent: Option<Uuid>,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(FolderTrashEventInfo);

impl HasLocationName for FolderTrashEventInfo {
    fn name_metadata_ref(&self) -> &str {
        &self.name_metadata
    }
}

impl HasUuid for FolderTrashEventInfo {
    fn uuid_ref(&self) -> &Uuid {
        &self.uuid
    }
}

user_event_struct!(
    /// Event emitted after a folder was moved to 'trash'.
    FolderTrashUserEvent<FolderTrashEventInfo>
);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ItemFavoriteEventInfo {
    /// Item ID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,

    /// What is favorited: a "file" or "folder"?
    #[serde(rename = "type")]
    pub item_type: ItemKind,

    /// 0 means item was unfavorited, 1 means item was favorited.
    #[serde(deserialize_with = "bool_from_int", serialize_with = "bool_to_int")]
    pub value: bool,

    /// File metadata.
    pub metadata: String,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(ItemFavoriteEventInfo);

impl HasFileMetadata for ItemFavoriteEventInfo {
    fn file_metadata_ref(&self) -> &str {
        &self.metadata
    }
}

user_event_struct!(
    /// Event emitted after a file or folder favorite status was changed.
    ItemFavoriteUserEvent<ItemFavoriteEventInfo>
);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RemovedSharedInItemsInfo {
    /// Email of the user who shared this item.
    #[serde(rename = "sharerEmail")]
    pub sharer_email: String,

    /// Removed items count.
    pub count: u32,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(RemovedSharedInItemsInfo);

user_event_struct!(
    /// Event emitted after some shared-in (from another user) items were removed.
    RemovedSharedInItemsUserEvent<RemovedSharedInItemsInfo>
);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RemovedSharedOutItemsInfo {
    /// Email of the user with whom the item is shared.
    #[serde(rename = "receiverEmail")]
    pub receiver_email: String,

    /// Removed items count.
    pub count: u32,

    /// User's IP and User-Agent.
    #[serde(flatten)]
    pub fingerprint: UserFingerprint,
}
utils::display_from_json!(RemovedSharedOutItemsInfo);

user_event_struct!(
    /// Event emitted after some shared-out items were removed.
    RemovedSharedOutItemsUserEvent<RemovedSharedOutItemsInfo>
);

user_event_struct!(
    /// Event emitted after a subfolder was created.
    SubFolderCreatedUserEvent<FolderEventInfo>
);

user_event_struct!(
    /// Event emitted after a versioned file was restored.
    VersionedFileRestoredUserEvent<DownloadableFileEventInfo>
);

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(untagged)]
pub enum UserEvent {
    BaseFolderCreated(BaseFolderCreatedUserEvent),
    CodeRedeemed(CodeRedeemedUserEvent),
    DeleteAll(PlainUserEvent),
    DeleteUnfinished(PlainUserEvent),
    DeleteVersioned(PlainUserEvent),
    Disabled2FA(PlainUserEvent),
    EmailChangeAttempt(EmailChangeAttemptUserEvent),
    EmailChanged(EmailChangedUserEvent),
    Enabled2FA(PlainUserEvent),
    FileLinkEdited(FileLinkEditedUserEvent),
    FileMoved(FileMovedUserEvent),
    FileRenamed(FileRenamedUserEvent),
    FileRestored(FileRestoredUserEvent),
    FileRm(FileRmUserEvent),
    FileShared(FileSharedUserEvent),
    FileTrash(FileTrashUserEvent),
    FileUploaded(FileUploadedUserEvent),
    FileVersioned(FileVersionedUserEvent),
    FolderColorChanged(FolderColorChangedUserEvent),
    FolderLinkEdited(FolderLinkEditedUserEvent),
    FolderMoved(FolderMovedUserEvent),
    FolderRenamed(FolderRenamedUserEvent),
    FolderRestored(FolderRestoredUserEvent),
    FolderShared(FolderSharedUserEvent),
    FolderTrash(FolderTrashUserEvent),
    ItemFavorite(ItemFavoriteUserEvent),
    Login(PlainUserEvent),
    PasswordChanged(PlainUserEvent),
    RemovedSharedInItems(RemovedSharedInItemsUserEvent),
    RemovedSharedOutItems(RemovedSharedOutItemsUserEvent),
    SubFolderCreated(SubFolderCreatedUserEvent),
    RequestAccountDeletion(PlainUserEvent),
    TrashEmptied(PlainUserEvent),
    VersionedFileRestored(VersionedFileRestoredUserEvent),
    Unknown(PlainUserEvent),
}

#[derive(Deserialize)]
pub(crate) struct UserEventDeserializeHelper {
    pub id: u64,
    pub uuid: Uuid,
    #[serde(rename = "type")]
    pub event_type: UserEventKind,
    pub info: serde_json::Value,
    pub timestamp: u64,
}

impl<'de> Deserialize<'de> for UserEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = UserEventDeserializeHelper::deserialize(deserializer)?;
        match helper.event_type {
            UserEventKind::BaseFolderCreated => BaseFolderCreatedEventInfo::deserialize(&helper.info)
                .map(|ei| Self::BaseFolderCreated(BaseFolderCreatedUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::CodeRedeemed => CodeRedeemedEventInfo::deserialize(&helper.info)
                .map(|ei| Self::CodeRedeemed(CodeRedeemedUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::DeleteAll => UserFingerprint::deserialize(&helper.info)
                .map(|ei| Self::DeleteAll(PlainUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::DeleteUnfinished => UserFingerprint::deserialize(&helper.info)
                .map(|ei| Self::DeleteUnfinished(PlainUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::DeleteVersioned => UserFingerprint::deserialize(&helper.info)
                .map(|ei| Self::DeleteVersioned(PlainUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::Disabled2FA => UserFingerprint::deserialize(&helper.info)
                .map(|ei| Self::Disabled2FA(PlainUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::EmailChangeAttempt => EmailChangeAttemptInfo::deserialize(&helper.info)
                .map(|ei| Self::EmailChangeAttempt(EmailChangeAttemptUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::EmailChanged => EmailChangedInfo::deserialize(&helper.info)
                .map(|ei| Self::EmailChanged(EmailChangedUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::Enabled2FA => UserFingerprint::deserialize(&helper.info)
                .map(|ei| Self::Enabled2FA(PlainUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FileLinkEdited => FileLinkEditedInfo::deserialize(&helper.info)
                .map(|ei| Self::FileLinkEdited(FileLinkEditedUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FileMoved => DownloadableFileEventInfo::deserialize(&helper.info)
                .map(|ei| Self::FileMoved(FileMovedUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FileRenamed => FileRenamedInfo::deserialize(&helper.info)
                .map(|ei| Self::FileRenamed(FileRenamedUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FileRestored => DownloadableFileEventInfo::deserialize(&helper.info)
                .map(|ei| Self::FileRestored(FileRestoredUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FileRm => FileParentlessEventInfo::deserialize(&helper.info)
                .map(|ei| Self::FileRm(FileRmUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FileShared => FileSharedInfo::deserialize(&helper.info)
                .map(|ei| Self::FileShared(FileSharedUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FileTrash => FileParentlessEventInfo::deserialize(&helper.info)
                .map(|ei| Self::FileTrash(FileTrashUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FileUploaded => DownloadableFileEventInfo::deserialize(&helper.info)
                .map(|ei| Self::FileUploaded(FileUploadedUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FileVersioned => FileParentlessEventInfo::deserialize(&helper.info)
                .map(|ei| Self::FileVersioned(FileVersionedUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FolderColorChanged => FolderColorChangedInfo::deserialize(&helper.info)
                .map(|ei| Self::FolderColorChanged(FolderColorChangedUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FolderLinkEdited => FolderLinkEditedInfo::deserialize(&helper.info)
                .map(|ei| Self::FolderLinkEdited(FolderLinkEditedUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FolderMoved => FolderEventInfo::deserialize(&helper.info)
                .map(|ei| Self::FolderMoved(FolderMovedUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FolderRenamed => FolderRenamedInfo::deserialize(&helper.info)
                .map(|ei| Self::FolderRenamed(FolderRenamedUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FolderRestored => FolderEventInfo::deserialize(&helper.info)
                .map(|ei| Self::FolderRestored(FolderRestoredUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FolderShared => FolderSharedEventInfo::deserialize(&helper.info)
                .map(|ei| Self::FolderShared(FolderSharedUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::FolderTrash => FolderTrashEventInfo::deserialize(&helper.info)
                .map(|ei| Self::FolderTrash(FolderTrashUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::ItemFavorite => ItemFavoriteEventInfo::deserialize(&helper.info)
                .map(|ei| Self::ItemFavorite(ItemFavoriteUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::Login => UserFingerprint::deserialize(&helper.info)
                .map(|ei| Self::Login(PlainUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::PasswordChanged => UserFingerprint::deserialize(&helper.info)
                .map(|ei| Self::PasswordChanged(PlainUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::RemovedSharedInItems => RemovedSharedInItemsInfo::deserialize(&helper.info)
                .map(|ei| Self::RemovedSharedInItems(RemovedSharedInItemsUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::RemovedSharedOutItems => RemovedSharedOutItemsInfo::deserialize(&helper.info)
                .map(|ei| Self::RemovedSharedOutItems(RemovedSharedOutItemsUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::SubFolderCreated => FolderEventInfo::deserialize(&helper.info)
                .map(|ei| Self::SubFolderCreated(SubFolderCreatedUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::RequestAccountDeletion => UserFingerprint::deserialize(&helper.info)
                .map(|ei| Self::RequestAccountDeletion(PlainUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::TrashEmptied => UserFingerprint::deserialize(&helper.info)
                .map(|ei| Self::TrashEmptied(PlainUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::VersionedFileRestored => DownloadableFileEventInfo::deserialize(&helper.info)
                .map(|ei| Self::VersionedFileRestored(VersionedFileRestoredUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
            UserEventKind::Unknown(_) => UserFingerprint::deserialize(&helper.info)
                .map(|ei| Self::Unknown(PlainUserEvent::from_helper_and_info(helper, ei)))
                .map_err(de::Error::custom),
        }
    }
}

/// Response data for `USER_EVENTS_PATH` endpoint.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserEventsResponseData {
    /// List of filtered user events.
    pub events: Vec<UserEvent>,

    /// Filtered events count.
    pub limit: u32,
}
utils::display_from_json!(UserEventsResponseData);

response_payload!(
    /// Response for `USER_EVENTS_PATH` endpoint.
    UserEventsResponsePayload<UserEventsResponseData>
);

/// Used for requests to `USER_EVENTS_GET_PATH` endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserEventsGetRequestPayload {
    /// User-associated Filen API key.
    #[serde(rename = "apiKey")]
    pub api_key: SecUtf8,

    /// Event UUID; hyphenated lowercased UUID V4.
    pub uuid: Uuid,
}

response_payload!(
    /// Response for `USER_EVENTS_GET_PATH` endpoint.
    UserEventsGetResponsePayload<UserEvent>
);

/// Calls `USER_EVENTS_PATH` endpoint.
pub fn user_events_request(
    payload: &UserEventsRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserEventsResponsePayload> {
    queries::query_filen_api(USER_EVENTS_PATH, payload, filen_settings).context(UserEventsQueryFailed {})
}

/// Calls `USER_EVENTS_PATH` endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn user_events_request_async(
    payload: &UserEventsRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserEventsResponsePayload> {
    queries::query_filen_api_async(USER_EVENTS_PATH, payload, filen_settings)
        .await
        .context(UserEventsQueryFailed {})
}

/// Calls `USER_EVENTS_GET_PATH` endpoint.
pub fn user_events_get_request(
    payload: &UserEventsGetRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserEventsGetResponsePayload> {
    queries::query_filen_api(USER_EVENTS_GET_PATH, payload, filen_settings).context(UserEventsGetQueryFailed {})
}

/// Calls `USER_EVENTS_GET_PATH` endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn user_events_get_request_async(
    payload: &UserEventsGetRequestPayload,
    filen_settings: &FilenSettings,
) -> Result<UserEventsGetResponsePayload> {
    queries::query_filen_api_async(USER_EVENTS_GET_PATH, payload, filen_settings)
        .await
        .context(UserEventsGetQueryFailed {})
}

macro_rules! user_event_struct {
    (
        $(#[$meta:meta])*
        $struct_name:ident<$event_data_type:ty>
    ) => {
        $(#[$meta])*
        #[serde_with::skip_serializing_none]
        #[derive(Clone, Debug, serde::Deserialize, Eq, Hash, PartialEq, serde::Serialize)]
        pub struct $struct_name {
            // Event ID; Filen-incremented counter.
            pub id: u64,

            /// Event UUID; hyphenated lowercased UUID V4.
            pub uuid: Uuid,

            /// Event kind.
            #[serde(rename = "type")]
            pub event_type: UserEventKind,

            /// Time when the event has occured, as Unix timestamp in seconds.
            pub timestamp: u64,

            /// Data, associated with the event.
            pub info: $event_data_type,
        }

        crate::utils::display_from_json!($struct_name);

        impl $struct_name {
            #[allow(clippy::missing_const_for_fn)]
            pub(crate) fn from_helper_and_info(helper: UserEventDeserializeHelper, info: $event_data_type) -> $struct_name {
                $struct_name {
                    id: helper.id,
                    uuid: helper.uuid,
                    event_type: helper.event_type,
                    timestamp: helper.timestamp,
                    info,
                }
            }
        }
    }
}
pub(crate) use user_event_struct;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{validate_contract, validate_contract_async};
    use once_cell::sync::Lazy;
    use pretty_assertions::assert_eq;
    use secstr::SecUtf8;

    static API_KEY: Lazy<SecUtf8> =
        Lazy::new(|| SecUtf8::from("bYZmrwdVEbHJSqeA1RfnPtKiBcXzUpRdKGRkjw9m1o1eqSGP1s6DM11CDnklpFq6"));

    #[test]
    fn known_user_event_kind_should_be_serialized() {
        let expected = r#""deleteAll""#;

        let serialized = serde_json::to_string(&UserEventKind::DeleteAll).unwrap();

        assert_eq!(serialized, expected);
    }

    #[test]
    fn unknown_user_event_kind_should_be_serialized() {
        let expected = r#""this is some unknown value""#;

        let serialized_user_event_kind =
            serde_json::to_string(&UserEventKind::Unknown("this is some unknown value".to_owned())).unwrap();

        assert_eq!(serialized_user_event_kind, expected);
    }

    #[test]
    fn known_user_event_kind_should_be_deserialized() {
        let expected = UserEventKind::DeleteAll;

        let deserialized_user_event_kind = serde_json::from_str::<UserEventKind>(r#""deleteAll""#).unwrap();

        assert_eq!(deserialized_user_event_kind, expected);
    }

    #[test]
    fn unknown_user_event_kind_should_be_deserialized() {
        let expected = UserEventKind::Unknown("this is some unknown value".to_owned());

        let deserialized_user_event_kind =
            serde_json::from_str::<UserEventKind>(r#""this is some unknown value""#).unwrap();

        assert_eq!(deserialized_user_event_kind, expected);
    }

    #[test]
    fn user_events_request_should_have_proper_contract() {
        let request_payload = UserEventsRequestPayload {
            api_key: API_KEY.clone(),
            id: 0,
            filter: UserEventFilter::All,
        };
        validate_contract(
            USER_EVENTS_PATH,
            request_payload,
            "tests/resources/responses/user_events.json",
            |request_payload, filen_settings| user_events_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn user_events_request_async_should_have_proper_contract() {
        let request_payload = UserEventsRequestPayload {
            api_key: API_KEY.clone(),
            id: 0,
            filter: UserEventFilter::All,
        };
        validate_contract_async(
            USER_EVENTS_PATH,
            request_payload,
            "tests/resources/responses/user_events.json",
            |request_payload, filen_settings| async move {
                user_events_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }

    #[test]
    fn user_events_get_request_should_have_proper_contract() {
        let request_payload = UserEventsGetRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract(
            USER_EVENTS_GET_PATH,
            request_payload,
            "tests/resources/responses/user_events_get.json",
            |request_payload, filen_settings| user_events_get_request(&request_payload, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn user_events_get_request_async_should_have_proper_contract() {
        let request_payload = UserEventsGetRequestPayload {
            api_key: API_KEY.clone(),
            uuid: Uuid::nil(),
        };
        validate_contract_async(
            USER_EVENTS_GET_PATH,
            request_payload,
            "tests/resources/responses/user_events_get.json",
            |request_payload, filen_settings| async move {
                user_events_get_request_async(&request_payload, &filen_settings).await
            },
        )
        .await;
    }
}
