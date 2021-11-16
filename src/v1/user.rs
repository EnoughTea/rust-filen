use crate::{
    queries, utils,
    v1::{bool_from_int, bool_to_int, response_payload, FilenResponse, Uuid},
    FilenSettings,
};
use secstr::SecUtf8;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, skip_serializing_none, DisplayFromStr};
use snafu::{ResultExt, Snafu};
use std::str::FromStr;
use strum::{Display, EnumString};
use url::Url;

type Result<T, E = Error> = std::result::Result<T, E>;

const USER_GET_ACCOUNT_PATH: &str = "/v1/user/get/account";
const USER_GET_SETTINGS_PATH: &str = "/v1/user/get/settings";
const USER_INFO_PATH: &str = "/v1/user/info";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("{} query failed: {}", USER_GET_ACCOUNT_PATH, source))]
    UserGetAccountQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_GET_SETTINGS_PATH, source))]
    UserGetSettingsQueryFailed { source: queries::Error },

    #[snafu(display("{} query failed: {}", USER_INFO_PATH, source))]
    UserInfoQueryFailed { source: queries::Error },
}

#[allow(clippy::doc_markdown)]
/// One of payment gateways Filen currently support.
///
/// Currently observed: "paypal", "paypal_sale", "stripe", "stripe_sale", "coinbase".
#[derive(Clone, Debug, Display, EnumString, Eq, Hash, PartialEq)]
#[strum(ascii_case_insensitive, serialize_all = "snake_case")]
pub enum FilenPaymentGateway {
    Paypal,
    PaypalSale,
    Stripe,
    StripeSale,
    Coinbase,
    #[strum(default)]
    Unknown(String),
}

impl<'de> Deserialize<'de> for FilenPaymentGateway {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from_str(&s).unwrap_or_else(|_| Self::Unknown(s)))
    }
}

impl Serialize for FilenPaymentGateway {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[allow(clippy::wildcard_enum_match_arm)]
        match self {
            &FilenPaymentGateway::Unknown(ref value) => serializer.serialize_str(value),
            other => serializer.serialize_str(&other.to_string()),
        }
    }
}

/// Represents an invoice for a Filen subscription.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UserSubInvoice {
    /// Invoice ID; hyphenated lowercased UUID V4.
    pub id: Uuid,

    /// Corresponding `UserSub::id`; hyphenated lowercased UUID V4.
    #[serde(rename = "subId")]
    pub sub_id: Uuid,

    /// Payment gateway.
    pub gateway: FilenPaymentGateway,

    /// Human-readable Filen plan name.
    #[serde(rename = "planName")]
    pub plan_name: String,

    /// Filen plan cost in Euros, with 2 decimal places for cents.
    #[serde(rename = "planCost")]
    pub plan_cost: f64,

    /// Invoice date, as Unix timestamp in seconds.
    pub timestamp: u64,
}
utils::display_from_json!(UserSubInvoice);

/// Represents a Filen subscription.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UserSub {
    /// Subscription ID; hyphenated lowercased UUID V4.
    pub id: Uuid,

    #[serde(rename = "planId")]
    pub plan_id: u32,

    /// Payment gateway.
    pub gateway: FilenPaymentGateway,

    /// Human-readable Filen plan name.
    #[serde(rename = "planName")]
    pub plan_name: String,

    /// Filen plan cost in Euros, with 2 decimal places for cents.
    #[serde(rename = "planCost")]
    pub plan_cost: f64,

    /// Plan-provided storage in bytes.
    pub storage: u64,

    /// True if user is a premium user; false otherwise.
    #[serde(deserialize_with = "bool_from_int", serialize_with = "bool_to_int")]
    pub cancelled: bool,

    /// True if user is a premium user; false otherwise.
    #[serde(deserialize_with = "bool_from_int", serialize_with = "bool_to_int")]
    pub activated: bool,

    /// Plan start date, as Unix timestamp in seconds.
    #[serde(rename = "startTimestamp")]
    pub start_timestamp: u64,

    /// Plan cancel date, as Unix timestamp in seconds.
    #[serde(rename = "cancelTimestamp")]
    pub cancel_timestamp: u64,
}
utils::display_from_json!(UserSub);

/// Response data for `USER_GET_ACCOUNT_PATH` endpoint.
#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UserGetAccountResponseData {
    /// User's email.
    pub email: String,

    /// Total uploads; note that this is not the number of currently uploaded files.
    pub uploads: u64,

    /// Storage bytes used by user.
    pub storage: u64,

    /// Storage bytes available to user.
    #[serde(rename = "maxStorage")]
    pub max_storage: u64,

    /// True if user is a premium user; false otherwise.
    #[serde(
        rename = "isPremium",
        deserialize_with = "bool_from_int",
        serialize_with = "bool_to_int"
    )]
    pub is_premium: bool,

    #[serde(rename = "subsInvoices")]
    pub subs_invoices: Vec<UserSubInvoice>,

    pub subs: Vec<UserSub>,

    #[serde(rename = "referCount")]
    pub refer_count: u32,

    #[serde(rename = "referStorage")]
    pub refer_storage: u64,

    #[serde(rename = "refLimit")]
    pub ref_limit: u32,

    #[serde(rename = "refStorage")]
    pub ref_storage: u64,

    #[serde(rename = "refId")]
    pub ref_id: String,

    #[serde(rename = "affId")]
    pub aff_id: String,

    #[serde(rename = "affRate")]
    pub aff_rate: f64,

    #[serde(rename = "affCount")]
    pub aff_count: u32,

    #[serde(rename = "affEarnings")]
    pub aff_earnings: f64,

    #[serde(rename = "affBalance")]
    pub aff_balance: f64,

    /// Avatar URL.
    #[serde(rename = "avatarURL")]
    #[serde_as(as = "DisplayFromStr")]
    pub avatar_url: Url,
}
utils::display_from_json!(UserGetAccountResponseData);

/// Response for `USER_GET_ACCOUNT_PATH` endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UserGetAccountResponsePayload {
    /// True when API call was successful; false otherwise.
    pub status: bool,

    /// Filen reason for success or failure.
    pub message: Option<String>,

    /// Resulting data.
    pub data: Option<UserGetAccountResponseData>,
}
utils::display_from_json!(UserGetAccountResponsePayload);

impl FilenResponse<UserGetAccountResponseData> for UserGetAccountResponsePayload {
    fn status_ref(&self) -> bool {
        self.status
    }

    fn message_ref(&self) -> Option<&str> {
        self.message.as_deref()
    }

    fn data_ref(&self) -> Option<&UserGetAccountResponseData> {
        self.data.as_ref()
    }
}

/// Response data for `USER_GET_SETTINGS_PATH` endpoint.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserGetSettingsResponseData {
    /// User's email.
    pub email: String,

    #[serde(rename = "twoFactorKey")]
    pub two_factor_key: String,

    /// True if user has enabled 2FA; false otherwise.
    #[serde(
        rename = "twoFactorEnabled",
        deserialize_with = "bool_from_int",
        serialize_with = "bool_to_int"
    )]
    pub two_factor_enabled: bool,

    /// Versioned files count.
    #[serde(rename = "versionedFiles")]
    pub versioned_files: u64,

    /// Storage bytes used by versioned files.
    #[serde(rename = "versionedStorage")]
    pub versioned_storage: u64,

    /// Unfinished uploads count.
    #[serde(rename = "unfinishedFiles")]
    pub unfinished_files: u64,

    /// Storage bytes used by unfinished files.
    #[serde(rename = "unfinishedStorage")]
    pub unfinished_storage: u64,

    /// Storage bytes used by uploaded unversioned files.
    #[serde(rename = "storageUsed")]
    pub storage_used: u64,
}
utils::display_from_json!(UserGetSettingsResponseData);

response_payload!(
    /// Response for `USER_GET_SETTINGS_PATH` endpoint.
    UserGetSettingsResponsePayload<UserGetSettingsResponseData>
);

/// Response data for `USER_INFO_PATH` endpoint.
#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserInfoResponseData {
    /// User's email.
    pub email: String,

    /// Storage bytes available to user.
    #[serde(rename = "maxStorage")]
    pub max_storage: u64,

    /// Storage bytes used by user.
    #[serde(rename = "storageUsed")]
    pub storage_used: u64,

    /// True if user is a premium user; false otherwise.
    #[serde(
        rename = "isPremium",
        deserialize_with = "bool_from_int",
        serialize_with = "bool_to_int"
    )]
    pub is_premium: bool,

    /// Avatar URL.
    #[serde(rename = "avatarURL")]
    #[serde_as(as = "DisplayFromStr")]
    pub avatar_url: Url,
}
utils::display_from_json!(UserInfoResponseData);

response_payload!(
    /// Response for `USER_INFO_PATH` endpoint.
    UserInfoResponsePayload<UserInfoResponseData>
);

/// Calls `USER_GET_ACCOUNT_PATH` endpoint.
/// Used to get various account-associated data, such as plans, invoices, referrals.
pub fn user_get_account_request(
    api_key: &SecUtf8,
    filen_settings: &FilenSettings,
) -> Result<UserGetAccountResponsePayload> {
    queries::query_filen_api(USER_GET_ACCOUNT_PATH, &utils::api_key_json(api_key), filen_settings)
        .context(UserGetAccountQueryFailed {})
}

/// Calls `USER_GET_ACCOUNT_PATH` endpoint asynchronously.
/// Used to get various account-associated data, such as plans, invoices, referrals.
#[cfg(feature = "async")]
pub async fn user_get_account_request_async(
    api_key: &SecUtf8,
    filen_settings: &FilenSettings,
) -> Result<UserGetAccountResponsePayload> {
    queries::query_filen_api_async(USER_GET_ACCOUNT_PATH, &utils::api_key_json(api_key), filen_settings)
        .await
        .context(UserGetAccountQueryFailed {})
}

/// Calls `USER_GET_SETTINGS_PATH` endpoint. Used to 2FA settings, versioned and unfinished storage sizes.
pub fn user_get_settings_request(
    api_key: &SecUtf8,
    filen_settings: &FilenSettings,
) -> Result<UserGetSettingsResponsePayload> {
    queries::query_filen_api(USER_GET_SETTINGS_PATH, &utils::api_key_json(api_key), filen_settings)
        .context(UserGetSettingsQueryFailed {})
}

/// Calls `USER_GET_SETTINGS_PATH` endpoint asynchronously.
/// Used to 2FA settings, versioned and unfinished storage sizes.
#[cfg(feature = "async")]
pub async fn user_get_settings_request_async(
    api_key: &SecUtf8,
    filen_settings: &FilenSettings,
) -> Result<UserGetSettingsResponsePayload> {
    queries::query_filen_api_async(USER_GET_SETTINGS_PATH, &utils::api_key_json(api_key), filen_settings)
        .await
        .context(UserGetSettingsQueryFailed {})
}

/// Calls `USER_INFO_PATH` endpoint.
pub fn user_info_request(api_key: &SecUtf8, filen_settings: &FilenSettings) -> Result<UserInfoResponsePayload> {
    queries::query_filen_api(USER_INFO_PATH, &utils::api_key_json(api_key), filen_settings)
        .context(UserInfoQueryFailed {})
}

/// Calls `USER_INFO_PATH` endpoint asynchronously.
#[cfg(feature = "async")]
pub async fn user_info_request_async(
    api_key: &SecUtf8,
    filen_settings: &FilenSettings,
) -> Result<UserInfoResponsePayload> {
    queries::query_filen_api_async(USER_INFO_PATH, &utils::api_key_json(api_key), filen_settings)
        .await
        .context(UserInfoQueryFailed {})
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
    fn user_get_account_request_should_have_proper_contract() {
        validate_contract(
            USER_GET_ACCOUNT_PATH,
            &utils::api_key_json(&API_KEY),
            "tests/resources/responses/user_get_account.json",
            |_, filen_settings| user_get_account_request(&API_KEY, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn user_get_account_request_async_should_have_proper_contract() {
        validate_contract_async(
            USER_GET_ACCOUNT_PATH,
            &utils::api_key_json(&API_KEY),
            "tests/resources/responses/user_get_account.json",
            |_, filen_settings| async move { user_get_account_request_async(&API_KEY, &filen_settings).await },
        )
        .await;
    }

    #[test]
    fn user_get_settings_request_should_have_proper_contract() {
        validate_contract(
            USER_GET_SETTINGS_PATH,
            &utils::api_key_json(&API_KEY),
            "tests/resources/responses/user_get_settings.json",
            |_, filen_settings| user_get_settings_request(&API_KEY, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn user_get_settings_request_async_should_have_proper_contract() {
        validate_contract_async(
            USER_GET_SETTINGS_PATH,
            &utils::api_key_json(&API_KEY),
            "tests/resources/responses/user_get_settings.json",
            |_, filen_settings| async move { user_get_settings_request_async(&API_KEY, &filen_settings).await },
        )
        .await;
    }

    #[test]
    fn user_info_request_should_have_proper_contract() {
        validate_contract(
            USER_INFO_PATH,
            &utils::api_key_json(&API_KEY),
            "tests/resources/responses/user_info.json",
            |_, filen_settings| user_info_request(&API_KEY, &filen_settings),
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn user_info_request_async_should_have_proper_contract() {
        validate_contract_async(
            USER_INFO_PATH,
            &utils::api_key_json(&API_KEY),
            "tests/resources/responses/user_info.json",
            |_, filen_settings| async move { user_info_request_async(&API_KEY, &filen_settings).await },
        )
        .await;
    }
}
