pub mod auth;
mod dirs;
mod download_dir;
mod download_file;
mod files;
pub mod fs;
pub mod keys;
mod sync_dir;
mod upload_file;

const METADATA_VERSION: u32 = 1;

/// Contains just the response status and corresponding message.
#[derive(Debug, Clone, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct PlainApiResponse {
    /// True when API call was successful; false otherwise.
    pub status: bool,

    /// Filen reason for success or failure.
    pub message: Option<String>,
}
crate::utils::display_from_json!(PlainApiResponse);

/// This macro generates a struct to parse Filen API response into.
///
/// Filen API uses mostly the same format for all its responses, successfull or not.
/// Status and message fields are always present, while data field can be returned on success,
/// when said success implies getting some data.
///
/// To use, pass generated struct name and contained data type:
/// ```
/// api_response_struct!(
///     /// Response for some endpoint.
///     SomeResponsePayload<Option<SomeResponseData>>
/// );
/// ```
macro_rules! api_response_struct {
    (
        $(#[$meta:meta])*
        $struct_name:ident<$response_data_type:ty>
    ) => {
        $(#[$meta])*
        #[skip_serializing_none]
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        pub struct $struct_name {
            /// True when API call was successful; false otherwise.
            pub status: bool,

            /// Filen reason for success or failure.
            pub message: Option<String>,

            /// Resulting data.
            pub data: $response_data_type,
        }

        crate::utils::display_from_json!($struct_name);
    }
}
pub(crate) use api_response_struct;
