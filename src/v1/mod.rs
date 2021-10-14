pub mod auth;
pub mod keys;

macro_rules! filen_api_response_struct {
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
            pub message: String,

            /// Resulting data.
            pub data: Option<$response_data_type>,
        }
    }
}
pub(crate) use filen_api_response_struct;
