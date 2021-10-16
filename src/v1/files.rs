use crate::{
    crypto,
    settings::FilenSettings,
    utils,
    v1::{fs::*, *},
};
use anyhow::*;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::*;
use uuid::Uuid;

const FILE_ARCHIVE_PATH: &str = "/v1/file/archive";
const FILE_EXISTS_PATH: &str = "/v1/file/exists";
const FILE_TRASH_PATH: &str = "/v1/file/trash";

/// Calls [FILE_EXISTS_PATH] endpoint.
/// Checks if file with the given name exists within the specified parent folder.
pub fn file_exists_request(
    payload: &LocationExistsRequestPayload,
    settings: &FilenSettings,
) -> Result<LocationExistsResponsePayload> {
    utils::query_filen_api(FILE_EXISTS_PATH, payload, settings)
}

/// Calls [FILE_EXISTS_PATH] endpoint asynchronously.
/// Checks if file with the given name exists within the specified parent folder.
pub async fn file_exists_request_async(
    payload: &LocationExistsRequestPayload,
    settings: &FilenSettings,
) -> Result<LocationExistsResponsePayload> {
    utils::query_filen_api_async(FILE_EXISTS_PATH, payload, settings).await
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

    #[tokio::test]
    async fn file_exists_request_and_async_should_work() -> Result<()> {
        let (server, filen_settings) = init_server();
        let request_payload = LocationExistsRequestPayload {
            api_key: API_KEY.clone(),
            parent: "b640414e-367e-4df6-b31a-030fd639bcff".to_owned(),
            name_hashed: NAME_HASHED.to_owned(),
        };
        let expected_response: LocationExistsResponsePayload =
            deserialize_from_file("tests/resources/responses/file_exists.json");
        let mock = setup_json_mock(FILE_EXISTS_PATH, &request_payload, &expected_response, &server);

        let response = spawn_blocking(
            closure!(clone request_payload, clone filen_settings, || { file_exists_request(&request_payload, &filen_settings) }),
        ).await??;
        mock.assert_hits(1);
        assert_eq!(response, expected_response);

        let async_response = file_exists_request_async(&request_payload, &filen_settings).await?;
        mock.assert_hits(2);
        assert_eq!(async_response, expected_response);
        Ok(())
    }
}
