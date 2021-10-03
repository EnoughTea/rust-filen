use serde::{Deserialize, Serialize};
use serde_with::*;
use std::str;

/// Used for requests to /v1/auth/info endpoint.
#[derive(Serialize, Deserialize, Debug)]
struct AuthInfoRequest {
    pub email: String,

    /// XXXXXX means no key
    #[serde(rename = "twoFactorKey")]
    pub two_factor_key: Option<String>,
}

#[serde_as]
#[derive(Deserialize, Serialize, PartialEq, Debug)]
struct AuthInfoResponseData {
    pub email: String,

    /// Currently values of 1 & 2 can be encountered.
    #[serde(rename = "authVersion")]
    pub auth_version: u32,

    /// Can be null.
    #[serde_as(as = "NoneAsEmptyString")]
    pub salt: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct AuthInfoResponse {
    pub status: bool,
    pub message: String,
    pub data: AuthInfoResponseData,
}

#[cfg(test)]
mod tests {
    use httpmock::prelude::*;
    use reqwest::blocking::Client;
    use serde_json::*;

    use crate::{filen::requests::*, test_utils};

    // TODO: remove
    #[test]
    fn auth_info_v1_contract() {
        let client = Client::new();
        let server = MockServer::start();
        let auth_info_path = "/auth/info";
        let auth_info_request = AuthInfoRequest {
            email: "test@email.com".to_owned(),
            two_factor_key: None,
        };
        server.mock(|when, then| {
            when.method(POST)
                .path(auth_info_path)
                .header("content-type", "application/json")
                .json_body(json!(auth_info_request));
            then.status(200)
                .header("content-type", "text/html")
                .body_from_file(test_utils::project_path_for("tests/resources/auth_info_v1_response.json").unwrap());
        });
        let expected_auth_info_response = AuthInfoResponse {
            status: true,
            message: "Authentication info fetched.".to_string(),
            data: AuthInfoResponseData {
                email: "test@test.com".to_string(),
                auth_version: 1,
                salt: None,
            },
        };

        let resp = client.post(server.url(auth_info_path)).json(&auth_info_request).send();
        let auth_info_response = resp.unwrap().json::<AuthInfoResponse>().unwrap();

        assert_eq!(auth_info_response, expected_auth_info_response);
    }
}
