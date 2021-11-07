//! This module contains helper functions for tests (aka test dump).
use crate::filen_settings::FilenSettings;
use camino::Utf8PathBuf;
use httpmock::Method::POST;
use httpmock::{Mock, MockServer};
use pretty_assertions::assert_eq;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use snafu::{ResultExt, Snafu};
use std::convert::TryFrom;
use std::env;
use std::fmt::Debug;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use url::Url;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Current working directory cannot be accessed: {}", source))]
    CurrentWorkingDirectoryIsUnaccessible { source: std::io::Error },

    #[snafu(display(
        "Caller expected file system path '{}' to be a valid UTF-8 string, but it was not: {}",
        path,
        source
    ))]
    FileSystemPathIsNotUtf8 {
        path: String,
        source: camino::FromPathBufError,
    },
}

pub(crate) fn init_server() -> (MockServer, FilenSettings) {
    let server = MockServer::start();
    let filen_settings = FilenSettings {
        api_servers: vec![Url::parse(&server.base_url()).unwrap()],
        download_servers: vec![Url::parse(&server.base_url()).unwrap()],
        upload_servers: vec![Url::parse(&server.base_url()).unwrap()],
        request_timeout: Duration::from_secs(10),
        upload_chunk_timeout: Duration::from_secs(10),
        download_chunk_timeout: Duration::from_secs(10),
    };
    (server, filen_settings)
}

pub(crate) fn deserialize_from_file<U: DeserializeOwned>(response_file_path: &str) -> U {
    let response_contents = read_project_file(response_file_path);
    serde_json::from_slice(&response_contents).unwrap()
}

pub(crate) fn project_path() -> Result<Utf8PathBuf> {
    match env::var("CARGO_MANIFEST_DIR") {
        Ok(val) => Ok(Utf8PathBuf::from(val)),
        _ => {
            let curr_dir = env::current_dir().context(CurrentWorkingDirectoryIsUnaccessible {})?;
            Utf8PathBuf::try_from(curr_dir.clone()).context(FileSystemPathIsNotUtf8 {
                path: format!("{:?}", curr_dir),
            })
        }
    }
}

pub(crate) fn project_path_for(file_path: &str) -> Utf8PathBuf {
    match Path::new(&file_path).is_absolute() {
        true => Utf8PathBuf::from(file_path),
        false => {
            let mut proj_dir = project_path().expect("Cannot get project path or it contains invalid UTF-8");
            proj_dir.push(file_path);
            proj_dir
        }
    }
}

/// Reads file at the specified path to the end.
pub(crate) fn read_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>, std::io::Error> {
    let mut f = File::open(&file_path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).map(|_read_bytes| buffer)
}

pub(crate) fn read_project_file(file_path: &str) -> Vec<u8> {
    let target_path = project_path_for(file_path);
    read_file(&target_path).expect(&format!("Cannot read file: {}", target_path))
}

pub(crate) fn setup_json_mock<'server, T: Serialize, U: Serialize>(
    api_path: &str,
    request_payload: &T,
    response_payload: &U,
    server: &'server MockServer,
) -> Mock<'server> {
    server.mock(|when, then| {
        when.method(POST)
            .path(api_path)
            .header("content-type", "application/json")
            .json_body(json!(request_payload));
        then.status(200)
            .header("content-type", "text/html")
            .json_body(json!(response_payload));
    })
}

pub(crate) fn validate_contract<P, A, R, E>(
    api_endpoint: &str,
    request_payload: P,
    expected_response_path: &str,
    action: A,
) -> MockServer
where
    P: Serialize,
    R: Debug + DeserializeOwned + PartialEq + Serialize,
    A: Fn(P, FilenSettings) -> Result<R, E>,
    E: Debug,
{
    let (server, filen_settings) = init_server();
    let expected_response: R = deserialize_from_file(expected_response_path);
    let mock = setup_json_mock(api_endpoint, &request_payload, &expected_response, &server);

    let response = action(request_payload, filen_settings);

    mock.assert_hits(1);
    assert!(response.is_ok());
    assert_eq!(response.unwrap(), expected_response);
    server
}

pub(crate) async fn validate_contract_async<P, A, R, E, F>(
    api_endpoint: &str,
    request_payload: P,
    expected_response_path: &str,
    action: A,
) -> MockServer
where
    P: Serialize,
    R: Debug + DeserializeOwned + PartialEq + Serialize,
    A: Fn(P, FilenSettings) -> F,
    E: Debug,
    F: futures::Future<Output = Result<R, E>>,
{
    let (server, filen_settings) = init_server();
    let expected_response: R = deserialize_from_file(expected_response_path);
    let mock = setup_json_mock(api_endpoint, &request_payload, &expected_response, &server);

    let response = action(request_payload, filen_settings).await;

    mock.assert_hits(1);
    assert!(response.is_ok());
    assert_eq!(response.unwrap(), expected_response);
    server
}
