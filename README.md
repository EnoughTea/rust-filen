# Library to call Filen.io API from Rust

[Filen.io](https://filen.io) is a cloud storage provider with an open-source [desktop client](https://github.com/FilenCloudDienste/filen-desktop). My goal was to write a library which calls Filen's API in a meaningful way, and to learn Rust in process.
Filen's API is currently undocumented and I try to get it right by studying the client's sources, so take it all with a grain of salt.

This library is in a usable yet unpolished state. It is possible to login, receive users RSA keys,
perform CRUD on files and folders, list Filen Sync folder/trash folder/recent files contents,
download and decrypt files, encrypt and upload files, and share/link files and folders.

Various user-specific API queries are still unimplemented and documentation is lacking, sorry about that.
If you need to call missing API query, you can do so with `rust_filen::queries::query_filen_api("/v1/some/uimplemented/api/path", any_serde_serializable_payload, filen_settings)`.

I have not published `rust_filen` yet, but chances are you would want to depend on its sources anyway.

## Optional async

By default, all queries are synchronous and performed with [ureq](https://github.com/algesten/ureq).

If you want, you can enable async versions of every API query and a way to retry them, `RetrySettings::retry_async`.
To do so, set `features = ["async"]` for this library in your `Cargo.toml`.
As a result, [reqwest](https://github.com/seanmonstar/reqwest) will be used instead of [ureq](https://github.com/algesten/ureq).


## Some examples

If you're interested, that's how it all looks. Start by importing all we need for exemplary purposes:

```rust
use rust_filen::{*, v1::*};
// All Filen API queries and related structs are in v1::*,
// while rust_filen::* provides FilenSettings and RetrySettings. Also, for advanced usage, there are rust_filen::crypto
// with crypto-functions to encrypt/decrypt various Filen metadata and
// rust_filen::queries as a way to define your own Filen API queries.
use anyhow::bail;  // bail is used for demo purposes, it's not really needed.
use secstr::SecUtf8;
```

While we are on the topic of imports, `rust_filen` re-exports all third-party crates used in public functions.
Namely `rust_filen::ureq`, `rust_filen::reqwest`, `rust_filen::fure`, `rust_filen::retry`, `rust_filen::secstr` and `rust_filen::uuid`.

Anyway, let's login first.

### Getting auth info

Actually, before logging in, we have to know how to do so.

```rust
// First let's calculate Filen password used for logging in.
// For that we need to know user's password, of course,
// and 'version' number which tells us which encryption algorithm to use.
// To get it all, call `/auth/info` endpoint:
let user_email = SecUtf8::from("registered.user@email.com");
let user_password = SecUtf8::from("user.password.in.plaintext");
let user_two_factor_key = SecUtf8::from("XXXXXX"); // Filen actually uses XXXXXX when 2FA is absent.
let filen_settings = FilenSettings::default();  // Provides Filen server URLs.

let auth_info_request_payload = auth::AuthInfoRequestPayload {
    email: user_email.clone(),
    two_factor_key: user_two_factor_key.clone(),
};
let auth_info_response = auth::auth_info_request(&auth_info_request_payload, &filen_settings)?;
if !auth_info_response.status || auth_info_response.data.is_none() {
    bail!("Filen API failed to return auth info: {:?}", auth_info_response.message);
}
let auth_info_response_data = auth_info_response.data.unwrap();
// filen_password_with_master_key() helper calculates Filen password for us,
// depending on returned auth_info_response_data.
let filen_password_and_m_key = auth_info_response_data
    .filen_password_with_master_key(&user_password)
    .unwrap();
```

### Logging in

```rust
// Now that we have Filen password, we can login. Master key is not needed for login,
// but is also very important, since it is used often throughout the API to encrypt/decrypt metadata.
let login_request_payload = auth::LoginRequestPayload {
    email: user_email.clone(),
    password: filen_password_and_m_key.sent_password.clone(),
    two_factor_key: user_two_factor_key.clone(),
    auth_version: auth_info_response_data.auth_version,
};
let login_response = auth::login_request(&login_request_payload, &filen_settings)?;
if !login_response.status || login_response.data.is_none() {
    bail!("Filen API failed to login: {:?}", auth_info_response.message);
}
// Login confirmed, now you can take API key and user's master key from the LoginResponseData
// and go perform some API calls!
let login_response_data = login_response.data.unwrap();
let api_key = login_response_data.api_key;
let last_master_key = filen_password_and_m_key.m_key;
// Just using filen_password_and_m_key.m_key everywhere as is not correct,
// but it will work for the demo purposes.
let user_master_keys = &[last_master_key.clone()];
```

### Gettings user's default folder

```rust
// Let's start by finding user's default folder:
let user_dir_request_payload = UserDirsRequestPayload {
    api_key: api_key.clone(),
};
let user_dirs_response = user_dirs_request(&user_dir_request_payload, &filen_settings)?;
if !user_dirs_response.status || user_dirs_response.data.is_empty() {
    bail!(
        "Filen API failed to provide user dirs: {:?}",
        user_dirs_response.message
    );
}
// That's just a convenience helper, you can iterate folders in user_dirs_response.data yourself
let default_folder_data = user_dirs_response.find_default_folder().unwrap();
```

### Getting remote folder contents

```rust
// Alright, we have our default folder, let's check out its contents.
let download_dir_request_payload = DownloadDirRequestPayload {
    api_key: api_key.clone(),
    uuid: default_folder_data.uuid,
};
let download_dir_response = download_dir_request(&download_dir_request_payload, &filen_settings)?;
if !download_dir_response.status || download_dir_response.data.is_none() {
    bail!(
        "Filen API failed to provide default folder contents: {:?}",
        download_dir_response.message
    );
}
// Again, this is just a helper method, feel free to decrypt metadata for every FileData yourself.
let download_dir_response_data = download_dir_response.data.unwrap();
let default_folder_files_and_properties = download_dir_response_data.decrypt_all_file_properties(user_master_keys)?;
```

### Downloading and decrypting a file

```rust
// Let's say user has a file 'some file.png' located in the default folder. Let's find and download it:
let (some_file_data, some_file_properties) = default_folder_files_and_properties
    .iter()
    .find(|(data, properties)|
        data.parent == default_folder_data.uuid && properties.name.eq_ignore_ascii_case("some file.png"))
    .unwrap();
let file_key = some_file_properties.key.clone();
// Let's store file in-memory via writer over vec:
let mut file_buffer = std::io::BufWriter::new(Vec::new());
// STANDARD_RETRIES retry 5 times with 1, 2, 4, 8 and 15 seconds pause between retries and some random jitter.
// Usually RetrySettings is opt-in, you call RetrySettings::retry yourself when needed for every API query you want retried.
// But file download/upload are helper methods where providing RetrySettings is mandatory.
// File is downloaded or uploaded as a sequence of chunks, and any one of them can fail.
// With external retries, if the last chunk fails, you'll have to redo the entire file.
// Internal retry logic avoid possible needless work.
let retry_settings = RetrySettings::STANDARD_RETRIES;
let sync_file_download_result = download_and_decrypt_file_from_data_and_key(
    &some_file_data,
    &file_key,
    &retry_settings,
    &filen_settings,
    &mut file_buffer,
);
// And now we have downloaded and decrypted bytes in memory.
let file_bytes = sync_file_download_result.map(|_| file_buffer.into_inner().unwrap());
```

### Uploading an encrypted file

```rust
// First let's define the file we will upload:
let file_path = <std::path::PathBuf as std::str::FromStr>::from_str("D:\\file_path\\some_file.txt").unwrap();
// Then let's define where the file will be uploaded on Filen. 
// If you're wondering how you can check Filen folder IDs to choose folder to upload to, check previous section
// 'Gettings user's default folder' or queries with "dir" in their names,
// like user_dirs_request() and dir_content_request().
let parent_folder_id = "cf2af9a0-6f4e-485d-862c-0459f4662cf1"; 
// Prepare file properties like file size and mime type for Filen.
// 'some_file.txt' is specified again here, because you can change uploaded file name if you want: 
let file_properties = FileProperties::from_name_and_local_path("some_file.txt", &file_path).unwrap();
/// 'file_version' determines how file bytes should be encrypted/decrypted, for now Filen uses version = 1 everywhere.
let file_version = 1;
// Now open a file into a reader, so encrypt_and_upload_file() can read file bytes later: 
let mut file_reader =
    std::io::BufReader::new(std::fs::File::open(file_path.to_str().unwrap()).expect("Unable to open file"));
// We're all done:
let upload_result = encrypt_and_upload_file(
    &api_key,
    parent_folder_id,
    &file_properties,
    file_version,
    &last_master_key,
    &retry_settings,
    &filen_settings,
    &mut file_reader,
);
```

### There is encrypted metadata everywhere, what to do?

Sooner or later you will encounter properties with "metadata" in their names and encrypted strings for their values.
Quite often there are helper methods on structs with such properties which can be used to decrypt it easily.
If not, you should know that "metadata" is a Filen way to encrypt any sensitive info, and there are two general ways of dealing with it:

1. User's data intended only for that user to use, like file properties and folder names, can be decrypted/encrypted with `rust_filen::crypto::decrypt_metadata_str`/ `rust_filen::crypto::encrypt_metadata_str` using user's last master key.
2. User's data intended to be public, like shared or publicly linked file properties, can be encrypted by `rust_filen::crypto::encrypt_rsa` using target user RSA public key, and decrypted by `rust_filen::crypto::decrypt_rsa` using target user RSA private key file.
This can be pretty confusing when sharing files. You will need to keep in mind who is currently the sharer and who is the receiver, so receiver's metadata needs to be encrypted with receiver's public key, so it can decipher it later with its private key.


### That's all, folks!

This is it for examples, at least for now.
To dig deeper, you might want to check out https://filen.io/assets/js/fm.min.js and https://filen.io/assets/js/app.min.js for Filen API usage patterns.