# Library to call Filen.io API from Rust

[Filen.io](https://filen.io) is a cloud storage provider with an open-source [desktop client](https://github.com/FilenCloudDienste/filen-desktop). My goal is to write a library which calls Filen's API in a meaningful way, and to learn Rust in process. Filen's API is currently undocumented and I try to get it right by studying the client's sources, so take it all with a grain of salt.

This library is **not in a usable state**. It is possible to login, receive user's RSA keys, perform CRUD on user folders, check Filen Sync folder contents and rename/move/trash files, and even download decrypted files, but file uploading and sharing/linking are still not done.

If you're interested, that's how it looks:

## Some examples

Import all we need for exemplary purposes:
```rust
use crate::{filen_settings::FilenSettings, retry_settings::RetrySettings, v1::auth, v1::fs::*};
use anyhow::*;  // or crate::anyhow::*, it re-exports anyhow just in case
use secstr::SecUtf8;    // or crate::secstr::SecUtf8, it re-exports secstr just in case
```

There are async versions of every API query, but examples will be blocking, this README is big enough as it is.
Let's login first.

### Logging in

```rust
let user_email = SecUtf8::from("registered.user@email.com");
let user_password = SecUtf8::from("user.password.in.plaintext");
let user_two_factor_key = SecUtf8::from("XXXXXX"); // Filen actually uses XXXXXX when 2FA is absent.
let filen_settings = FilenSettings::default();

// First let's get Filen password and master key from user password,
// for that we need to call `/auth/info` endpoint:
let auth_info_request_payload = auth::AuthInfoRequestPayload {
    email: user_email.clone(),
    two_factor_key: user_two_factor_key.clone(),
};
let auth_info_response = auth::auth_info_request(&auth_info_request_payload, &filen_settings)?;
if !auth_info_response.status || auth_info_response.data.is_none() {
    bail!("Filen API failed to return auth info: {:?}", auth_info_response.message);
}
let auth_info_response_data = auth_info_response.data.unwrap();
let filen_password_and_m_key = auth_info_response_data
    .filen_password_with_master_key(&user_password)
    .unwrap();

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
// Just using filen_password_and_m_key.m_key everywhere is not correct,
// but it will work for the demo purposes
let last_master_key = filen_password_and_m_key.m_key;
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
    uuid: default_folder_data.uuid.clone(),
};
let download_dir_response = download_dir_request(&download_dir_request_payload, &filen_settings)?;
if !download_dir_response.status || download_dir_response.data.is_none() {
    bail!(
        "Filen API failed to provide default folder contents: {:?}",
        download_dir_response.message
    );
}
// Again, this is just a helper method, feel free to decrypt metadata for every [DownloadedFileData] yourself.
let download_dir_response_data = download_dir_response.data.unwrap();
let default_folder_files_and_properties = download_dir_response_data.decrypt_all_files(&last_master_key)?;
```

### Downloading and decrypting a file

```rust
// Let's say user has a file 'some file.png' located in the default folder. Let's find and download it:
let (some_file_data, some_file_properties) = default_folder_files_and_properties
    .iter()
    .find(|(data, properties)| data.parent == default_folder_data.uuid && properties.name == "some file.png")
    .unwrap();
let file_key = some_file_properties.key.clone();
// Let's store file in-memory via writer over vec:
let mut file_buffer = std::io::BufWriter::new(Vec::new());
let retry_settings = RetrySettings::from_max_tries(7); // Lucky number.
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

This is it for examples, at least for now.