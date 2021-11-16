# rust_filen  &emsp; [![Build Status]][actions] [![Latest Version]][crates.io]

[Build Status]: https://img.shields.io/github/workflow/status/EnoughTea/rust-filen/CI/main
[actions]: https://github.com/EnoughTea/rust-filen/actions?query=branch%3Amain
[Latest Version]: https://img.shields.io/crates/v/rust_filen.svg
[crates.io]: https://crates.io/crates/rust_filen

This is a library to call Filen.io API from Rust.

[Filen.io](https://filen.io) is a cloud storage provider with an open-source [desktop client](https://github.com/FilenCloudDienste/filen-desktop). My goal was to write a library which calls Filen's API in a meaningful way, and to learn Rust in process.
Filen's API was undocumented at time of writing and I tried to get it right by studying the client's sources, so take it all with a grain of salt.

This library is in a usable yet unpolished state. It is possible to make almost every imaginable Filen query:
you can login, receive users RSA keys, view user's options and events,
perform CRUD on files and folders, list Filen Sync folder/trash folder/recent files contents,
download and decrypt files, encrypt and upload files, and share/link files/folders with helpers for recursion.

Some obscure user-specific API queries are unimplemented and documentation is almost non-existent, sorry about that.
If you need to call missing API query, you can do so with `rust_filen::queries::query_filen_api("/v1/some/uimplemented/api/path", any_serde_serializable_payload, filen_settings)`.

## Optional async

By default, all queries are synchronous and performed with [ureq](https://github.com/algesten/ureq).

If you want, you can enable async versions of every API query and a way to retry them, `RetrySettings::call_async`.
To do so, set `features = ["async"]` for this library in your `Cargo.toml`.
As a result, [reqwest](https://github.com/seanmonstar/reqwest) will be used instead of [ureq](https://github.com/algesten/ureq).


## Some examples

All Filen API requests are named by their original URL with `_request` appended at the end.
Usually requests have associated `*RequestPayload` struct, which corresponds to original sent JSON, and
`*ResponsePayload` struct, which corresponds to JSON response.
For example, `/v1/user/baseFolders` request will be performed by
`rust_filen::v1::user_base_folders_request` and `UserBaseFoldersRequestPayload`, with response stored in `UserBaseFoldersResponsePayload`.

If you are interested, below is a series of small demos with all you need to know to start doing stuff with Filen.
Start by importing all we need for exemplary purposes:

```rust
use rust_filen::{*, v1::*};
// All Filen API queries and related structs are in v1::*,
// while rust_filen::* provides FilenSettings, RetrySettings and their bundle
// for convenience, aptly called SettingsBundle.
// Also, for advanced usage, there are rust_filen::crypto
// with crypto-functions to encrypt/decrypt various Filen metadata and
// rust_filen::queries as a way to define your own Filen API queries.
use rust_filen::secstr::SecUtf8;
use rust_filen::uuid::Uuid;
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
 // Filen actually uses XXXXXX when 2FA is absent.
let user_two_factor_key = SecUtf8::from("XXXXXX");
let settings = STANDARD_SETTINGS_BUNDLE.clone();
let filen_settings = settings.filen;  // Provides Filen server URLs.

let auth_info_request_payload = AuthInfoRequestPayload {
    email: user_email.clone(),
    two_factor_key: user_two_factor_key.clone(),
};
let auth_info_response = auth_info_request(&auth_info_request_payload, &filen_settings)?;
if !auth_info_response.status {
    panic!("Filen API failed to return auth info: {:?}", auth_info_response.message);
}
let auth_info_response_data = auth_info_response.data_or_err()?;

// `filen_password_with_master_key` helper calculates Filen password for us,
// depending on returned auth_info_response_data.
let filen_password_and_m_key = auth_info_response_data
    .filen_password_with_master_key(&user_password)?;
```


### Logging in

```rust
// Now that we have Filen password, we can login. Master key is not needed for login,
// but is also very important, since it is used often throughout the API to encrypt/decrypt metadata.
let login_request_payload = LoginRequestPayload {
    email: user_email.clone(),
    password: filen_password_and_m_key.sent_password.clone(),
    two_factor_key: user_two_factor_key.clone(),
    auth_version: auth_info_response_data.auth_version,
};
let login_response = login_request(&login_request_payload, &filen_settings)?;
if !login_response.status {
    panic!("Filen API failed to login: {:?}", auth_info_response.message);
}

// Login confirmed, now you can take API key and user's master key from the LoginResponseData
// and go perform some API calls!
let login_response_data = login_response.data_or_err()?;

// Api key is needed for almost every call to Filen API, so it's a must have.
let api_key = login_response_data.api_key;

// Last master key is used for encryption of user's private data.
let last_master_key = filen_password_and_m_key.m_key;

// List of all user's master keys is used for decryption of user's private data.
// New master key is generated by Filen each time user changes password,
// so when decrypting previously encrypted user data we have to try not
// only the last master key, but all of the previous keys as well.
let master_keys = login_response_data.decrypt_master_keys_metadata(&last_master_key)?;
```


### Gettings user's default folder

```rust
// Let's start by finding user's default folder:
let user_dir_request_payload = UserDirsRequestPayload {
    api_key: api_key.clone(),
};
let user_dirs_response = user_dirs_request(&user_dir_request_payload, &filen_settings)?;
if !user_dirs_response.status {
    panic!(
        "Filen API failed to provide user dirs: {:?}",
        user_dirs_response.message
    );
}

// This is just a convenience helper, 
// you can iterate folders in user_dirs_response.data yourself:
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
if !download_dir_response.status {
    panic!(
        "Filen API failed to provide default folder contents: {:?}",
        download_dir_response.message
    );
}
// Again, this is just a helper method, feel free to decrypt metadata for every FileData yourself.
let download_dir_response_data = download_dir_response.data_or_err()?;
let default_folder_files_and_properties =
    download_dir_response_data.decrypt_all_file_properties(&master_keys)?;
```


### Downloading and decrypting a file

```rust
// Let's say user has a file 'some file.png' located in the default folder.
// Let's find and download it:
let (some_file_data, some_file_properties) = default_folder_files_and_properties
    .iter()
    .find(|(data, properties)|
        data.parent == default_folder_data.uuid &&
        properties.name.eq_ignore_ascii_case("some file.png"))
    .unwrap();
let file_key = some_file_properties.key.clone();

// Let's store file in-memory via writer over vec:
let mut file_writer = std::io::BufWriter::new(Vec::new());

// STANDARD_SETTINGS_BUNDLE earlier contained `retry` field with STANDARD_RETRIES,
// which retry 5 times with 1, 2, 4, 8 and 15 seconds pause
// between retries and some random jitter.
// Usually RetrySettings is opt-in, you call `RetrySettings::call` yourself
// when needed for every API query you want retried.
//
// File is downloaded or uploaded as a sequence of chunks,
// and a query to download or upload any one of them can fail.
// With external retries, if the last chunk fails, you'll have to redo the entire file.
// Internal retry logic avoid possible needless work.
//
// For this reason, file download/upload and other complex helper methods 
// with chains of Filen API queries inside, require reference to RetrySettings
// in addition to usual FilenSettings.
// So file download below uses settings bundle we defined earlier, which contains them: 
let sync_file_download_result = download_and_decrypt_file_from_data_and_key(
    some_file_data,
    &file_key,
    &mut file_writer,
    &settings,
);

// And now we have downloaded and decrypted bytes in memory.
let file_bytes = sync_file_download_result.map(|_| file_writer.into_inner().unwrap())?;
```


### Uploading an encrypted file

```rust
// First let's define the file we will upload:
let file_path = <std::path::PathBuf as std::str::FromStr>::from_str(
    "D:\\file_path\\some_file.txt")?;

// Then let's define where the file will be uploaded on Filen. 
// If you're wondering how you can check Filen folder IDs to choose folder to upload to,
// check previous section "Gettings user's default folder" or queries with 'dir' in their names,
// like `user_dirs_request` and `dir_content_request`.
let parent_folder_id = "cf2af9a0-6f4e-485d-862c-0459f4662cf1"; 

// Prepare file properties like file size and mime type for Filen.
// 'some_file.txt' is specified again here, because you can change uploaded file name if you want: 
let file_properties =
    FileProperties::from_name_and_local_path("some_file.txt", &file_path)?;

// `file_version` determines how file bytes should be encrypted/decrypted,
// for now Filen uses version = 1 everywhere.
let file_version = 1;

// Now open a file into a reader, so encrypt_and_upload_file() can read file bytes later: 
let mut file_reader = std::io::BufReader::new(std::fs::File::open(file_path.to_str()?)
    .expect("Unable to open file"));

// We're all done:
let upload_result = encrypt_and_upload_file(
    &api_key,
    parent_folder_id,
    &file_properties,
    file_version,
    &last_master_key,
    &mut file_reader,
    &settings,
);
```

### Creating a new folder

```rust
// All folders in Filen can be divided into 'base' and 'non-base'.
// Base folders are called "cloud drives" in the web manager,
// non-base folders are your usual folders.
// 
// So let's create a new cloud drive, where we will put a new folder.
// But before creating something new, you should always check if it's name is free to use.
// 
// Since we will be creating 2 folders, it would be wise to put
// this check into a separate helper function:
fn folder_exists(
    api_key: &SecUtf8,
    // ParentOrBase defines whether to seek folder_name among base folders or
    // in the given parent folder. 
    parent: ParentOrBase,
    // Plain-text folder name.
    filen_settings: &FilenSettings,
) -> Result<bool> {
    let folder_exists_payload =
        LocationExistsRequestPayload::new(api_key.clone(), parent, folder_name);
    dir_exists_request(&folder_exists_payload, filen_settings)?
        .data_or_err()?
        .exists;
}

// Alright, now we have everything we need to create some folders.
let new_base_folder_name = "New cloud drive";

// Check that base folder with name "New cloud drive" does not exist already.
if folder_exists(&api_key, ParentOrBase::Base, new_base_folder_name, &filen_settings)? {
    panic!("Folder {} already exists!", new_base_folder_name)
}

// No "New cloud drive" base folder exists, so create one. Prepare request payload first:
let create_base_folder_payload =
    DirCreateRequestPayload::new(api_key.clone(), new_base_folder_name, &last_master_key);

// New folder ID is random, so get hold of it.
let created_base_folder_uuid = create_base_folder_payload.uuid;

// Finally, create "New cloud drive" base folder,
// dir_create_request used for base folder creation.
let create_base_folder_result = dir_create_request(&create_base_folder_payload, &filen_settings)?;
if !create_base_folder_result.status {
    panic!(
        "Filen API failed to create base folder: {:?}",
        create_base_folder_result.message
    );
}

// Now lets create "This is a new folder" folder inside freshly
// created "New cloud drive" base folder.
// Good thing we stored base folder ID in `created_base_folder_uuid`, 
// we're going to pass it as a parent.
// 
// Again, check folder for existence first:
let new_folder_name = "This is a new folder";
if folder_exists(
    &api_key,
    ParentKind::Folder(created_base_folder_uuid.clone()),
    new_folder_name,
    &filen_settings,
)? {
    panic!("Folder {} already exists!", new_folder_name)
}

// Everything should make sense by now. 
// Usual folders are created with `dir_sub_create_request`:
let folder_payload = DirSubCreateRequestPayload::new(
    api_key.clone(),
    new_folder_name,
    created_base_folder_uuid,
    &last_master_key,
);
let create_folder_result = dir_sub_create_request(&folder_payload, &filen_settings)?;
if !create_folder_result.status {
    panic!("Filen API failed to create folder: {:?}", create_folder_result.message);
}
```


### Sharing a file 

```rust
// To share a file, we need to know UUIDs of the file and its parent.
// Often these come from `download_dir_request`, but assume we have UUIDs already.
// There we have ID of the file we want to share.
let shared_file_uuid = Uuid::parse_str("e132fbc4-22c9-4ee6-af91-f53f8855a65b")?;

// And this is ID of its parent folder. Our shared file is located in a root,
// so its parent is a base folder. So in the context of this tutorial 'cf2a...2cf1' uuid below
// refers to a 'Default' Filen cloud drive.
let shared_file_parent_uuid = Uuid::parse_str("cf2af9a0-6f4e-485d-862c-0459f4662cf1")?;

// Email of the user we want to share the file with.
let receiver_email = "file.receiver@test.com";

// Before sharing the file with the user, we need to know said user's RSA public key,
// so we can use it to encode shared file's metadata.
// Public key can be ferched with `user_public_key_get_request`, it's straightforward:
let get_public_key_payload = UserPublicKeyGetRequestPayload {
    email: receiver_email.to_owned(),
};
let user_public_key_get_response = user_public_key_get_request(&get_public_key_payload, &filen_settings)?;
if !user_public_key_get_response.status {
    panic!(
        "Filen API failed to get user's public key: {:?}",
        user_public_key_get_response.message
    );
}
let receiver_key_data = user_public_key_get_response.data_or_err()?;
// Now receiver_key_data.public_key contains base64-encoded public key,
// so let's use a helper method to get key bytes:
let receiver_public_key = receiver_key_data.decode_public_key()?;
// Having user's public key, we can start sharing the file.
// However, having just a file UUID won't be sufficient, we need to have file metadata as well.
// So let's fetch files from parent folder and find our target file metadata:
let download_dir_payload = DownloadDirRequestPayload {
    api_key: api_key.clone(),
    uuid: shared_file_parent_uuid,
};
let dir_content_response = download_dir_request(&download_dir_payload, &filen_settings)?;
if !dir_content_response.status {
    panic!(
        "Filen API failed to get folder contents: {:?}",
        dir_content_response.message
    );
}
let contents = dir_content_response.data_or_err()?;
// Find file description:
let shared_file = contents
    .file_with_uuid(&shared_file_uuid)
    .ok_or_else(|| "Parent folder does not contain shared file")?;
// Decrypt file metadata to the file properties.
let shared_file_properties = shared_file.decrypt_file_metadata(&master_keys)?;

// Finally, we are all set to share the file.
// Properly executed share queries are idempotent-ish, so there is no need
// to check if file is shared or not. But if you want, you can see
// with whom the file is shared by calling `user_shared_item_status_request`:
let file_share_status_payload = UserSharedItemStatusRequestPayload {
    api_key: api_key.clone(),
    uuid: shared_file_uuid.clone(),
};
let file_share_status_response =
    user_shared_item_status_request(&file_share_status_payload, &filen_settings)?;
// `file_shared_with` below should be empty now, but if file was already shared,
// there would be several user records, often with duplicates.
let file_shared_with = file_share_status_response.data_or_err()?.users;

// Alright, back to sharing the file.
// When sharing items, Filen expects special parent notation.
// If an item's parent is a base folder, no UUID is needed, pass "none" instead.
// 
// As you can recall, in this tutorial shared file is rooted,
// and `shared_file_parent_uuid` refers to a base folder. So instead of passing
// `ParentOrNone::Folder(shared_file_parent_uuid)`to share_request() call,
// we should pass `ParentOrNone::None`.
// 
// See `user_base_folders_request` query for a way to fetch base folders
// and check if file parent is a base folder or not.
let share_payload = ShareRequestPayload::from_file_properties(
    api_key.clone(),
    shared_file_uuid,
    &shared_file_properties,
    ParentOrNone::None,
    receiver_email.to_owned(),
    &receiver_public_key,
)?;
let share_response = share_request(&share_payload, &filen_settings)?;
if !share_response.status {
    panic!("Filen API failed to share file: {:?}", share_response.message);
}
```


### Sharing a folder

```rust
// If you share a folder which contains other folders or files,
// you need to share all those sub-items manually. However, rust_filen has a helper
// method that does it for you. Just take some folder to share and feed it to
// `share_folder_recursively(_async)`:
let folder_to_share = Uuid::parse_str("3a15c71c-762b-43d3-99d6-c484093b9db5")?;
let share_folder_recursively_result = share_folder_recursively(
    &api_key,
    folder_to_share,
    receiver_email,
    &receiver_public_key,
    &master_keys,
    &settings,
)
```


### Linking a file

```rust
// First of all, creating a public link for a file and
// adding a file to existing folder link so it can be seen inside linked folder
// are two different concepts.
// 
// File links are "global": they are always present and not attached to any linked folder,
// but can be disabled or enabled. 
// At any given time only one file link can be enabled, so it is not possible
// to link the same file two times with different settings.
// 
// For this example, let's toggle file's global public link:
// disable file's link if it is already enabled, and vice-versa.
//
// Start by checking current file link status:
let linked_file_uuid = Uuid::parse_str("e132fbc4-22c9-4ee6-af91-f53f8855a65b")?;
let link_status_payload = LinkStatusRequestPayload {
    api_key: api_key.clone(),
    file_uuid: linked_file_uuid.clone(),
};
let link_status_response = link_status_request(&link_status_payload, &filen_settings)?;
let link_status_data = link_status_response.data_or_err()?;
// LinkEditRequestPayload::(disabled|enabled) are helper methods
// to create a payload used disable or enable file link.
let toggle_payload = if link_status_data.enabled && link_status_data.uuid.is_some() {
    LinkEditRequestPayload::disabled(api_key.clone(), linked_file_uuid, link_status_data.uuid.unwrap())
} else {
    LinkEditRequestPayload::enabled(
        api_key.clone(),
        linked_file_uuid,
        DownloadBtnState::Enable,
        Expire::Never,
        None,
        None,
    )
};
// This is it, file link will be enabled or disabled depending on its current status.
let response = link_edit_request(&toggle_payload, &filen_settings)?;
if !response.status {
    panic!("Filen API failed to edit file link: {:?}", response.message)
}
```


### Linking a folder

```rust
// Again, creating a public link for a folder and
// adding a folder to existing folder link so it can be seen inside linked folder
// are two different concepts.
//
// Unlike file links, folder links are not global and multiple links with different settings
// can be created to the same folder.
//
// If you want to create a folder link for a folder which contains other folders or files,
// you need to link all those sub-items manually. However, rust_filen has a helper
// method that does it for you. Just take some folder to share and feed it to
// `link_folder_recursively(_async)`:
let linked_folder_uuid = Uuid::parse_str("3a15c71c-762b-43d3-99d6-c484093b9db5")?;
link_folder_recursively(
    &api_key,
    linked_folder_uuid,
    master_keys,
    &settings,
)?
```

### There is encrypted metadata everywhere, what to do?

Sooner or later you will encounter properties with "metadata" in their names and encrypted strings for their values.
Quite often there are helper methods on structs with such properties which can be used to decrypt it easily.
If not, you should know that "metadata" is a Filen way to encrypt any sensitive info, and there are 3 general ways of dealing with it:

1. User's data intended only for that user to use, like file properties and folder names, can be decrypted/encrypted with `rust_filen::crypto::decrypt_metadata_str`/ `rust_filen::crypto::encrypt_metadata_str` using user's last master key.
2. User's data intended to be public, like shared or publicly linked file properties. 
Shared and linked item metadata are treated differently. Shared item metadata can be encrypted by
`rust_filen::crypto::encrypt_rsa` using target user RSA public key, and decrypted by
`rust_filen::crypto::decrypt_rsa` using target user RSA private key file. This can be pretty confusing when sharing files.
You will need to keep in mind who is currently the sharer and who is the receiver,
so receiver's metadata needs to be encrypted with receiver's public key, so it can decipher it later with its private key.
3. Linked item metadata is treated like user's private data in list item #1, only with link key instead of user's last master key.

Check `FileProperties::encrypt_file_metadata(_rsa)`/`FileProperties::decrypt_file_metadata(_rsa)`
for a convenient way to encrypt&decrypt file properties. Note that folder properties consist of just folder name, so
`LocationNameMetadata::encrypt_name_to_metadata(_rsa)`/`LocationNameMetadata::decrypt_name_to_metadata(_rsa)`
can be used to encrypt&decrypt folder/file names.


### That's all, folks!

This is it for examples, at least for now.
To dig deeper, you might want to check out https://filen.io/assets/js/fm.min.js and
https://filen.io/assets/js/app.min.js for Filen API usage patterns.