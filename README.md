# Library to call Filen.io API from Rust

[Filen.io](https://filen.io) is a cloud storage provider with an open-source [desktop client](https://github.com/FilenCloudDienste/filen-desktop). My goal is to write a library which calls Filen's API in a meaningful way, and to learn Rust in process. Filen's API is currently undocumented and I try to get it right by studying the client's sources, so take it all with a grain of salt.

This library is **not in a usable state**. All of the crypto stuff and a subset of API is implemented, but it is still incomplete.

It is possible to login, receive user's RSA keys and perform CRUD on folders, but that's it for now.

## 
```
use crate::{v1::auth, settings::FilenSettings};
use anyhow::*;
use secstr::SecUtf8;

fn simple_login() -> Result<auth::LoginResponseData> {
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
        bail!("Filen API failed to return auth info: {}", auth_info_response.message);
    }
    let auth_info_response_data = auth_info_response.data.unwrap();
    let filen_password_and_m_key = auth_info_response_data.filen_password_with_master_key(&user_password);
    
    // Now that we have Filen password, we can login. Master key is not needed for login, but is also very important,
    // since it is used often throughout the API to encrypt/decrypt metadata.
    let login_request_payload = auth::LoginRequestPayload {
        email: user_email.clone(),
        password: filen_password_and_m_key.sent_password.clone(),
        two_factor_key: user_two_factor_key.clone(),
        auth_version: auth_info_response_data.auth_version,
    };
    let login_response = auth::login_request(&login_request_payload, &filen_settings)?;
    if !login_response.status || login_response.data.is_none() {
        bail!("Filen API failed to login: {}", auth_info_response.message);
    }
    // Login confirmed, now you can take API key from the LoginResponseData and go do everything*
    Ok(login_response.data.unwrap())
}
// * Everything means creating/moving/renaming/trashing folders for now.
```