# Library to call Filen.io API from Rust

[Filen.io](https://filen.io) is a cloud storage provider with an open-source [desktop client](https://github.com/FilenCloudDienste/filen-desktop). My goal is to write a library which calls Filen's API in a meaningful way, and to learn Rust in process. Filen's API is currently undocumented and I try to get it right by studying the client's sources, so take it all with a grain of salt.

This library is **not in a usable state**. Most of the crypto stuff is implemented and you can login and receive all the keys, but that's it for now.

## 
```
use crate::{auth_v1, settings::FilenSettings, crypto::FilenPasswordWithMasterKey};
use anyhow::*;
use secstr::SecUtf8;

fn how_login_may_look() -> Result<LoginResponseData> {
    let user_email = "registered.user@email.com".to_owned();
    let user_password = SecUtf8::from("user.password");
    let user_two_factor_key = SecUtf8::from("XXXXXX"); // Filen actually uses XXXXXX when 2FA is absent.

    let filen_settings = FilenSettings::default();
    let auth_info_request_payload = auth_v1::AuthInfoRequestPayload {
        email: user_email.clone(),
        two_factor_key: user_two_factor_key.clone(),
    };
    let auth_info_response = auth_v1::auth_info_request(&auth_info_request_payload, &filen_settings)?;
    if !auth_info_response.status || auth_info_response.data.is_none() {
        bail!("Filen API failed to return auth info: {}", auth_info_response.message);
    }
    let auth_info_response_data = auth_info_response.data.unwrap();
    let filen_password_and_m_key = match auth_info_response_data.auth_version {
        1 => FilenPasswordWithMasterKey::from_user_password(&user_password),
        2 => {
            let filen_salt = SecUtf8::from(auth_info_response_data.salt.unwrap_or_else(|| String::new()));
            FilenPasswordWithMasterKey::from_user_password_and_auth_info_salt(&user_password, &filen_salt)
        }
        _ => bail!("Unsupported auth version"),
    };

    let login_request_payload = auth_v1::LoginRequestPayload {
        email: user_email,
        password: filen_password_and_m_key.sent_password,
        two_factor_key: user_two_factor_key.clone(),
        auth_version: 1,
    };
    let login_response = auth_v1::login_request(&login_request_payload, &filen_settings)?;
    if !login_response.status || login_response.data.is_none() {
        bail!("Filen API failed to login: {}", auth_info_response.message);
    }

    Ok(login_response.data.unwrap())
}
```