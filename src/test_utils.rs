use std::{env, io};

use camino::Utf8PathBuf;

pub(crate) fn project_path() -> io::Result<Utf8PathBuf> {
    match env::var("CARGO_MANIFEST_DIR") {
        Ok(val) => Ok(Utf8PathBuf::from(val)),
        _ => env::current_dir().and_then(|curr_dir| {
            let utf8_conversion = Utf8PathBuf::from_path_buf(curr_dir);
            utf8_conversion.map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
        }),
    }
}

pub(crate) fn project_path_for(path: &str) -> io::Result<String> {
    let root = project_path();
    root.map(|mut proj_dir| {
        proj_dir.push(path);
        proj_dir.to_string()
    })
}
