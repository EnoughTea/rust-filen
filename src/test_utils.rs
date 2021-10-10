use anyhow::*;
use std::env;
use std::path::Path;

use camino::Utf8PathBuf;

use crate::utils;

pub(crate) fn project_path() -> Result<Utf8PathBuf> {
    match env::var("CARGO_MANIFEST_DIR") {
        Ok(val) => Ok(Utf8PathBuf::from(val)),
        _ => {
            let curr_dir = env::current_dir()?;
            Utf8PathBuf::from_path_buf(curr_dir.clone())
                .map_err(|_| anyhow!("Current directory is not a valid UTF-8: {:?}", curr_dir))
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

pub(crate) fn read_project_file(file_path: &str) -> Vec<u8> {
    let target_path = project_path_for(file_path);
    utils::read_file(&target_path).expect(&format!("Cannot read file: {}", target_path))
}
