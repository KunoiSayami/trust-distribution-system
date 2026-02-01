use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use crate::types::{KeyStore, RawKeyStore};

pub fn open_file_and_read<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<u8>> {
    let mut file_to_sign = File::open(path)?;

    let mut buff = vec![];
    file_to_sign.read_to_end(&mut buff)?;

    Ok(buff)
}

pub fn write_to_file<P: AsRef<Path>>(path: P, content: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    file.write_all(content)?;
    Ok(())
}

pub fn load_key<P: AsRef<Path>>(path: P) -> anyhow::Result<RawKeyStore> {
    let f = open_file_and_read(path)?;
    Ok(serde_json::from_slice(&f)?)
}

pub fn write_key<P: AsRef<Path> + Debug>(
    path: P,
    key_override: bool,
    key: &KeyStore,
) -> std::io::Result<()> {
    if path.as_ref().exists() && key_override {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("File exists in {path:?}"),
        ));
    }

    write_to_file(path, serde_json::to_string(key).unwrap().as_bytes())?;
    Ok(())
}
