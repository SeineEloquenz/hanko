mod aab;
mod apk;
mod tool;

use std::path::{Path, PathBuf};

use serde::Deserialize;
use tokio::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Aab,
    Apk,
}

/// A signing key. Passwords are passed to the tools as file paths so they never appear in argv.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keystore {
    pub path: PathBuf,
    pub alias: String,
    pub store_password_file: PathBuf,
    pub key_password_file: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("artifact rejected: {0}")]
    Unreadable(tool::Error),
    #[error("artifact rejected: package is {actual}, expected {expected}")]
    WrongPackage { expected: String, actual: String },
    #[error("signing: {0}")]
    Signing(tool::Error),
}

impl Error {
    /// Whether the uploaded artifact is at fault rather than the server.
    pub const fn is_rejection(&self) -> bool {
        matches!(
            self,
            Self::Unreadable(tool::Error::Failed { .. }) | Self::WrongPackage { .. }
        )
    }
}

/// Fails unless the tools for `format` are on `PATH`, every file of `keystore` is readable,
/// and the keystore opens with its password and holds its alias.
pub async fn preflight(format: Format, keystore: &Keystore) -> std::io::Result<()> {
    let tools: &[&str] = match format {
        Format::Aab => &["bundletool", "jarsigner", "keytool"],
        Format::Apk => &["aapt2", "apksigner", "keytool"],
    };
    if let Some(missing) = tools.iter().find(|tool| !tool::on_path(tool)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{missing} is not on PATH"),
        ));
    }
    let files = [
        Some(&keystore.path),
        Some(&keystore.store_password_file),
        keystore.key_password_file.as_ref(),
    ];
    for path in files.into_iter().flatten() {
        std::fs::File::open(path).map_err(|e| {
            std::io::Error::new(e.kind(), format!("reading {}: {e}", path.display()))
        })?;
    }
    let mut list = Command::new("keytool");
    list.arg("-list")
        .arg("-keystore")
        .arg(&keystore.path)
        .arg("-storepass:file")
        .arg(&keystore.store_password_file)
        .arg("-alias")
        .arg(&keystore.alias);
    tool::run("keytool -list", list)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(())
}

/// Ensures `path` is a well-formed artifact of `format` for package `expected`.
pub async fn verify_package(format: Format, path: &Path, expected: &str) -> Result<(), Error> {
    let actual = match format {
        Format::Aab => aab::package_name(path).await,
        Format::Apk => apk::package_name(path).await,
    }
    .map_err(Error::Unreadable)?;
    if actual != expected {
        return Err(Error::WrongPackage {
            expected: expected.to_owned(),
            actual,
        });
    }
    Ok(())
}

/// Signs `input` into `output` and verifies the result.
pub async fn sign(
    format: Format,
    keystore: &Keystore,
    input: &Path,
    output: &Path,
) -> Result<(), Error> {
    match format {
        Format::Aab => aab::sign(keystore, input, output).await,
        Format::Apk => apk::sign(keystore, input, output).await,
    }
    .map_err(Error::Signing)
}
