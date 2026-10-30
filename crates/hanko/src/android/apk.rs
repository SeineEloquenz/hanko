use std::path::Path;

use tokio::process::Command;

use super::Keystore;
use super::tool::{self, Error};

pub async fn package_name(apk: &Path) -> Result<String, Error> {
    let mut command = Command::new("aapt2");
    command.args(["dump", "packagename"]).arg(apk);
    tool::run("aapt2", command).await
}

pub async fn sign(keystore: &Keystore, input: &Path, output: &Path) -> Result<(), Error> {
    let mut sign = Command::new("apksigner");
    sign.arg("sign")
        .arg("--ks")
        .arg(&keystore.path)
        .arg("--ks-key-alias")
        .arg(&keystore.alias)
        .arg("--ks-pass")
        .arg(format!("file:{}", keystore.store_password_file.display()));
    if let Some(key_password) = &keystore.key_password_file {
        sign.arg("--key-pass")
            .arg(format!("file:{}", key_password.display()));
    }
    sign.arg("--out").arg(output).arg(input);
    tool::run("apksigner sign", sign).await?;

    let mut verify = Command::new("apksigner");
    verify.arg("verify").arg(output);
    tool::run("apksigner verify", verify).await?;
    Ok(())
}
