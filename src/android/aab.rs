use std::path::Path;

use tokio::process::Command;

use super::Keystore;
use super::tool::{self, Error};

pub async fn package_name(bundle: &Path) -> Result<String, Error> {
    let mut command = Command::new("bundletool");
    command
        .args(["dump", "manifest", "--xpath=/manifest/@package"])
        .arg(format!("--bundle={}", bundle.display()));
    tool::run("bundletool", command).await
}

pub async fn sign(keystore: &Keystore, input: &Path, output: &Path) -> Result<(), Error> {
    let mut sign = Command::new("jarsigner");
    sign.arg("-keystore")
        .arg(&keystore.path)
        .arg("-storepass:file")
        .arg(&keystore.store_password_file);
    if let Some(key_password) = &keystore.key_password_file {
        sign.arg("-keypass:file").arg(key_password);
    }
    sign.arg("-signedjar")
        .arg(output)
        .arg(input)
        .arg(&keystore.alias);
    tool::run("jarsigner", sign).await?;

    // jarsigner exits 0 even for unsigned jars and -strict rejects self-signed upload keys,
    // so the English report is checked instead.
    let mut verify = Command::new("jarsigner");
    verify.args(["-J-Duser.language=en", "-verify"]).arg(output);
    let report = tool::run("jarsigner -verify", verify).await?;
    if !report.contains("jar verified.") {
        return Err(Error::Failed {
            tool: "jarsigner -verify",
            output: report,
        });
    }
    Ok(())
}
