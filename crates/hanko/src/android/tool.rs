use tokio::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("running {tool}: {source}")]
    Spawn {
        tool: &'static str,
        source: std::io::Error,
    },
    #[error("{tool} failed: {output}")]
    Failed { tool: &'static str, output: String },
}

/// Runs `command` to completion and returns its trimmed stdout.
pub async fn run(tool: &'static str, mut command: Command) -> Result<String, Error> {
    let result = command
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|source| Error::Spawn { tool, source })?;
    let stdout = String::from_utf8_lossy(&result.stdout).trim().to_owned();
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        return Err(Error::Failed {
            tool,
            output: format!("{stdout} {}", stderr.trim()).trim().to_owned(),
        });
    }
    Ok(stdout)
}

pub fn on_path(tool: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(tool).is_file()))
}
