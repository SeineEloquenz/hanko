use std::path::Path;

use serde::Serialize;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::auth::Caller;

/// Append-only JSON Lines record of every signature.
pub struct Log {
    file: Mutex<File>,
}

#[derive(Serialize)]
pub struct Entry<'a> {
    pub time: u64,
    pub profile: &'a str,
    pub input_sha256: &'a str,
    pub output_sha256: &'a str,
    pub caller: &'a Caller,
}

impl Log {
    pub async fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Appends `line` and returns once it is on disk.
    pub async fn record(&self, line: &str) -> std::io::Result<()> {
        let line = format!("{line}\n");
        let mut file = self.file.lock().await;
        file.write_all(line.as_bytes()).await?;
        file.flush().await?;
        file.sync_data().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{github_token, verifier};
    use serde_json::{Value, json};

    #[tokio::test]
    async fn appends_one_line_per_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let caller = verifier().verify(&github_token(json!({}))).await.unwrap();
        let log = Log::open(&path).await.unwrap();
        for profile in ["a", "b"] {
            let entry = Entry {
                time: 1,
                profile,
                input_sha256: "in",
                output_sha256: "out",
                caller: &caller,
            };
            log.record(&serde_json::to_string(&entry).unwrap())
                .await
                .unwrap();
        }

        let lines: Vec<Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1]["profile"], "b");
        assert_eq!(lines[1]["caller"]["issuer"], "github");
        assert_eq!(lines[1]["caller"]["repository_id"], 42);
    }
}
