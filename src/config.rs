use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use url::Url;

use crate::access::Access;
use crate::android::{Format, Keystore};
use crate::{github, kanidm};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: NonZeroU64,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: NonZeroUsize,
    /// Requests that may wait for a signing slot while holding an upload.
    #[serde(default = "default_max_queued")]
    pub max_queued: usize,
    #[serde(default = "default_timeout_secs")]
    pub upload_timeout_secs: NonZeroU64,
    #[serde(default = "default_timeout_secs")]
    pub queue_timeout_secs: NonZeroU64,
    #[serde(default = "default_timeout_secs")]
    pub signing_timeout_secs: NonZeroU64,
    /// JSON Lines file that receives every signature before the artifact is returned.
    pub audit_log: Option<PathBuf>,
    pub notify_url: Option<Url>,
    pub github: Option<github::Oidc>,
    pub kanidm: Option<kanidm::OAuthClient>,
    pub profiles: HashMap<String, Profile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub format: Format,
    pub package_name: String,
    pub keystore: Keystore,
    pub access: Access,
}

const fn default_max_body_bytes() -> NonZeroU64 {
    NonZeroU64::new(200 * 1024 * 1024).unwrap()
}

const fn default_max_concurrent() -> NonZeroUsize {
    NonZeroUsize::MIN
}

const fn default_max_queued() -> usize {
    4
}

const fn default_timeout_secs() -> NonZeroU64 {
    NonZeroU64::new(300).unwrap()
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("{path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let raw = std::fs::read(path).map_err(|source| Error::Read {
            path: path.to_owned(),
            source,
        })?;
        let config: Self = serde_json::from_slice(&raw).map_err(|source| Error::Parse {
            path: path.to_owned(),
            source,
        })?;
        config.validate().map_err(|reason| Error::Invalid {
            path: path.to_owned(),
            reason,
        })?;
        Ok(config)
    }

    pub const fn upload_timeout(&self) -> Duration {
        Duration::from_secs(self.upload_timeout_secs.get())
    }

    pub const fn queue_timeout(&self) -> Duration {
        Duration::from_secs(self.queue_timeout_secs.get())
    }

    pub const fn signing_timeout(&self) -> Duration {
        Duration::from_secs(self.signing_timeout_secs.get())
    }

    fn validate(&self) -> Result<(), String> {
        for (name, profile) in &self.profiles {
            if !profile.access.allows_any() {
                return Err(format!("profile {name} must allow github, kanidm or both"));
            }
            if profile.access.github.is_some() && self.github.is_none() {
                return Err(format!(
                    "profile {name} allows github, but no github audience is configured"
                ));
            }
            if profile.access.kanidm.is_some() && self.kanidm.is_none() {
                return Err(format!(
                    "profile {name} allows kanidm, but no kanidm issuer is configured"
                ));
            }
            if profile
                .access
                .github
                .as_ref()
                .is_some_and(|github| !github.pins_trusted_context())
            {
                return Err(format!(
                    "profile {name} must pin environment, ref or job_workflow_ref for github"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::ClaimName;
    use serde_json::{Value, json};

    fn config(github: Value, kanidm: Value, access: Value) -> Result<Config, String> {
        let config: Config = serde_json::from_value(json!({
            "listen": "127.0.0.1:8470",
            "github": github,
            "kanidm": kanidm,
            "profiles": {
                "app": {
                    "format": "aab",
                    "package_name": "com.example",
                    "keystore": { "path": "/ks", "alias": "upload", "store_password_file": "/pw" },
                    "access": access,
                }
            }
        }))
        .map_err(|e| e.to_string())?;
        config.validate()?;
        Ok(config)
    }

    fn github_oidc() -> Value {
        json!({ "audience": "https://sign.example" })
    }

    fn kanidm_issuer() -> Value {
        json!({ "url": "https://idm.example/oauth2/openid/hanko", "client_id": "hanko" })
    }

    #[test]
    fn parses_github_access() {
        let config = config(
            github_oidc(),
            Value::Null,
            json!({ "github": { "repository_id": 42, "environment": "release" } }),
        )
        .unwrap();
        let github = config.profiles["app"].access.github.as_ref().unwrap();
        assert_eq!(github.repository_id, 42);
        assert_eq!(github.claims[&ClaimName::Environment], "release");
        assert_eq!(config.max_concurrent.get(), 1);
        assert_eq!(config.max_queued, 4);
        assert_eq!(config.signing_timeout(), Duration::from_secs(300));
    }

    #[test]
    fn parses_both() {
        let config = config(
            github_oidc(),
            kanidm_issuer(),
            json!({
                "github": { "repository_id": 42, "environment": "release" },
                "kanidm": { "scope": "sign" },
            }),
        )
        .unwrap();
        let access = &config.profiles["app"].access;
        assert!(access.github.is_some() && access.kanidm.is_some());
    }

    #[test]
    fn requires_github_access_to_pin_context() {
        let unpinned = json!({ "github": { "repository_id": 42 } });
        assert!(config(github_oidc(), Value::Null, unpinned).is_err());
        let pinned = json!({ "github": { "repository_id": 42, "ref": "refs/heads/main" } });
        assert!(config(github_oidc(), Value::Null, pinned).is_ok());
    }

    #[test]
    fn requires_some_access() {
        assert!(config(github_oidc(), kanidm_issuer(), json!({})).is_err());
    }

    #[test]
    fn requires_kanidm_issuer_for_kanidm_access() {
        let access = json!({ "kanidm": { "scope": "sign" } });
        assert!(config(github_oidc(), Value::Null, access).is_err());
    }

    #[test]
    fn requires_github_audience_for_github_access() {
        let access = json!({ "github": { "repository_id": 42, "environment": "release" } });
        assert!(config(Value::Null, kanidm_issuer(), access).is_err());
    }

    #[test]
    fn requires_repository_id() {
        let access = json!({ "github": { "repository": "someone/app" } });
        assert!(config(github_oidc(), Value::Null, access).is_err());
    }

    #[test]
    fn rejects_unknown_claim() {
        let access = json!({ "github": { "repository_id": 42, "enviroment": "release" } });
        assert!(config(github_oidc(), Value::Null, access).is_err());
    }

    #[test]
    fn rejects_unknown_access_section() {
        let access = json!({ "github": { "repository_id": 42 }, "gitlab": {} });
        assert!(config(github_oidc(), Value::Null, access).is_err());
    }
}
