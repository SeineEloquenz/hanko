use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::JwkSet;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;

const RETRY_INTERVAL: Duration = Duration::from_secs(60);
const MAX_KEY_AGE: Duration = Duration::from_secs(60 * 60);

/// Caches an issuer's signing keys, refetching them hourly and when an unknown `kid` shows up.
/// Fetches happen at most once a minute, and cached keys stay in use while the issuer is unreachable.
pub struct Jwks {
    http: reqwest::Client,
    issuer: String,
    cache: RwLock<Cache>,
    refresh: Mutex<()>,
}

#[derive(Default)]
struct Cache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
    attempted_at: Option<Instant>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown kid {0}")]
    UnknownKid(String),
    #[error("fetching {url}: {source}")]
    Fetch { url: String, source: reqwest::Error },
}

#[derive(Deserialize)]
struct Discovery {
    jwks_uri: String,
}

impl Jwks {
    pub fn remote(http: reqwest::Client, issuer: &str) -> Self {
        Self::with_cache(http, issuer, Cache::default())
    }

    #[cfg(test)]
    pub fn fixed(issuer: &str, set: &JwkSet) -> Self {
        let now = Instant::now();
        let cache = Cache {
            keys: decode_set(set),
            fetched_at: Some(now),
            attempted_at: Some(now),
        };
        Self::with_cache(reqwest::Client::new(), issuer, cache)
    }

    fn with_cache(http: reqwest::Client, issuer: &str, cache: Cache) -> Self {
        Self {
            http,
            issuer: issuer.trim_end_matches('/').to_owned(),
            cache: RwLock::new(cache),
            refresh: Mutex::default(),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub async fn key(&self, kid: &str) -> Result<DecodingKey, Error> {
        if let Some(key) = self.lookup(kid)? {
            return Ok(key);
        }
        let _refresh = self.refresh.lock().await;
        if let Some(key) = self.lookup(kid)? {
            return Ok(key);
        }
        self.refetch(kid).await
    }

    /// Returns the cached key, or `None` when a fetch is due.
    fn lookup(&self, kid: &str) -> Result<Option<DecodingKey>, Error> {
        let cache = self.cache.read().unwrap();
        let key = cache.keys.get(kid);
        let cached_age = key.and(cache.fetched_at).map(|at| at.elapsed());
        match plan(cached_age, cache.attempted_at.map(|at| at.elapsed())) {
            Plan::Use => Ok(key.cloned()),
            Plan::Fetch => Ok(None),
            Plan::Unknown => Err(Error::UnknownKid(kid.to_owned())),
        }
    }

    async fn refetch(&self, kid: &str) -> Result<DecodingKey, Error> {
        let fetched = fetch(&self.http, &self.issuer).await;
        let mut cache = self.cache.write().unwrap();
        let now = Instant::now();
        cache.attempted_at = Some(now);
        match fetched {
            Ok(keys) => {
                cache.keys = keys;
                cache.fetched_at = Some(now);
            }
            Err(e) if cache.keys.contains_key(kid) => {
                tracing::warn!("keeping cached keys of {}: {e}", self.issuer);
            }
            Err(e) => return Err(e),
        }
        cache
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| Error::UnknownKid(kid.to_owned()))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Plan {
    Use,
    Fetch,
    Unknown,
}

/// `cached_age` is the age of the requested key, `None` if it is not cached.
fn plan(cached_age: Option<Duration>, since_attempt: Option<Duration>) -> Plan {
    let retry_due = since_attempt.is_none_or(|since| since >= RETRY_INTERVAL);
    match cached_age {
        Some(age) if age < MAX_KEY_AGE || !retry_due => Plan::Use,
        _ if retry_due => Plan::Fetch,
        _ => Plan::Unknown,
    }
}

async fn fetch(
    http: &reqwest::Client,
    issuer: &str,
) -> Result<HashMap<String, DecodingKey>, Error> {
    let discovery_url = format!("{issuer}/.well-known/openid-configuration");
    let discovery: Discovery = get_json(http, &discovery_url).await?;
    Ok(decode_set(&get_json(http, &discovery.jwks_uri).await?))
}

async fn get_json<T: DeserializeOwned>(http: &reqwest::Client, url: &str) -> Result<T, Error> {
    let fetch = async { http.get(url).send().await?.error_for_status()?.json().await };
    fetch.await.map_err(|source| Error::Fetch {
        url: url.to_owned(),
        source,
    })
}

fn decode_set(set: &JwkSet) -> HashMap<String, DecodingKey> {
    set.keys
        .iter()
        .filter_map(|jwk| {
            let kid = jwk.common.key_id.clone()?;
            let key = DecodingKey::from_jwk(jwk).ok()?;
            Some((kid, key))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_fetches() {
        let secs = |s| Some(Duration::from_secs(s));
        let hours = |h: u64| secs(h * 60 * 60);
        let cases = [
            (None, None, Plan::Fetch),
            (secs(10), secs(10), Plan::Use),
            (None, secs(10), Plan::Unknown),
            (None, secs(120), Plan::Fetch),
            (secs(120), secs(120), Plan::Use),
            (hours(2), hours(2), Plan::Fetch),
            (hours(2), secs(10), Plan::Use),
        ];
        for (cached_age, since_attempt, expected) in cases {
            assert_eq!(
                plan(cached_age, since_attempt),
                expected,
                "cached age {cached_age:?}, since attempt {since_attempt:?}"
            );
        }
    }

    #[tokio::test]
    async fn keeps_cached_key_when_refresh_fails() {
        let set: JwkSet =
            serde_json::from_str(include_str!("../tests/fixtures/github-jwks.json")).unwrap();
        let jwks = Jwks::fixed("http://127.0.0.1:1", &set);
        let stale = Instant::now().checked_sub(2 * MAX_KEY_AGE);
        {
            let mut cache = jwks.cache.write().unwrap();
            cache.fetched_at = stale;
            cache.attempted_at = stale;
        }
        jwks.key("test").await.unwrap();
        assert!(matches!(jwks.key("other").await, Err(Error::UnknownKid(_))));
    }

    #[tokio::test]
    #[ignore = "needs network, set HANKO_LIVE_ISSUERS to space-separated issuer URLs"]
    async fn decodes_live_keys() {
        let issuers = std::env::var("HANKO_LIVE_ISSUERS").unwrap();
        for issuer in issuers.split_whitespace() {
            let keys = fetch(&reqwest::Client::new(), issuer).await.unwrap();
            assert!(!keys.is_empty(), "{issuer} has no usable keys");
        }
    }
}
