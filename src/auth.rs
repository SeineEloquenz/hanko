use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use jsonwebtoken::dangerous::insecure_decode_claims;
use jsonwebtoken::{Algorithm, Validation, decode, decode_header, get_current_timestamp};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::jwks::{self, Jwks};
use crate::{github, kanidm};

const LEEWAY_SECS: u64 = 60;

/// A verified caller.
#[derive(Serialize)]
#[serde(tag = "issuer", rename_all = "lowercase")]
pub enum Caller {
    Github(Box<github::Claims>),
    Kanidm(kanidm::Claims),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerName {
    Github,
    Kanidm,
}

/// Used GitHub token ids are tracked in memory, so hanko must run as a single instance
/// and a restart forgets them.
pub struct Verifier {
    github: Option<Issuer>,
    kanidm: Option<Issuer>,
    seen: Mutex<HashMap<String, u64>>,
}

/// Validation settings and signing keys of one token issuer.
pub struct Issuer {
    jwks: Jwks,
    validation: Validation,
}

#[derive(Deserialize)]
struct UnverifiedIssuer {
    iss: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("token has no kid")]
    MissingKid,
    #[error("token from unknown issuer {0}")]
    UnknownIssuer(String),
    #[error("kanidm token is not an access token")]
    NotAccessToken,
    #[error(transparent)]
    Jwks(#[from] jwks::Error),
    #[error("invalid token: {0}")]
    Invalid(#[from] jsonwebtoken::errors::Error),
    #[error("token {0} was already used")]
    Replayed(String),
}

impl Caller {
    pub const fn issuer(&self) -> IssuerName {
        match self {
            Self::Github(_) => IssuerName::Github,
            Self::Kanidm(_) => IssuerName::Kanidm,
        }
    }
}

impl fmt::Display for Caller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Github(claims) => claims.fmt(f),
            Self::Kanidm(claims) => claims.fmt(f),
        }
    }
}

impl fmt::Display for IssuerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Github => "github",
            Self::Kanidm => "kanidm",
        })
    }
}

impl Issuer {
    pub fn github(jwks: Jwks, audience: &str) -> Self {
        Self::new(jwks, github::ALGORITHM, audience)
    }

    pub fn kanidm(jwks: Jwks, client_id: &str) -> Self {
        Self::new(jwks, kanidm::ALGORITHM, client_id)
    }

    fn new(jwks: Jwks, algorithm: Algorithm, audience: &str) -> Self {
        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[jwks.issuer()]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud"]);
        validation.validate_nbf = true;
        validation.leeway = LEEWAY_SECS;
        Self { jwks, validation }
    }

    async fn decode<C: DeserializeOwned>(&self, token: &str, kid: &str) -> Result<C, Error> {
        let key = self.jwks.key(kid).await?;
        Ok(decode::<C>(token, &key, &self.validation)?.claims)
    }
}

impl Verifier {
    pub fn new(github: Option<Issuer>, kanidm: Option<Issuer>) -> Self {
        Self {
            github,
            kanidm,
            seen: Mutex::default(),
        }
    }

    /// Verifies the token against the issuer it names.
    pub async fn verify(&self, token: &str) -> Result<Caller, Error> {
        let header = decode_header(token)?;
        let kid = header.kid.ok_or(Error::MissingKid)?;
        let iss = insecure_decode_claims::<UnverifiedIssuer>(token)?.iss;

        if let Some(github) = self
            .github
            .as_ref()
            .filter(|github| iss == github.jwks.issuer())
        {
            return Ok(Caller::Github(Box::new(github.decode(token, &kid).await?)));
        }
        if let Some(kanidm) = self
            .kanidm
            .as_ref()
            .filter(|kanidm| iss == kanidm.jwks.issuer())
        {
            if header.typ.as_deref() != Some(kanidm::TOKEN_TYPE) {
                return Err(Error::NotAccessToken);
            }
            return Ok(Caller::Kanidm(kanidm.decode(token, &kid).await?));
        }
        Err(Error::UnknownIssuer(iss))
    }

    /// Marks the caller's GitHub token as used, failing if it already was.
    pub fn consume(&self, caller: &Caller) -> Result<(), Error> {
        // Kanidm sets jti to the session id, so its tokens cannot be made single-use.
        let Caller::Github(claims) = caller else {
            return Ok(());
        };
        let now = get_current_timestamp();
        let mut seen = self.seen.lock().unwrap();
        seen.retain(|_, exp| *exp + LEEWAY_SECS >= now);
        if seen.insert(claims.jti.clone(), claims.exp).is_some() {
            return Err(Error::Replayed(claims.jti.clone()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{github_token, kanidm_token, verifier};
    use serde_json::json;

    #[tokio::test]
    async fn accepts_valid_github_token() {
        let caller = verifier().verify(&github_token(json!({}))).await.unwrap();
        assert_eq!(caller.issuer(), IssuerName::Github);
    }

    #[tokio::test]
    async fn rejects_github_replay() {
        let v = verifier();
        let t = github_token(json!({}));
        let first = v.verify(&t).await.unwrap();
        let second = v.verify(&t).await.unwrap();
        v.consume(&first).unwrap();
        assert!(matches!(v.consume(&second), Err(Error::Replayed(_))));
    }

    #[tokio::test]
    async fn rejects_wrong_audience() {
        let t = github_token(json!({ "aud": "https://other.example" }));
        assert!(matches!(
            verifier().verify(&t).await,
            Err(Error::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn rejects_unknown_issuer() {
        let t = github_token(json!({ "iss": "https://evil.example" }));
        assert!(matches!(
            verifier().verify(&t).await,
            Err(Error::UnknownIssuer(_))
        ));
    }

    #[tokio::test]
    async fn rejects_token_signed_by_other_issuer() {
        let t = kanidm_token("at+jwt", json!({ "iss": github::ISSUER }));
        assert!(matches!(
            verifier().verify(&t).await,
            Err(Error::Jwks(jwks::Error::UnknownKid(_)))
        ));
    }

    #[tokio::test]
    async fn rejects_expired() {
        let now = get_current_timestamp();
        let t = github_token(json!({ "iat": now - 1000, "nbf": now - 1000, "exp": now - 600 }));
        assert!(matches!(
            verifier().verify(&t).await,
            Err(Error::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn rejects_tampered_signature() {
        let mut t = github_token(json!({}));
        let last = t.pop().unwrap();
        t.push(if last == 'A' { 'B' } else { 'A' });
        assert!(matches!(
            verifier().verify(&t).await,
            Err(Error::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn rejects_token_missing_github_claims() {
        let t = github_token(json!({ "job_workflow_ref": null }));
        assert!(matches!(
            verifier().verify(&t).await,
            Err(Error::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn accepts_kanidm_access_token_more_than_once() {
        let v = verifier();
        let t = kanidm_token("at+jwt", json!({}));
        for _ in 0..2 {
            v.consume(&v.verify(&t).await.unwrap()).unwrap();
        }
    }

    #[tokio::test]
    async fn rejects_kanidm_id_token() {
        let t = kanidm_token("JWT", json!({}));
        assert!(matches!(
            verifier().verify(&t).await,
            Err(Error::NotAccessToken)
        ));
    }

    #[tokio::test]
    async fn rejects_kanidm_token_for_other_client() {
        let t = kanidm_token("at+jwt", json!({ "aud": "grafana" }));
        assert!(matches!(
            verifier().verify(&t).await,
            Err(Error::Invalid(_))
        ));
    }
}
