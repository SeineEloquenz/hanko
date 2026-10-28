use std::collections::BTreeSet;
use std::fmt;

use jsonwebtoken::Algorithm;
use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

pub const ALGORITHM: Algorithm = Algorithm::ES256;
/// RFC 9068 `typ` header that tells access tokens apart from ID tokens.
pub const TOKEN_TYPE: &str = "at+jwt";

/// The Kanidm OAuth2 client hanko accepts access tokens for.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthClient {
    /// Per-client issuer, e.g. `https://idm.example.com/oauth2/openid/hanko`.
    pub url: Url,
    pub client_id: String,
}

/// The RFC 9068 access token claims hanko relies on.
#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
    #[serde(deserialize_with = "space_separated")]
    pub scope: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Scope the token must carry, granted to signers through a Kanidm scope map.
    pub scope: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Violation {
    #[error("token lacks scope {0}")]
    MissingScope(String),
}

impl Policy {
    pub fn check(&self, claims: &Claims) -> Result<(), Violation> {
        if claims.scope.contains(&self.scope) {
            Ok(())
        } else {
            Err(Violation::MissingScope(self.scope.clone()))
        }
    }
}

impl fmt::Display for Claims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "kanidm user {}", self.sub)
    }
}

fn space_separated<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeSet<String>, D::Error> {
    Ok(String::deserialize(deserializer)?
        .split_whitespace()
        .map(str::to_owned)
        .collect())
}
