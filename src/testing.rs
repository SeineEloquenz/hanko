use std::sync::atomic::{AtomicU64, Ordering};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, get_current_timestamp};
use serde_json::{Value, json};

use crate::auth::{Issuer, Verifier};
use crate::github;
use crate::jwks::Jwks;

pub const AUDIENCE: &str = "https://sign.example";
pub const KANIDM_ISSUER: &str = "https://idm.example/oauth2/openid/hanko";
pub const KANIDM_CLIENT: &str = "hanko";

pub fn verifier() -> Verifier {
    let jwks =
        |issuer, raw: &str| Jwks::fixed(issuer, &serde_json::from_str::<JwkSet>(raw).unwrap());
    Verifier::new(
        Some(Issuer::github(
            jwks(
                github::ISSUER,
                include_str!("../tests/fixtures/github-jwks.json"),
            ),
            AUDIENCE,
        )),
        Some(Issuer::kanidm(
            jwks(
                KANIDM_ISSUER,
                include_str!("../tests/fixtures/kanidm-jwks.json"),
            ),
            KANIDM_CLIENT,
        )),
    )
}

/// Signs a GitHub-shaped token for repository 42. A `null` override removes the claim.
pub fn github_token(overrides: Value) -> String {
    static NEXT_JTI: AtomicU64 = AtomicU64::new(0);
    let now = get_current_timestamp();
    let claims = json!({
        "iss": github::ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": NEXT_JTI.fetch_add(1, Ordering::Relaxed).to_string(),
        "repository_id": "42",
        "repository": "owner/app",
        "repository_owner": "owner",
        "repository_owner_id": "7",
        "ref": "refs/heads/main",
        "ref_type": "branch",
        "sha": "abc",
        "environment": "release",
        "event_name": "workflow_dispatch",
        "workflow": "Release",
        "workflow_ref": "owner/app/.github/workflows/release.yml@refs/heads/main",
        "job_workflow_ref": "owner/app/.github/workflows/release.yml@refs/heads/main",
        "actor": "owner",
        "actor_id": "7",
        "run_id": "1",
        "run_attempt": "1",
        "runner_environment": "github-hosted",
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test".into());
    let key =
        EncodingKey::from_rsa_pem(include_bytes!("../tests/fixtures/github-key.pem")).unwrap();
    encode(&header, &apply(claims, overrides), &key).unwrap()
}

/// Signs a Kanidm-shaped token with the given `typ` header. A `null` override removes the claim.
pub fn kanidm_token(typ: &str, overrides: Value) -> String {
    let now = get_current_timestamp();
    let claims = json!({
        "iss": KANIDM_ISSUER,
        "sub": "00000000-0000-0000-0000-000000000001",
        "aud": KANIDM_CLIENT,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": "00000000-0000-0000-0000-000000000002",
        "client_id": KANIDM_CLIENT,
        "scope": "openid sign",
        "session_id": "00000000-0000-0000-0000-000000000002",
    });
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("kanidm-test".into());
    header.typ = Some(typ.into());
    let key = EncodingKey::from_ec_pem(include_bytes!("../tests/fixtures/kanidm-key.pem")).unwrap();
    encode(&header, &apply(claims, overrides), &key).unwrap()
}

fn apply(mut claims: Value, overrides: Value) -> Value {
    for (k, v) in overrides.as_object().unwrap() {
        if v.is_null() {
            claims.as_object_mut().unwrap().remove(k);
        } else {
            claims[k] = v.clone();
        }
    }
    claims
}
