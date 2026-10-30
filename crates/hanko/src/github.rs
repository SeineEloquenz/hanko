use std::collections::BTreeMap;
use std::fmt;

use jsonwebtoken::Algorithm;
use serde::{Deserialize, Deserializer, Serialize};

pub const ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const ALGORITHM: Algorithm = Algorithm::RS256;

/// The GitHub Actions OIDC tokens hanko accepts.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oidc {
    /// Audience the tokens must be issued for.
    pub audience: String,
}

/// The GitHub Actions OIDC claims hanko relies on.
#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub jti: String,
    pub exp: u64,
    #[serde(deserialize_with = "numeric_string")]
    pub repository_id: u64,
    pub repository: String,
    pub repository_owner: String,
    pub repository_owner_id: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub ref_type: String,
    pub sha: String,
    pub environment: Option<String>,
    pub event_name: String,
    pub workflow: String,
    pub workflow_ref: String,
    pub job_workflow_ref: String,
    pub actor: String,
    pub actor_id: String,
    pub run_id: String,
    pub run_attempt: String,
    pub runner_environment: String,
}

/// Claims a policy may pin, besides the mandatory `repository_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimName {
    Repository,
    RepositoryOwner,
    RepositoryOwnerId,
    Ref,
    RefType,
    Environment,
    EventName,
    Workflow,
    WorkflowRef,
    JobWorkflowRef,
    Actor,
    ActorId,
    RunnerEnvironment,
}

impl Claims {
    pub fn get(&self, name: ClaimName) -> Option<&str> {
        let value = match name {
            ClaimName::Repository => &self.repository,
            ClaimName::RepositoryOwner => &self.repository_owner,
            ClaimName::RepositoryOwnerId => &self.repository_owner_id,
            ClaimName::Ref => &self.git_ref,
            ClaimName::RefType => &self.ref_type,
            ClaimName::Environment => return self.environment.as_deref(),
            ClaimName::EventName => &self.event_name,
            ClaimName::Workflow => &self.workflow,
            ClaimName::WorkflowRef => &self.workflow_ref,
            ClaimName::JobWorkflowRef => &self.job_workflow_ref,
            ClaimName::Actor => &self.actor,
            ClaimName::ActorId => &self.actor_id,
            ClaimName::RunnerEnvironment => &self.runner_environment,
        };
        Some(value)
    }
}

impl fmt::Display for Claims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{} (run {}, actor {})",
            self.repository, self.sha, self.run_id, self.actor
        )
    }
}

/// Claims a token must carry exactly. `repository_id` is mandatory so no other repository can match.
#[derive(Debug, Deserialize)]
pub struct Policy {
    pub repository_id: u64,
    #[serde(flatten)]
    pub claims: BTreeMap<ClaimName, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum Violation {
    #[error("event {0} is never allowed")]
    ForbiddenEvent(String),
    #[error("repository_id is {actual}, expected {expected}")]
    Repository { expected: u64, actual: u64 },
    #[error("claim {claim:?} is {actual:?}, expected {expected:?}")]
    Mismatch {
        claim: ClaimName,
        expected: String,
        actual: Option<String>,
    },
}

impl Policy {
    /// Whether the policy pins a claim that pushing an arbitrary branch cannot satisfy.
    pub fn pins_trusted_context(&self) -> bool {
        [
            ClaimName::Environment,
            ClaimName::Ref,
            ClaimName::JobWorkflowRef,
        ]
        .iter()
        .any(|claim| self.claims.contains_key(claim))
    }

    pub fn check(&self, claims: &Claims) -> Result<(), Violation> {
        if matches!(
            claims.event_name.as_str(),
            "pull_request" | "pull_request_target"
        ) {
            return Err(Violation::ForbiddenEvent(claims.event_name.clone()));
        }
        if claims.repository_id != self.repository_id {
            return Err(Violation::Repository {
                expected: self.repository_id,
                actual: claims.repository_id,
            });
        }
        for (&claim, expected) in &self.claims {
            let actual = claims.get(claim);
            if actual != Some(expected.as_str()) {
                return Err(Violation::Mismatch {
                    claim,
                    expected: expected.clone(),
                    actual: actual.map(str::to_owned),
                });
            }
        }
        Ok(())
    }
}

fn numeric_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    String::deserialize(deserializer)?
        .parse()
        .map_err(serde::de::Error::custom)
}
