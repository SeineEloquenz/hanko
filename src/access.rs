use serde::Deserialize;

use crate::auth::{Caller, IssuerName};
use crate::{github, kanidm};

/// Who may sign with a profile. Callers of an issuer without a policy are denied.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Access {
    pub github: Option<github::Policy>,
    pub kanidm: Option<kanidm::Policy>,
}

#[derive(Debug, thiserror::Error)]
pub enum Violation {
    #[error("{0} callers are not allowed")]
    IssuerNotAllowed(IssuerName),
    #[error(transparent)]
    Github(#[from] github::Violation),
    #[error(transparent)]
    Kanidm(#[from] kanidm::Violation),
}

impl Access {
    pub const fn allows_any(&self) -> bool {
        self.github.is_some() || self.kanidm.is_some()
    }

    pub fn check(&self, caller: &Caller) -> Result<(), Violation> {
        let not_allowed = || Violation::IssuerNotAllowed(caller.issuer());
        match caller {
            Caller::Github(claims) => self
                .github
                .as_ref()
                .ok_or_else(not_allowed)?
                .check(claims)?,
            Caller::Kanidm(claims) => self
                .kanidm
                .as_ref()
                .ok_or_else(not_allowed)?
                .check(claims)?,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::ClaimName;
    use crate::testing::{github_token, kanidm_token, verifier};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;

    fn github_access() -> Access {
        Access {
            github: Some(github::Policy {
                repository_id: 42,
                claims: BTreeMap::from([(ClaimName::Environment, "release".into())]),
            }),
            kanidm: None,
        }
    }

    fn kanidm_access() -> Access {
        Access {
            github: None,
            kanidm: Some(kanidm::Policy {
                scope: "sign".into(),
            }),
        }
    }

    async fn github_caller(overrides: Value) -> Caller {
        verifier().verify(&github_token(overrides)).await.unwrap()
    }

    async fn kanidm_caller(overrides: Value) -> Caller {
        verifier()
            .verify(&kanidm_token("at+jwt", overrides))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn accepts_valid_github_caller() {
        github_access()
            .check(&github_caller(json!({})).await)
            .unwrap();
    }

    #[tokio::test]
    async fn rejects_other_repository() {
        let caller = github_caller(json!({ "repository_id": "43" })).await;
        assert!(matches!(
            github_access().check(&caller),
            Err(Violation::Github(github::Violation::Repository { .. }))
        ));
    }

    #[tokio::test]
    async fn rejects_missing_environment() {
        let caller = github_caller(json!({ "environment": null })).await;
        assert!(matches!(
            github_access().check(&caller),
            Err(Violation::Github(github::Violation::Mismatch {
                actual: None,
                ..
            }))
        ));
    }

    #[tokio::test]
    async fn rejects_pull_request_even_if_policy_allows() {
        let caller = github_caller(json!({ "event_name": "pull_request_target" })).await;
        let access = Access {
            github: Some(github::Policy {
                repository_id: 42,
                claims: BTreeMap::from([(ClaimName::EventName, "pull_request_target".into())]),
            }),
            kanidm: None,
        };
        assert!(matches!(
            access.check(&caller),
            Err(Violation::Github(github::Violation::ForbiddenEvent(_)))
        ));
    }

    #[tokio::test]
    async fn accepts_kanidm_caller_with_scope() {
        kanidm_access()
            .check(&kanidm_caller(json!({})).await)
            .unwrap();
    }

    #[tokio::test]
    async fn rejects_kanidm_caller_without_scope() {
        let caller = kanidm_caller(json!({ "scope": "openid profile" })).await;
        assert!(matches!(
            kanidm_access().check(&caller),
            Err(Violation::Kanidm(kanidm::Violation::MissingScope(_)))
        ));
    }

    #[tokio::test]
    async fn rejects_caller_from_issuer_the_profile_does_not_allow() {
        let caller = kanidm_caller(json!({})).await;
        assert!(matches!(
            github_access().check(&caller),
            Err(Violation::IssuerNotAllowed(IssuerName::Kanidm))
        ));
        let caller = github_caller(json!({})).await;
        assert!(matches!(
            kanidm_access().check(&caller),
            Err(Violation::IssuerNotAllowed(IssuerName::Github))
        ));
    }
}
