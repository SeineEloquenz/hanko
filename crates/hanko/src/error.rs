use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::{access, android, auth, jwks};

/// Request failure. The reason is logged but never sent to the client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing bearer token")]
    MissingToken,
    #[error(transparent)]
    Unauthorized(#[from] auth::Error),
    #[error("unknown profile {0}")]
    UnknownProfile(String),
    #[error("denied: {0}")]
    Forbidden(#[from] access::Violation),
    #[error("payload too large")]
    TooLarge,
    #[error("reading body: {0}")]
    Body(#[from] axum::Error),
    #[error("upload timed out")]
    UploadTimeout,
    #[error(transparent)]
    Android(#[from] android::Error),
    #[error("timed out waiting in the queue")]
    QueueTimeout,
    #[error("signing timed out")]
    SigningTimeout,
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        source: std::io::Error,
    },
}

impl Error {
    pub fn io(context: &'static str) -> impl FnOnce(std::io::Error) -> Self {
        move |source| Self::Io { context, source }
    }

    const fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized(auth::Error::Jwks(jwks::Error::Fetch { .. })) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::MissingToken | Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::UnknownProfile(_) | Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Body(_) => StatusCode::BAD_REQUEST,
            Self::UploadTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::Android(e) if e.is_rejection() => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Android(_) | Self::Io { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::QueueTimeout | Self::SigningTimeout => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status();
        if status.is_server_error() {
            tracing::error!("{self}");
        } else {
            tracing::warn!("{self}");
        }
        (status, status.canonical_reason().unwrap_or_default()).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn issuer_outage_is_unavailable() {
        let source = reqwest::get("http://127.0.0.1:1").await.unwrap_err();
        let error = Error::Unauthorized(auth::Error::Jwks(jwks::Error::Fetch {
            url: String::new(),
            source,
        }));
        assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
