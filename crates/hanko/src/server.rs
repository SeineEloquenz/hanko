use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::get_current_timestamp;

use axum::Router;
use axum::body::Body;
use axum::extract::{FromRequestParts, Path as UrlPath, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::io::ReaderStream;
use tracing::Instrument;
use tracing::field::{Empty, display};

use crate::auth::{Caller, Issuer, Verifier};
use crate::config::Config;
use crate::error::Error;
use crate::jwks::Jwks;
use crate::{android, audit, github};

struct App {
    config: Config,
    verifier: Verifier,
    signing: Semaphore,
    uploads: Semaphore,
    http: reqwest::Client,
    audit: Option<audit::Log>,
}

impl App {
    fn new(
        config: Config,
        verifier: Verifier,
        http: reqwest::Client,
        audit: Option<audit::Log>,
    ) -> Arc<Self> {
        let signing = config.max_concurrent.get();
        Arc::new(Self {
            signing: Semaphore::new(signing),
            uploads: Semaphore::new(signing + config.max_queued),
            config,
            verifier,
            http,
            audit,
        })
    }
}

/// Serves the signing API until `shutdown` completes.
pub async fn serve(
    config: Config,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    for (name, profile) in &config.profiles {
        android::preflight(profile.format, &profile.keystore)
            .await
            .map_err(|e| {
                std::io::Error::new(e.kind(), format!("profile {name} cannot sign: {e}"))
            })?;
    }
    let audit = match &config.audit_log {
        Some(path) => Some(audit::Log::open(path).await.map_err(|e| {
            std::io::Error::new(e.kind(), format!("opening {}: {e}", path.display()))
        })?),
        None => None,
    };
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(std::io::Error::other)?;
    let github = config
        .github
        .as_ref()
        .map(|oidc| Issuer::github(Jwks::remote(http.clone(), github::ISSUER), &oidc.audience));
    let kanidm = config.kanidm.as_ref().map(|client| {
        Issuer::kanidm(
            Jwks::remote(http.clone(), client.url.as_str()),
            &client.client_id,
        )
    });
    let listen = config.listen;
    let app = App::new(config, Verifier::new(github, kanidm), http, audit);

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| std::io::Error::new(e.kind(), format!("binding {listen}: {e}")))?;
    tracing::info!("listening on {listen}");
    axum::serve(listener, router(app))
        .with_graceful_shutdown(shutdown)
        .await
}

fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/sign/{profile}", post(sign))
        .layer(middleware::from_fn(trace))
        .with_state(app)
}

async fn trace(request: Request, next: Next) -> Response {
    let span = tracing::info_span!(
        "request",
        method = %request.method(),
        path = request.uri().path(),
        caller = Empty,
    );
    next.run(request).instrument(span).await
}

impl FromRequestParts<Arc<App>> for Caller {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, Error> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| {
                let (scheme, token) = v.to_str().ok()?.split_once(' ')?;
                scheme.eq_ignore_ascii_case("bearer").then_some(token)
            })
            .ok_or(Error::MissingToken)?;
        let caller = app.verifier.verify(token).await?;
        tracing::Span::current().record("caller", display(&caller));
        Ok(caller)
    }
}

async fn sign(
    State(app): State<Arc<App>>,
    UrlPath(profile_name): UrlPath<String>,
    caller: Caller,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Error> {
    let profile = app
        .config
        .profiles
        .get(&profile_name)
        .ok_or_else(|| Error::UnknownProfile(profile_name.clone()))?;
    profile.access.check(&caller)?;
    app.verifier.consume(&caller)?;

    let limit = app.config.max_body_bytes.get();
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
    if declared.is_some_and(|length| length > limit) {
        return Err(Error::TooLarge);
    }

    let upload_deadline = Instant::now() + app.config.upload_timeout();
    let _upload = timeout_at(upload_deadline, app.uploads.acquire())
        .await
        .map_err(|_| Error::QueueTimeout)?
        .expect("semaphore is never closed");
    let dir = tempfile::tempdir().map_err(Error::io("creating work directory"))?;
    let input = dir.path().join("input");
    let output = dir.path().join("output");

    let input_sha256 = timeout_at(upload_deadline, receive(body, &input, limit))
        .await
        .map_err(|_| Error::UploadTimeout)??;
    let _signing = timeout(app.config.queue_timeout(), app.signing.acquire())
        .await
        .map_err(|_| Error::QueueTimeout)?
        .expect("semaphore is never closed");
    let (signed, output_sha256) = timeout(app.config.signing_timeout(), async {
        android::verify_package(profile.format, &input, &profile.package_name).await?;
        android::sign(profile.format, &profile.keystore, &input, &output).await?;
        open_hashed(&output)
            .await
            .map_err(Error::io("reading signed artifact"))
    })
    .await
    .map_err(|_| Error::SigningTimeout)??;
    let length = signed
        .metadata()
        .await
        .map_err(Error::io("reading signed artifact"))?
        .len();

    let entry = serde_json::to_string(&audit::Entry {
        time: get_current_timestamp(),
        profile: &profile_name,
        input_sha256: &input_sha256,
        output_sha256: &output_sha256,
        caller: &caller,
    })
    .map_err(std::io::Error::from)
    .map_err(Error::io("writing audit log"))?;
    tracing::info!(target: "hanko::audit", "{entry}");
    if let Some(log) = &app.audit {
        log.record(&entry)
            .await
            .map_err(Error::io("writing audit log"))?;
    }
    notify(&app, &profile_name, &caller);

    // Unix keeps the open file readable after `dir` is dropped and deleted.
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (header::CONTENT_LENGTH, length.to_string()),
        ],
        Body::from_stream(ReaderStream::new(signed)),
    )
        .into_response())
}

async fn receive(body: Body, path: &Path, limit: u64) -> Result<String, Error> {
    let mut file = File::create(path)
        .await
        .map_err(Error::io("creating input file"))?;
    let mut hasher = Sha256::new();
    let mut received = 0u64;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        received += chunk.len() as u64;
        if received > limit {
            return Err(Error::TooLarge);
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(Error::io("writing input file"))?;
    }
    file.flush()
        .await
        .map_err(Error::io("writing input file"))?;
    Ok(hex::encode(hasher.finalize()))
}

/// Opens `path` positioned at its start, together with its SHA-256.
async fn open_hashed(path: &Path) -> std::io::Result<(File, String)> {
    let mut file = File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0; 64 * 1024];
    loop {
        let read = file.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    file.rewind().await?;
    Ok((file, hex::encode(hasher.finalize())))
}

fn notify(app: &App, profile: &str, caller: &Caller) {
    let Some(url) = app.config.notify_url.clone() else {
        return;
    };
    let message = format!("hanko signed {profile} for {caller}");
    let http = app.http.clone();
    tokio::spawn(async move {
        let sent = async {
            http.post(url)
                .body(message)
                .send()
                .await?
                .error_for_status()
        };
        if let Err(e) = sent.await {
            tracing::error!("notification failed: {e}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{AUDIENCE, github_token, kanidm_token, verifier};
    use axum::http::{Request, StatusCode};
    use serde_json::json;
    use tower::ServiceExt;

    fn app() -> Router {
        app_with(json!({}))
    }

    fn app_with(overrides: serde_json::Value) -> Router {
        let mut config = json!({
            "listen": "127.0.0.1:0",
            "github": { "audience": AUDIENCE },
            "max_body_bytes": 4,
            "profiles": {
                "app": {
                    "format": "aab",
                    "package_name": "com.example",
                    "keystore": { "path": "/ks", "alias": "upload", "store_password_file": "/pw" },
                    "access": { "github": { "repository_id": 42, "environment": "release" } },
                }
            }
        });
        for (key, value) in overrides.as_object().unwrap() {
            config[key] = value.clone();
        }
        let config = serde_json::from_value(config).unwrap();
        router(App::new(config, verifier(), reqwest::Client::new(), None))
    }

    async fn post(token: Option<String>, body: Body) -> StatusCode {
        post_to(app(), token, body).await
    }

    async fn post_to(app: Router, token: Option<String>, body: Body) -> StatusCode {
        let mut request = Request::post("/v1/sign/app");
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        app.oneshot(request.body(body).unwrap())
            .await
            .unwrap()
            .status()
    }

    fn unreadable_body() -> Body {
        Body::from_stream(futures_util::stream::poll_fn(
            |_| -> std::task::Poll<Option<Result<Vec<u8>, std::io::Error>>> {
                panic!("body was read")
            },
        ))
    }

    #[tokio::test]
    async fn slow_upload_does_not_hold_signing_slot() {
        let app = app_with(json!({ "max_queued": 1, "queue_timeout_secs": 1 }));
        let stalled = Body::from_stream(futures_util::stream::pending::<
            Result<Vec<u8>, std::io::Error>,
        >());
        let slow = tokio::spawn(post_to(app.clone(), Some(github_token(json!({}))), stalled));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let status = post_to(app, Some(github_token(json!({}))), Body::from("x")).await;
        assert_ne!(status, StatusCode::SERVICE_UNAVAILABLE);
        slow.abort();
    }

    #[tokio::test]
    async fn accepts_lowercase_bearer_scheme() {
        let request = Request::post("/v1/sign/app")
            .header(
                header::AUTHORIZATION,
                format!("bearer {}", github_token(json!({ "repository_id": "43" }))),
            )
            .body(unreadable_body())
            .unwrap();
        let status = app().oneshot(request).await.unwrap().status();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rejects_missing_token_without_reading_body() {
        assert_eq!(
            post(None, unreadable_body()).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn rejects_forbidden_repository_without_reading_body() {
        let token = github_token(json!({ "repository_id": "43" }));
        assert_eq!(
            post(Some(token), unreadable_body()).await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn does_not_consume_token_of_forbidden_caller() {
        let app = app();
        let token = github_token(json!({ "repository_id": "43" }));
        for _ in 0..2 {
            let status = post_to(app.clone(), Some(token.clone()), unreadable_body()).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn rejects_kanidm_caller_on_github_profile_without_reading_body() {
        let token = kanidm_token("at+jwt", json!({}));
        assert_eq!(
            post(Some(token), unreadable_body()).await,
            StatusCode::FORBIDDEN
        );
    }

    fn env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
    }

    async fn sign_real(format: &str, file: &str, package: &str) -> (StatusCode, Vec<u8>) {
        let config = serde_json::from_value(json!({
            "listen": "127.0.0.1:0",
            "github": { "audience": AUDIENCE },
            "profiles": {
                "app": {
                    "format": format,
                    "package_name": package,
                    "keystore": {
                        "path": env("HANKO_E2E_KEYSTORE"),
                        "alias": "upload",
                        "store_password_file": env("HANKO_E2E_STORE_PASS_FILE"),
                    },
                    "access": { "github": { "repository_id": 42, "environment": "release" } },
                }
            }
        }))
        .unwrap();
        let request = Request::post("/v1/sign/app")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", github_token(json!({}))),
            )
            .body(Body::from(std::fs::read(env(file)).unwrap()))
            .unwrap();
        let response = router(App::new(config, verifier(), reqwest::Client::new(), None))
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, body.to_vec())
    }

    fn run(program: &str, args: &[&str], file: &std::path::Path) -> String {
        let output = std::process::Command::new(program)
            .args(args)
            .arg(file)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(output.status.success(), "{program} failed: {stdout}");
        stdout
    }

    #[tokio::test]
    #[ignore = "needs HANKO_E2E_* and the Android signing tools"]
    async fn signs_real_bundle() {
        let (status, signed) = sign_real("aab", "HANKO_E2E_AAB", &env("HANKO_E2E_PACKAGE")).await;
        assert_eq!(status, StatusCode::OK);
        let out = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(out.path(), signed).unwrap();
        assert!(run("jarsigner", &["-verify"], out.path()).contains("jar verified."));
        assert!(run("keytool", &["-printcert", "-jarfile"], out.path()).contains("CN=hanko test"));
    }

    #[tokio::test]
    #[ignore = "needs HANKO_E2E_* and the Android signing tools"]
    async fn signs_real_apk() {
        let (status, signed) = sign_real("apk", "HANKO_E2E_APK", &env("HANKO_E2E_PACKAGE")).await;
        assert_eq!(status, StatusCode::OK);
        let out = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(out.path(), signed).unwrap();
        let certs = run("apksigner", &["verify", "--print-certs"], out.path());
        assert!(certs.contains("CN=hanko test"), "{certs}");
    }

    #[tokio::test]
    #[ignore = "needs HANKO_E2E_* and the Android signing tools"]
    async fn rejects_real_bundle_for_other_package() {
        let (status, _) = sign_real("aab", "HANKO_E2E_AAB", "com.example").await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    #[ignore = "needs HANKO_E2E_* and the Android signing tools"]
    async fn refuses_to_return_broken_double_signed_bundle() {
        let (status, _) = sign_real("aab", "HANKO_E2E_SIGNED_AAB", &env("HANKO_E2E_PACKAGE")).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn rejects_oversized_body() {
        let body = Body::from_stream(futures_util::stream::iter([Ok::<_, std::io::Error>(
            vec![0u8; 10],
        )]));
        assert_eq!(
            post(Some(github_token(json!({}))), body).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}
