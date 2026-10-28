use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::{Host, Url};

const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CALLBACK_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Sign an Android artifact with hanko after logging in through Kanidm.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Unsigned AAB or APK.
    input: PathBuf,
    /// Where to write the signed file.
    #[arg(short, long)]
    output: PathBuf,
    /// hanko profile to sign with.
    #[arg(short, long)]
    profile: String,
    /// hanko base URL.
    #[arg(long, env = "HANKO_SERVER")]
    server: Url,
    /// Kanidm issuer of the hanko OAuth2 client.
    #[arg(long, env = "HANKO_ISSUER")]
    issuer: Url,
    #[arg(long, env = "HANKO_CLIENT_ID", default_value = "hanko")]
    client_id: String,
    #[arg(long, env = "HANKO_SCOPE", default_value = "sign")]
    scope: String,
    /// Seconds to wait for hanko's answer. Must exceed the server's upload, queue and signing timeouts combined.
    #[arg(long, env = "HANKO_READ_TIMEOUT", default_value_t = 960)]
    read_timeout: u64,
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        source: std::io::Error,
    },
    #[error("{action} {path}: {source}")]
    File {
        action: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("server and issuer URLs must start with https://, or http:// for a loopback host")]
    InvalidServer,
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("no randomness available: {0}")]
    Random(getrandom::Error),
    #[error("login failed: {0}")]
    Login(String),
    #[error("login timed out")]
    LoginTimeout,
    #[error("hanko refused with {status}: {body}")]
    Refused {
        status: reqwest::StatusCode,
        body: String,
    },
}

#[derive(Deserialize)]
struct Discovery {
    authorization_endpoint: Url,
    token_endpoint: Url,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Debug, PartialEq, Eq)]
enum Callback {
    Code(String),
    Failed(String),
    Ignored,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hanko-sign: {e}");
            ExitCode::FAILURE
        }
    }
}

impl Error {
    fn io(context: &'static str) -> impl FnOnce(std::io::Error) -> Self {
        move |source| Self::Io { context, source }
    }

    fn file(action: &'static str, path: &Path) -> impl FnOnce(std::io::Error) -> Self {
        move |source| Self::File {
            action,
            path: path.to_owned(),
            source,
        }
    }
}

async fn run(args: Args) -> Result<(), Error> {
    if !allowed_server(&args.server) || !allowed_server(&args.issuer) {
        return Err(Error::InvalidServer);
    }
    let mut url = args.server.clone();
    url.path_segments_mut()
        .map_err(|()| Error::InvalidServer)?
        .pop_if_empty()
        .extend(["v1", "sign", &args.profile]);
    let input = tokio::fs::read(&args.input)
        .await
        .map_err(Error::file("reading", &args.input))?;

    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(Duration::from_secs(args.read_timeout))
        .build()?;
    let token = login(&http, &args).await?;
    let response = http.post(url).bearer_auth(token).body(input).send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(Error::Refused {
            status,
            body: response.text().await.unwrap_or_default(),
        });
    }
    let signed = response.bytes().await?;
    tokio::fs::write(&args.output, &signed)
        .await
        .map_err(Error::file("writing", &args.output))?;
    eprintln!(
        "signed {} -> {} (sha256 {})",
        args.input.display(),
        args.output.display(),
        hex::encode(Sha256::digest(&signed))
    );
    Ok(())
}

/// Kanidm tokens are reusable, so they may travel in plain HTTP only to this machine.
fn allowed_server(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => match url.host() {
            Some(Host::Domain(domain)) => domain == "localhost",
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        },
        _ => false,
    }
}

/// Runs the authorization code flow with PKCE and a loopback redirect, returning an access token.
async fn login(http: &reqwest::Client, args: &Args) -> Result<String, Error> {
    let discovery: Discovery = http
        .get(format!(
            "{}/.well-known/openid-configuration",
            args.issuer.as_str().trim_end_matches('/')
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(Error::io("opening login callback listener"))?;
    let port = listener
        .local_addr()
        .map_err(Error::io("opening login callback listener"))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    let verifier = random_token()?;
    let state = random_token()?;

    let mut authorize = discovery.authorization_endpoint;
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &args.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", &format!("openid {}", args.scope))
        .append_pair("state", &state)
        .append_pair(
            "code_challenge",
            &URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        )
        .append_pair("code_challenge_method", "S256");

    eprintln!("log in at {authorize}");
    open_browser(authorize.as_str());

    let code = tokio::time::timeout(LOGIN_TIMEOUT, await_code(&listener, &state))
        .await
        .map_err(|_| Error::LoginTimeout)??;

    let token: TokenResponse = http
        .post(discovery.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &args.client_id),
            ("code_verifier", &verifier),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(token.access_token)
}

async fn await_code(listener: &TcpListener, state: &str) -> Result<String, Error> {
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(Error::io("accepting login callback"))?;
        let mut buf = [0u8; 8192];
        // Browsers open idle preconnect sockets that would otherwise block the real callback.
        let Ok(read) = tokio::time::timeout(CALLBACK_READ_TIMEOUT, stream.read(&mut buf)).await
        else {
            continue;
        };
        let read = read.map_err(Error::io("reading login callback"))?;
        let callback = parse_callback(&String::from_utf8_lossy(&buf[..read]), state);
        let (status, page) = match &callback {
            Callback::Code(_) => ("200 OK", "Logged in. You can close this window."),
            Callback::Failed(_) => ("200 OK", "Login failed. See the terminal."),
            Callback::Ignored => ("404 Not Found", "Not found."),
        };
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{page}",
            page.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .map_err(Error::io("answering login callback"))?;
        match callback {
            Callback::Code(code) => return Ok(code),
            Callback::Failed(reason) => return Err(Error::Login(reason)),
            Callback::Ignored => {}
        }
    }
}

/// Interprets one HTTP request to the loopback listener. Requests without our `state` are ignored.
fn parse_callback(request: &str, state: &str) -> Callback {
    let Some(target) = request
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("GET "))
        .and_then(|rest| rest.split(' ').next())
    else {
        return Callback::Ignored;
    };
    let Ok(url) = Url::parse("http://127.0.0.1").and_then(|base| base.join(target)) else {
        return Callback::Ignored;
    };
    if url.path() != "/callback" {
        return Callback::Ignored;
    }
    let param = |name: &str| {
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    };
    if param("state").as_deref() != Some(state) {
        return Callback::Ignored;
    }
    match (param("code"), param("error")) {
        (Some(code), None) => Callback::Code(code),
        (_, error) => Callback::Failed(
            param("error_description")
                .or(error)
                .unwrap_or_else(|| "no code in callback".into()),
        ),
    }
}

fn random_token() -> Result<String, Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(Error::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn open_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(opener)
        .arg(url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(target: &str) -> String {
        format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    }

    #[test]
    fn accepts_code_with_matching_state() {
        assert_eq!(
            parse_callback(&request("/callback?code=abc&state=s1"), "s1"),
            Callback::Code("abc".into())
        );
    }

    #[test]
    fn ignores_wrong_state() {
        assert_eq!(
            parse_callback(&request("/callback?code=abc&state=other"), "s1"),
            Callback::Ignored
        );
    }

    #[test]
    fn ignores_other_paths() {
        assert_eq!(
            parse_callback(&request("/favicon.ico"), "s1"),
            Callback::Ignored
        );
        assert_eq!(parse_callback("garbage", "s1"), Callback::Ignored);
    }

    #[test]
    fn allows_plain_http_only_to_loopback() {
        let allowed = |url: &str| allowed_server(&Url::parse(url).unwrap());
        assert!(allowed("https://sign.example"));
        assert!(allowed("http://127.0.0.1:8470"));
        assert!(allowed("http://[::1]:8470"));
        assert!(allowed("http://localhost:8470"));
        assert!(!allowed("http://sign.example"));
        assert!(!allowed("ftp://sign.example"));
    }

    #[test]
    fn reports_denied_login() {
        assert_eq!(
            parse_callback(
                &request("/callback?error=access_denied&error_description=nope&state=s1"),
                "s1"
            ),
            Callback::Failed("nope".into())
        );
    }
}
