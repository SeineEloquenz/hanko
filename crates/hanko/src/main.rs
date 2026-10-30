use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use hanko::config::Config;

/// Sign Android artifacts for verified GitHub Actions jobs and Kanidm users.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Only validate the config.
    #[arg(long)]
    check: bool,
    config: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    init_tracing();

    let config = match Config::load(&args.config) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if args.check {
        return ExitCode::SUCCESS;
    }

    match hanko::server::serve(config, shutdown_signal()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing() {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "hanko=info".into());
    let journald = std::env::var_os("JOURNAL_STREAM").and_then(|_| tracing_journald::layer().ok());
    let registry = tracing_subscriber::registry().with(filter);
    let _ = match journald {
        Some(layer) => registry.with(layer).try_init(),
        None => registry.with(fmt::layer()).try_init(),
    };
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    };
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
