// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `misty-server` — the Misty sync service.
//!
//! Configuration comes from the environment; see `README.md`. **TLS is not
//! terminated here.** Run this behind a reverse proxy that speaks TLS 1.3, and
//! bind it to loopback or a private interface. Terminating TLS in-process would
//! mean a certificate store, an ACME client, and a rustls stack inside the one
//! component whose whole selling point is that it holds nothing worth stealing.

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::sync::Arc;

use misty_server::store::Store;
use misty_server::time_key::KeyOrigin;
use misty_server::{serve as serve_http, AppState, Config, SqliteStore, TimeKey};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Startup failures happen before, or instead of, a working
            // subscriber, so they go to stderr as well as to the log.
            eprintln!("misty-server: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let config = Config::from_env()?;
    let time_key = TimeKey::from_env()?;

    tracing::info!(
        target: "misty_server",
        bind = %config.bind,
        database = %config.database.display(),
        time_key_origin = ?time_key.origin(),
        time_public_key = %hex::encode(time_key.public_key()),
        "starting",
    );
    warn_about_posture(&config, &time_key);

    let store = Arc::new(SqliteStore::open(&config.database)?);
    // Migrations run inside `open`; this makes the forward-only guarantee an
    // explicit startup step rather than a side effect.
    store.migrate()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(config, time_key, store))
}

async fn serve(
    config: Config,
    time_key: TimeKey,
    store: Arc<SqliteStore>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!(target: "misty_server", local = %listener.local_addr()?, "listening");

    let sweep_interval = config.sweep_interval;
    let tombstone_retention = config.tombstone_retention;
    let state = AppState::new(store.clone(), config, time_key);
    let sweeper = tokio::spawn(sweep_forever(
        store,
        Arc::clone(&state.limiter),
        sweep_interval,
        tombstone_retention,
    ));

    serve_http(listener, state, shutdown()).await?;

    sweeper.abort();
    tracing::info!(target: "misty_server", "stopped");
    Ok(())
}

/// Deletes expired challenges, tokens, and enrollments, releases tombstone slots,
/// and forgets idle rate-limit buckets — which is what keeps addresses from
/// accumulating in memory.
async fn sweep_forever(
    store: Arc<SqliteStore>,
    limiter: Arc<misty_server::rate_limit::RateLimiter>,
    interval: std::time::Duration,
    tombstone_retention: std::time::Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        limiter.evict_idle();

        let store = Arc::clone(&store);
        let retention = i64::try_from(tombstone_retention.as_millis()).unwrap_or(i64::MAX);
        let swept = tokio::task::spawn_blocking(move || {
            let now = misty_server::time_key::now_unix_ms();
            store.sweep(now, now.saturating_sub(retention))
        })
        .await;
        match swept {
            Ok(Ok(swept)) if swept != Default::default() => {
                tracing::info!(
                    target: "misty_server::sweep",
                    challenges = swept.challenges,
                    tokens = swept.tokens,
                    enrollments = swept.enrollments,
                    tombstones = swept.tombstones,
                    "swept",
                );
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                tracing::error!(target: "misty_server::sweep", detail = %error, "sweep failed");
            }
            Err(_) => {
                tracing::error!(target: "misty_server::sweep", "sweep task failed");
            }
        }
    }
}

/// Resolves on `SIGINT` or `SIGTERM`, which lets `axum::serve` finish in-flight
/// requests before the process exits. A container runtime sends `SIGTERM`; a
/// terminal sends `SIGINT`; a server that ignored one of them would be killed
/// mid-transaction by whichever it ignored.
async fn shutdown() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => {
                tracing::error!(target: "misty_server", detail = %error, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
    tracing::info!(target: "misty_server", "shutting down");
}

fn init_tracing() {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let filter = tracing_subscriber::EnvFilter::try_from_env("MISTY_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    // JSON by default: these lines are meant to be shipped and queried, and a
    // structured line cannot be accidentally reformatted into something that
    // reveals more than its fields.
    let json = std::env::var("MISTY_LOG_FORMAT")
        .map(|v| v != "text")
        .unwrap_or(true);
    let registry = tracing_subscriber::registry().with(filter);
    if json {
        registry
            .with(tracing_subscriber::fmt::layer().json().with_target(true))
            .init();
    } else {
        registry
            .with(tracing_subscriber::fmt::layer().with_target(true))
            .init();
    }
}

/// Says out loud what an operator would otherwise have to infer.
fn warn_about_posture(config: &Config, time_key: &TimeKey) {
    if time_key.origin() == KeyOrigin::Ephemeral {
        tracing::warn!(
            target: "misty_server",
            "no MISTY_TIME_SIGNING_KEY: generated an ephemeral /v1/time key. Every restart \
             invalidates the key clients have pinned, so signed time stops working. Set one \
             before this instance has users.",
        );
    }
    if !config.bind.ip().is_loopback() {
        tracing::warn!(
            target: "misty_server",
            "bound to a non-loopback address. TLS is NOT terminated by this process: put a \
             TLS 1.3 reverse proxy in front of it, or every request travels in the clear.",
        );
    }
    if config.registration_token.is_none() && config.max_vaults.is_none() {
        tracing::warn!(
            target: "misty_server",
            "MISTY_REGISTRATION_TOKEN and MISTY_MAX_VAULTS are both unset: anyone who can \
             reach this socket can create vaults. That is fine on a private network and a \
             free disk on a public one.",
        );
    }
}
