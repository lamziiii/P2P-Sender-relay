//! Relay for P2P Share, meant to run behind an HTTPS reverse proxy.
//!
//! One plain-HTTP port serves:
//! - `/relay`: iroh's relay (WebSocket), which carries the end-to-end
//!   encrypted traffic between endpoints that cannot reach each other
//!   directly and lets them set up direct connections;
//! - `/ping`, `/generate_204`: the probes iroh uses to pick its relay;
//! - `/pkarr/<id>`: the address directory where endpoints publish their
//!   signed address and look up their friends';
//! - `/healthz`: health check.
//!
//! Settings come from environment variables, see the README.

mod pkarr;

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use iroh_relay::server::http_server::{
    BytesBody, Handlers, HyperError, RelayService, RelayServiceWithNotify,
};
use iroh_relay::server::streams::MaybeTlsStream;
use iroh_relay::server::{Access, AccessControl, ClientRateLimit, ClientRequest, Metrics};
use iroh_relay::KeyCache;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use crate::pkarr::{PutError, Store};

const DEFAULT_LISTEN: &str = "0.0.0.0:3340";
const DEFAULT_MAX_RECORDS: usize = 100_000;
/// Same as iroh's own relays.
const KEY_CACHE_CAPACITY: usize = 1024 * 1024;
/// A signed packet is at most 1104 bytes.
const MAX_PKARR_BODY: usize = 2048;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

struct Config {
    listen: SocketAddr,
    token: Option<String>,
    rate_limit: Option<ClientRateLimit>,
    max_records: usize,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let listen = var("LISTEN_ADDR")
            .unwrap_or_else(|| DEFAULT_LISTEN.into())
            .parse()
            .map_err(|e| format!("LISTEN_ADDR: {e}"))?;
        let rate_limit = match var("RATE_LIMIT_KBPS") {
            Some(v) => {
                let kbps: u32 = v.parse().map_err(|e| format!("RATE_LIMIT_KBPS: {e}"))?;
                let bytes = NonZeroU32::new(kbps.saturating_mul(1024))
                    .ok_or("RATE_LIMIT_KBPS must be greater than 0")?;
                let mut limit = ClientRateLimit::new(bytes);
                limit.max_burst_bytes = Some(bytes.saturating_mul(NonZeroU32::new(2).unwrap()));
                Some(limit)
            }
            None => None,
        };
        let max_records = match var("MAX_RECORDS") {
            Some(v) => v.parse().map_err(|e| format!("MAX_RECORDS: {e}"))?,
            None => DEFAULT_MAX_RECORDS,
        };
        Ok(Config {
            listen,
            token: var("RELAY_TOKEN"),
            rate_limit,
            max_records,
        })
    }
}

/// Admits everyone, or only clients sending the configured token.
#[derive(Debug)]
struct TokenAccess(Option<String>);

impl AccessControl for TokenAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let Some(expected) = &self.0 else {
            return Access::Allow;
        };
        if request
            .auth_token()
            .is_some_and(|t| constant_time_eq(t.as_bytes(), expected.as_bytes()))
        {
            Access::Allow
        } else {
            debug!(endpoint = %request.endpoint_id().fmt_short(), "refused: bad token");
            Access::Deny {
                reason: Some("invalid token".into()),
            }
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Clone)]
struct Router {
    relay: RelayServiceWithNotify,
    store: Arc<Store>,
}

type BoxFuture = Pin<Box<dyn Future<Output = Result<Response<BytesBody>, HyperError>> + Send>>;

impl Service<Request<Incoming>> for Router {
    type Response = Response<BytesBody>;
    type Error = HyperError;
    type Future = BoxFuture;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        if req.uri().path() == "/relay" {
            return Box::pin(self.relay.call(req));
        }
        let store = self.store.clone();
        Box::pin(async move { Ok(handle(&store, req).await) })
    }
}

fn full(body: impl Into<Bytes>) -> BytesBody {
    Box::new(Full::new(body.into()))
}

fn empty() -> BytesBody {
    Box::new(Empty::<Bytes>::new().map_err(|e: Infallible| match e {}))
}

fn reply(status: StatusCode, body: BytesBody) -> Response<BytesBody> {
    let mut res = Response::new(body);
    *res.status_mut() = status;
    res
}

async fn handle(store: &Store, req: Request<Incoming>) -> Response<BytesBody> {
    let path = req.uri().path().to_owned();
    match (req.method(), path.as_str()) {
        (&Method::GET, "/" | "/index.html") => reply(
            StatusCode::OK,
            full("P2P Share relay\n"),
        ),
        (&Method::GET, "/ping") => {
            let mut res = reply(StatusCode::OK, empty());
            res.headers_mut()
                .insert("Access-Control-Allow-Origin", HeaderValue::from_static("*"));
            res
        }
        (&Method::GET, "/generate_204") => generate_204(&req),
        (&Method::GET, "/healthz") => {
            let mut res = reply(
                StatusCode::OK,
                full(format!(
                    "{{\"status\":\"ok\",\"version\":\"{}\",\"records\":{}}}",
                    env!("CARGO_PKG_VERSION"),
                    store.len()
                )),
            );
            res.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            res
        }
        (&Method::GET, "/robots.txt") => {
            reply(StatusCode::OK, full("User-agent: *\nDisallow: /\n"))
        }
        (method, p) if p.starts_with("/pkarr/") => {
            let id = &p["/pkarr/".len()..];
            match *method {
                Method::GET => match store.get(id) {
                    Some(payload) => {
                        let mut res = reply(StatusCode::OK, full(payload));
                        res.headers_mut().insert(
                            CONTENT_TYPE,
                            HeaderValue::from_static("application/pkarr.org/relays#payload"),
                        );
                        res
                    }
                    None => reply(StatusCode::NOT_FOUND, empty()),
                },
                Method::PUT => {
                    let body = match Limited::new(req.into_body(), MAX_PKARR_BODY).collect().await {
                        Ok(b) => b.to_bytes(),
                        Err(_) => return reply(StatusCode::PAYLOAD_TOO_LARGE, empty()),
                    };
                    match store.put(id, &body) {
                        Ok(()) => reply(StatusCode::NO_CONTENT, empty()),
                        Err(PutError::Invalid) => reply(StatusCode::BAD_REQUEST, empty()),
                        Err(PutError::Outdated) => reply(StatusCode::CONFLICT, empty()),
                        Err(PutError::Full) => {
                            warn!("address directory full, raise MAX_RECORDS");
                            reply(StatusCode::SERVICE_UNAVAILABLE, empty())
                        }
                    }
                }
                _ => reply(StatusCode::METHOD_NOT_ALLOWED, empty()),
            }
        }
        _ => reply(StatusCode::NOT_FOUND, full("Not Found")),
    }
}

/// Captive-portal check: echo iroh's challenge.
fn generate_204(req: &Request<Incoming>) -> Response<BytesBody> {
    let mut res = reply(StatusCode::NO_CONTENT, empty());
    if let Some(challenge) = req
        .headers()
        .get("X-Iroh-Challenge")
        .and_then(|c| c.to_str().ok())
        .filter(|c| {
            !c.is_empty()
                && c.len() < 64
                && c.chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
        })
        && let Ok(value) = HeaderValue::from_str(&format!("response {challenge}"))
    {
        res.headers_mut().insert("X-Iroh-Response", value);
    }
    res
}

async fn serve(stream: TcpStream, relay: RelayService, store: Arc<Store>) {
    let _ = stream.set_nodelay(true);
    let router = Router {
        relay: RelayServiceWithNotify::new(relay, Arc::new(Notify::new())),
        store,
    };
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .serve_connection(TokioIo::new(MaybeTlsStream::Plain(stream)), router)
        .with_upgrades();
    if let Err(e) = conn.await {
        debug!("connection ended: {e}");
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

/// `p2p-relay healthcheck`: exit status for Docker's HEALTHCHECK.
async fn healthcheck(listen: SocketAddr) -> bool {
    let port = listen.port();
    let check = async {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
        s.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
            .await
            .ok()?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.ok()?;
        Some(buf.starts_with(b"HTTP/1.0 200") || buf.starts_with(b"HTTP/1.1 200"))
    };
    tokio::time::timeout(Duration::from_secs(5), check)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

#[tokio::main]
async fn main() {
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("invalid setting: {e}");
            std::process::exit(2);
        }
    };
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(if healthcheck(config.listen).await { 0 } else { 1 });
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,iroh_relay=warn".into()),
        )
        .init();

    let relay = RelayService::new(
        Handlers::default(),
        Default::default(),
        config.rate_limit,
        KeyCache::new(KEY_CACHE_CAPACITY),
        Arc::new(TokenAccess(config.token.clone())),
        Arc::new(Metrics::default()),
    );
    let store = Arc::new(Store::new(config.max_records));

    let listener = match TcpListener::bind(config.listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot listen on {}: {e}", config.listen);
            std::process::exit(1);
        }
    };
    info!(
        "P2P Share relay {} listening on http://{} (token {}, rate limit {})",
        env!("CARGO_PKG_VERSION"),
        config.listen,
        if config.token.is_some() { "required" } else { "not required" },
        match &config.rate_limit {
            Some(l) => format!("{} KB/s", l.bytes_per_second.get() / 1024),
            None => "none".into(),
        },
    );

    let pruner = {
        let store = store.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(600));
            loop {
                tick.tick().await;
                store.prune();
            }
        })
    };

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    tokio::spawn(serve(stream, relay.clone(), store.clone()));
                }
                Err(e) => {
                    warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            _ = &mut shutdown => break,
        }
    }
    info!("shutting down");
    pruner.abort();
    relay.shutdown().await;
}
