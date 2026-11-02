//! Relay for P2P Share, meant to run behind an HTTPS reverse proxy.
//!
//! One plain-HTTP port serves:
//! - `/relay`: iroh's relay (WebSocket), which carries the end-to-end
//!   encrypted traffic between endpoints that cannot reach each other
//!   directly and lets them set up direct connections;
//! - `/ping`, `/generate_204`: the probes iroh uses to pick its relay;
//! - `/pkarr/<id>`: the address directory where endpoints publish their
//!   signed address and look up their friends'; it stands in for iroh's
//!   public directory too (see `upstream.rs`);
//! - `/tunnel`: a way to iroh's public relays for clients on networks that
//!   block them (see `tunnel.rs`);
//! - `/healthz`: health check.
//!
//! Settings come from environment variables, see the README.

mod pkarr;
mod tunnel;
mod upstream;

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
use crate::tunnel::{Allowed, Tunnels};
use crate::upstream::Upstream;

const DEFAULT_LISTEN: &str = "0.0.0.0:3340";
const DEFAULT_MAX_RECORDS: usize = 100_000;
/// iroh's public relays (`*.relay.n0.iroh.link`).
const DEFAULT_TUNNEL_HOSTS: &str = "relay.n0.iroh.link";
const DEFAULT_MAX_TUNNELS: usize = 256;
const DEFAULT_UPSTREAM_PKARR: &str = "https://dns.iroh.link/pkarr";
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
    tunnel_hosts: Allowed,
    max_tunnels: usize,
    upstream: Option<Upstream>,
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
        // Set but empty: turned off.
        let set_or = |name: &str, default: &str| std::env::var(name).unwrap_or_else(|_| default.into());
        let tunnel_hosts = Allowed::parse(&set_or("TUNNEL_HOSTS", DEFAULT_TUNNEL_HOSTS))
            .map_err(|e| format!("TUNNEL_HOSTS: {e}"))?;
        let max_tunnels = match var("MAX_TUNNELS") {
            Some(v) => v.parse().map_err(|e| format!("MAX_TUNNELS: {e}"))?,
            None => DEFAULT_MAX_TUNNELS,
        };
        let upstream = Upstream::parse(&set_or("UPSTREAM_PKARR", DEFAULT_UPSTREAM_PKARR))
            .map_err(|e| format!("UPSTREAM_PKARR: {e}"))?;
        Ok(Config {
            listen,
            token: var("RELAY_TOKEN"),
            rate_limit,
            max_records,
            tunnel_hosts,
            max_tunnels,
            upstream,
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
    shared: Arc<Shared>,
}

/// What every connection uses.
struct Shared {
    store: Store,
    upstream: Option<Upstream>,
    tunnels: Arc<Tunnels>,
    token: Option<String>,
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
        let shared = self.shared.clone();
        if req.uri().path() == "/tunnel" {
            return Box::pin(async move {
                Ok(tunnel::open(&shared.tunnels, shared.token.as_deref(), req).await)
            });
        }
        Box::pin(async move { Ok(handle(&shared, req).await) })
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

async fn handle(shared: &Arc<Shared>, req: Request<Incoming>) -> Response<BytesBody> {
    let store = &shared.store;
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
                Method::GET => match lookup(shared, id).await {
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
                        Ok(()) => {
                            // Also where friends without this relay look.
                            if shared.upstream.is_some() {
                                let shared = shared.clone();
                                let id = id.to_string();
                                tokio::spawn(async move {
                                    if let Some(up) = &shared.upstream {
                                        up.put(&id, body).await;
                                    }
                                });
                            }
                            reply(StatusCode::NO_CONTENT, empty())
                        }
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

/// The record of `id`: ours, or else the upstream directory's, checked.
async fn lookup(shared: &Shared, id: &str) -> Option<Vec<u8>> {
    if let Some(payload) = shared.store.get(id) {
        return Some(payload);
    }
    let payload = shared.upstream.as_ref()?.get(id).await?;
    pkarr::verify(id, &payload).then(|| payload.to_vec())
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

async fn serve(stream: TcpStream, relay: RelayService, shared: Arc<Shared>) {
    let _ = stream.set_nodelay(true);
    let router = Router {
        relay: RelayServiceWithNotify::new(relay, Arc::new(Notify::new())),
        shared,
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
    let shared = Arc::new(Shared {
        store: Store::new(config.max_records),
        upstream: config.upstream,
        tunnels: Arc::new(Tunnels {
            allowed: config.tunnel_hosts,
            slots: tokio::sync::Semaphore::new(config.max_tunnels),
        }),
        token: config.token.clone(),
    });

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
    info!(
        "tunnel to iroh's relays {}, upstream directory {}",
        if shared.tunnels.allowed.is_empty() { "off" } else { "on" },
        shared.upstream.as_ref().map_or("off".into(), |u| u.describe()),
    );

    let pruner = {
        let shared = shared.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(600));
            loop {
                tick.tick().await;
                shared.store.prune();
            }
        })
    };

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    tokio::spawn(serve(stream, relay.clone(), shared.clone()));
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
