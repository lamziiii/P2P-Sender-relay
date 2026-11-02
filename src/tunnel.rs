//! `/tunnel`: for P2P Share on networks that block iroh's public relays. A
//! client with the token opens a WebSocket to `/tunnel?to=<host>:<port>`;
//! the relay connects to that address (one of iroh's relays by default, see
//! `TUNNEL_HOSTS`) and passes the bytes both ways. The client speaks TLS
//! with the target inside the tunnel, so the relay never sees what goes
//! through, and the target still checks who the client is.

use std::time::Duration;

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::{
    AUTHORIZATION, CONNECTION, HeaderValue, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY,
    SEC_WEBSOCKET_VERSION, UPGRADE,
};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use n0_future::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_websockets::{Message, WebSocketStream};
use tracing::debug;

use crate::{BytesBody, constant_time_eq, empty, reply};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const BUFFER: usize = 64 * 1024;
/// Largest message accepted from a client (they send at most `BUFFER`).
const MAX_MESSAGE: usize = 1024 * 1024;
const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Where tunnels may lead: a domain and its subdomains on port 443, or an
/// exact `host:port`.
#[derive(Debug, PartialEq)]
pub struct Allowed(Vec<(String, Option<u16>)>);

impl Allowed {
    /// Comma-separated entries; empty: no tunnel at all.
    pub fn parse(list: &str) -> Result<Self, String> {
        let mut entries = Vec::new();
        for entry in list.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let entry = entry.trim_end_matches('.').to_ascii_lowercase();
            match entry.rsplit_once(':') {
                Some((host, port)) => {
                    let port = port.parse().map_err(|_| format!("bad port in {entry}"))?;
                    entries.push((host.to_string(), Some(port)));
                }
                None => entries.push((entry, None)),
            }
        }
        Ok(Allowed(entries))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn allows(&self, host: &str, port: u16) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.0.iter().any(|(entry, entry_port)| match entry_port {
            Some(p) => *p == port && host == *entry,
            None => {
                port == 443
                    && (host == *entry
                        || host
                            .strip_suffix(entry.as_str())
                            .is_some_and(|rest| rest.ends_with('.')))
            }
        })
    }
}

pub struct Tunnels {
    pub allowed: Allowed,
    /// Tunnels open at once, at most.
    pub slots: Semaphore,
}

/// Answers a tunnel request: 101 and the piping in the background, or why not.
pub async fn open(
    tunnels: &std::sync::Arc<Tunnels>,
    token: Option<&str>,
    mut req: Request<Incoming>,
) -> Response<BytesBody> {
    if tunnels.allowed.is_empty() {
        return reply(StatusCode::NOT_FOUND, empty());
    }
    if let Some(expected) = token {
        let sent = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if !sent.is_some_and(|t| constant_time_eq(t.as_bytes(), expected.as_bytes())) {
            return reply(StatusCode::UNAUTHORIZED, empty());
        }
    }
    let websocket = req
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        && req
            .headers()
            .get(SEC_WEBSOCKET_VERSION)
            .is_some_and(|v| v == "13");
    let Some(key) = req
        .headers()
        .get(SEC_WEBSOCKET_KEY)
        .cloned()
        .filter(|_| websocket)
    else {
        return reply(StatusCode::BAD_REQUEST, empty());
    };
    let Some((host, port)) = target(req.uri().query()) else {
        return reply(StatusCode::BAD_REQUEST, empty());
    };
    if !tunnels.allowed.allows(&host, port) {
        debug!(%host, port, "tunnel refused: not an allowed destination");
        return reply(StatusCode::FORBIDDEN, empty());
    }
    let Ok(slot) = tunnels.slots.try_acquire() else {
        return reply(StatusCode::SERVICE_UNAVAILABLE, empty());
    };
    // Connected first: a target that does not answer is a plain error.
    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
    {
        Ok(Ok(tcp)) => tcp,
        _ => {
            debug!(%host, port, "tunnel: target unreachable");
            return reply(StatusCode::BAD_GATEWAY, empty());
        }
    };
    let _ = tcp.set_nodelay(true);
    slot.forget();
    let tunnels = tunnels.clone();
    tokio::spawn(async move {
        if let Ok(upgraded) = hyper::upgrade::on(&mut req).await {
            let ws = tokio_websockets::ServerBuilder::new()
                .limits(tokio_websockets::Limits::default().max_payload_len(Some(MAX_MESSAGE)))
                .serve(TokioIo::new(upgraded));
            pipe(ws, tcp).await;
        }
        tunnels.slots.add_permits(1);
    });
    let mut res = reply(StatusCode::SWITCHING_PROTOCOLS, empty());
    let headers = res.headers_mut();
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    if let Ok(accept) = HeaderValue::from_str(&accept_key(key.as_bytes())) {
        headers.insert(SEC_WEBSOCKET_ACCEPT, accept);
    }
    res
}

/// `to=<host>:<port>` of the query.
fn target(query: Option<&str>) -> Option<(String, u16)> {
    let to = query?
        .split('&')
        .find_map(|pair| pair.strip_prefix("to="))?;
    let (host, port) = to.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty()).then(|| (host.to_string(), port))
}

fn accept_key(key: &[u8]) -> String {
    use sha1::Digest;
    let mut sha1 = sha1::Sha1::new();
    sha1.update(key);
    sha1.update(WEBSOCKET_GUID);
    data_encoding::BASE64.encode(&sha1.finalize())
}

/// Bytes both ways until one side ends.
async fn pipe<S: AsyncRead + AsyncWrite + Unpin>(mut ws: WebSocketStream<S>, mut tcp: TcpStream) {
    let mut buf = vec![0u8; BUFFER];
    loop {
        tokio::select! {
            read = tcp.read(&mut buf) => match read {
                Ok(n) if n > 0 => {
                    if ws.send(Message::binary(Bytes::copy_from_slice(&buf[..n]))).await.is_err() {
                        return;
                    }
                }
                _ => break,
            },
            msg = ws.next() => match msg {
                Some(Ok(m)) if m.is_binary() => {
                    let data: Bytes = m.into_payload().into();
                    if tcp.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Some(Ok(m)) if m.is_close() => break,
                // Pings are answered by the WebSocket itself.
                Some(Ok(_)) => {}
                _ => break,
            },
        }
    }
    let _ = ws.close().await;
    let _ = tcp.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_destinations() {
        let a = Allowed::parse("relay.n0.iroh.link, 127.0.0.1:4433").unwrap();
        assert!(a.allows("euc1-1.relay.n0.iroh.link", 443));
        assert!(a.allows("euc1-1.relay.n0.iroh.link.", 443));
        assert!(a.allows("relay.n0.iroh.link", 443));
        assert!(!a.allows("euc1-1.relay.n0.iroh.link", 80));
        assert!(!a.allows("evilrelay.n0.iroh.link", 443));
        assert!(!a.allows("relay.n0.iroh.link.evil.com", 443));
        assert!(!a.allows("example.com", 443));
        assert!(a.allows("127.0.0.1", 4433));
        assert!(!a.allows("127.0.0.1", 443));
        assert!(Allowed::parse("").unwrap().is_empty());
    }

    #[test]
    fn tunnel_target() {
        assert_eq!(
            target(Some("to=euc1-1.relay.n0.iroh.link:443")),
            Some(("euc1-1.relay.n0.iroh.link".into(), 443))
        );
        assert_eq!(
            target(Some("x=1&to=[::1]:8443")),
            Some(("::1".into(), 8443))
        );
        assert_eq!(target(Some("to=nohost")), None);
        assert_eq!(target(None), None);
    }

    #[test]
    fn accept_key_of_the_rfc_example() {
        assert_eq!(
            accept_key(b"dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
