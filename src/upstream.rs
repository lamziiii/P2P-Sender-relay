//! iroh's public address directory (`UPSTREAM_PKARR`), so that the relay's
//! own directory stands in for it on networks that block it: records
//! published here are passed on, and records not found here are looked up
//! there. Records are signed by their owner: what comes back is checked
//! before it is served.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::HOST;
use hyper::{Method, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

const TIMEOUT: Duration = Duration::from_secs(5);
/// A signed packet is at most 1104 bytes.
const MAX_BODY: usize = 2048;

pub struct Upstream {
    host: String,
    port: u16,
    /// Without its trailing slash, e.g. `/pkarr`.
    path: String,
    tls: TlsConnector,
}

impl Upstream {
    /// An `https://` URL; empty: no upstream.
    pub fn parse(url: &str) -> Result<Option<Self>, String> {
        let url = url.trim();
        if url.is_empty() {
            return Ok(None);
        }
        let uri: Uri = url.parse().map_err(|e| format!("{e}"))?;
        if uri.scheme_str() != Some("https") {
            return Err("must start with https://".into());
        }
        let host = uri.host().ok_or("no host")?.to_string();
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Some(Upstream {
            host,
            port: uri.port_u16().unwrap_or(443),
            path: uri.path().trim_end_matches('/').to_string(),
            tls: TlsConnector::from(Arc::new(config)),
        }))
    }

    pub fn describe(&self) -> String {
        format!("https://{}{}", self.host, self.path)
    }

    /// The record of `z32` there, as found (to be checked by the caller).
    pub async fn get(&self, z32: &str) -> Option<Bytes> {
        match self.request(Method::GET, z32, Bytes::new()).await {
            Some((StatusCode::OK, body)) => Some(body),
            _ => None,
        }
    }

    pub async fn put(&self, z32: &str, payload: Bytes) {
        let status = self
            .request(Method::PUT, z32, payload)
            .await
            .map(|(s, _)| s);
        if !status.is_some_and(|s| s.is_success()) {
            debug!(?status, "record not passed on to the upstream directory");
        }
    }

    async fn request(&self, method: Method, z32: &str, body: Bytes) -> Option<(StatusCode, Bytes)> {
        let exchange = async {
            let tcp = TcpStream::connect((self.host.as_str(), self.port))
                .await
                .ok()?;
            let name = rustls::pki_types::ServerName::try_from(self.host.clone()).ok()?;
            let tls = self.tls.connect(name, tcp).await.ok()?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .ok()?;
            let req = Request::builder()
                .method(method)
                .uri(format!("{}/{z32}", self.path))
                .header(HOST, self.host.as_str())
                .body(Full::new(body))
                .ok()?;
            // The sender is dropped with the exchange, which lets the connection end.
            let exchange = async move {
                let res = sender.send_request(req).await.ok()?;
                let status = res.status();
                let body = Limited::new(res.into_body(), MAX_BODY)
                    .collect()
                    .await
                    .ok()?
                    .to_bytes();
                Some((status, body))
            };
            let (result, _) = tokio::join!(exchange, conn);
            result
        };
        tokio::time::timeout(TIMEOUT, exchange).await.ok().flatten()
    }
}
