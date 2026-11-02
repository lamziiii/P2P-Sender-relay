//! Two iroh endpoints that can only talk through the relay (no UDP) and only
//! know each other's ID find each other through the relay's address directory;
//! and the tunnel passes bytes to an allowed destination only, with the token.

use std::process::{Child, Command};
use std::time::Duration;

use iroh::address_lookup::{PkarrPublisher, PkarrResolver};
use iroh::endpoint::presets;
use iroh::{Endpoint, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey};

const ALPN: &[u8] = b"p2p-relay-test";
const TOKEN: &str = "s3cret";

struct Relay(Child);

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn start_relay(port: u16, tunnel_hosts: &str) -> Relay {
    let child = Command::new(env!("CARGO_BIN_EXE_p2p-relay"))
        .env("LISTEN_ADDR", format!("127.0.0.1:{port}"))
        .env("RELAY_TOKEN", TOKEN)
        // Nothing sent to iroh's public directory from the tests.
        .env("UPSTREAM_PKARR", "")
        .env("TUNNEL_HOSTS", tunnel_hosts)
        .spawn()
        .expect("start relay");
    Relay(child)
}

async fn wait_listening(port: u16) {
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn endpoint(base: &str, token: Option<&str>) -> Endpoint {
    let url: RelayUrl = base.parse().unwrap();
    let mut relay = RelayConfig::new(url, None);
    if let Some(t) = token {
        relay = relay.with_auth_token(t);
    }
    let pkarr = format!("{base}pkarr").parse().unwrap();
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Custom(RelayMap::from(relay)))
        .clear_ip_transports()
        .address_lookup(PkarrPublisher::builder(pkarr))
        .address_lookup(PkarrResolver::builder(format!("{base}pkarr").parse().unwrap()))
        .bind()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn relayed_connection_found_through_directory() {
    // P2P_RELAY_URL tests a running relay (e.g. behind a reverse proxy)
    // that uses the same token.
    let (base, _relay) = match std::env::var("P2P_RELAY_URL") {
        Ok(url) => (url, None),
        Err(_) => {
            let port = 43_000 + (std::process::id() % 2000) as u16;
            let relay = start_relay(port, "");
            wait_listening(port).await;
            (format!("http://127.0.0.1:{port}/"), Some(relay))
        }
    };

    let server = endpoint(&base, Some(TOKEN)).await;
    let client = endpoint(&base, Some(TOKEN)).await;
    tokio::time::timeout(Duration::from_secs(20), server.online())
        .await
        .expect("server reaches the relay");

    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let msg = recv.read_to_end(1024).await.unwrap();
            send.write_all(&msg).await.unwrap();
            send.finish().unwrap();
            conn.closed().await;
        })
    };

    // Give the server time to publish its address.
    let id = server.id();
    let conn = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match client.connect(id, ALPN).await {
                Ok(c) => break c,
                Err(e) => {
                    eprintln!("retrying: {e:#}");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    })
    .await
    .expect("client connects through the relay");
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"bonjour").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(1024).await.unwrap(), b"bonjour");
    conn.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;

    // Without the token the relay refuses the client.
    let intruder = endpoint(&base, None).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), intruder.online())
            .await
            .is_err(),
        "a client without the token must not get online"
    );
}

/// A WebSocket to the tunnel, or the HTTP status that refused it.
async fn open_tunnel(
    port: u16,
    to: &str,
    token: Option<&str>,
) -> Result<tokio_websockets::WebSocketStream<tokio_websockets::MaybeTlsStream<tokio::net::TcpStream>>, String> {
    let uri: hyper::Uri = format!("ws://127.0.0.1:{port}/tunnel?to={to}").parse().unwrap();
    let mut builder = tokio_websockets::ClientBuilder::from_uri(uri);
    if let Some(t) = token {
        builder = builder
            .add_header(
                hyper::header::AUTHORIZATION,
                format!("Bearer {t}").parse().unwrap(),
            )
            .unwrap();
    }
    builder.connect().await.map(|(ws, _)| ws).map_err(|e| e.to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn tunnel_passes_bytes_to_allowed_destinations_only() {
    use n0_future::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // An echo server: the tunnel's destination.
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let port = 45_000 + (std::process::id() % 2000) as u16;
    let _relay = start_relay(port, &format!("127.0.0.1:{echo_port}"));
    wait_listening(port).await;
    let to = format!("127.0.0.1:{echo_port}");

    let mut ws = open_tunnel(port, &to, Some(TOKEN)).await.expect("tunnel with the token");
    ws.send(tokio_websockets::Message::binary(&b"bonjour"[..])).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("an answer")
        .expect("a message")
        .expect("no error");
    assert_eq!(&*reply.into_payload(), b"bonjour");

    assert!(open_tunnel(port, &to, None).await.is_err(), "no token, no tunnel");
    assert!(open_tunnel(port, &to, Some("wrong")).await.is_err(), "wrong token, no tunnel");
    assert!(
        open_tunnel(port, "example.com:443", Some(TOKEN)).await.is_err(),
        "only allowed destinations"
    );
}
