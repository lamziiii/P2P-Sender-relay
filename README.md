# P2P Share Relay

Self-hosted relay for [P2P Share](https://github.com/lamziiii/P2P-Sender), for networks that block iroh's public relays (for example eduroam behind a FortiGate, which blocks `*.iroh.link` and outgoing UDP).

It serves everything over **one plain-HTTP port**, meant to sit behind your HTTPS reverse proxy on port 443:

| Path | Role |
| --- | --- |
| `/relay` | iroh relay (WebSocket): carries the end-to-end encrypted traffic between friends who cannot reach each other directly |
| `/pkarr/<id>` | address directory: endpoints publish their signed address and look up their friends'. It stands in for iroh's public one (`dns.iroh.link`): records published here are passed on to it, and records not found here are looked up there |
| `/tunnel` | a way to iroh's public relays for P2P Share on networks that block them (WebSocket, with the token): the relay connects to the iroh relay and passes the bytes on |
| `/ping`, `/generate_204` | probes iroh uses to measure and check the relay |
| `/healthz` | health check |

The relay never sees message or file contents: everything is encrypted end to end with the friends' keys. Through the tunnel, the app speaks TLS with iroh's relay itself, so this relay only passes encrypted bytes, and only to iroh's relays (`TUNNEL_HOSTS`): it is not an open proxy. Address records are signed by their owner, so the relay cannot forge them.

## Run it

```bash
docker run -d --name p2p-relay --restart unless-stopped \
  -p 127.0.0.1:3340:3340 \
  -e RELAY_TOKEN=$(openssl rand -hex 24) \
  ghcr.io/lamziiii/p2p-sender-relay:latest
```

Or with [docker-compose.yml](docker-compose.yml) (put `RELAY_TOKEN=...` in a `.env` file next to it):

```bash
docker compose up -d
```

The image is about 3.5 MB (static binary on an empty image), for `linux/amd64` and `linux/arm64`.

### Settings

| Variable | Default | |
| --- | --- | --- |
| `RELAY_TOKEN` | none | When set, only clients sending this token can use the relay. Recommended. |
| `RATE_LIMIT_KBPS` | none | Maximum receive rate per client, in KB/s. |
| `MAX_RECORDS` | `100000` | Maximum number of addresses in the directory. |
| `TUNNEL_HOSTS` | `relay.n0.iroh.link` | Where the tunnel may lead, comma-separated: a domain and its subdomains on port 443, or an exact `host:port`. Empty: no tunnel. |
| `MAX_TUNNELS` | `256` | Tunnels open at once, at most. |
| `UPSTREAM_PKARR` | `https://dns.iroh.link/pkarr` | iroh's public directory, which the relay's stands in for. Empty: the relay's directory stays on its own. |
| `LISTEN_ADDR` | `0.0.0.0:3340` | Listening address inside the container. |
| `RUST_LOG` | `info,iroh_relay=warn` | Log level. |

## Reverse proxy

The relay must be at the root of a (sub)domain with a valid public certificate (Let's Encrypt is fine), and the proxy must pass WebSocket upgrades. Use a neutral name such as `files.example.com`, not one containing "relay" or "p2p", to avoid being classified by filtering firewalls.

**Caddy**

```
files.example.com {
    reverse_proxy 127.0.0.1:3340
}
```

**nginx**

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl http2;
    server_name files.example.com;
    # ssl_certificate ...;

    location / {
        proxy_pass http://127.0.0.1:3340;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_buffering off;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
    }
}
```

**Nginx Proxy Manager**: a proxy host to `p2p-relay:3340` (or `127.0.0.1:3340`) with *Websockets Support* enabled and an SSL certificate.

**Traefik** (labels on the container):

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.p2p-relay.rule=Host(`files.example.com`)
  - traefik.http.routers.p2p-relay.entrypoints=websecure
  - traefik.http.routers.p2p-relay.tls.certresolver=letsencrypt
  - traefik.http.services.p2p-relay.loadbalancer.server.port=3340
```

Cloudflare's proxy (orange cloud) works too, as it passes WebSockets.

Check it from outside: `curl https://files.example.com/healthz` should answer `{"status":"ok",...}`.

## In P2P Share

Settings → Réseau → **Relais personnel**: enter `https://files.example.com` and the token, then *Appliquer et redémarrer*. The status line shows whether the app is connected to your relay.

Since P2P Share 3.4.5:

- **Your relay comes first.** It is the app's home relay whenever it answers, so friends who set the same relay exchange with you through it when no direct path works. That is usually faster than iroh's public relays, which everyone using iroh shares; set `RATE_LIMIT_KBPS` if you want to cap what your server carries.
- **Friends who do not use it are still reached** on their own relays: directly where the network allows, otherwise through the tunnel of your relay (P2P Share checks once per relay and network whether it answers directly). Your friends have nothing to set up.
- **While your relay does not answer**, the app falls back to the public relays, then checks `/ping` every minute and comes back to yours once it answers.
- **Your address** is published to your relay's directory and to iroh's public one.

On a network that blocks iroh's public relays (eduroam behind a FortiGate…), your app reaches them through your relay, and friends without it find you through your relay's directory, passed on to iroh's. They cannot call you first while your relay is your home relay (they lack the token), but your app calls them, and the connection then works both ways.

Before 3.4.5, the relay replaced the public relays entirely: the app had no fallback when it did not answer.

## Build

```bash
cargo test --release      # unit tests, two endpoints connecting through the relay, the tunnel
docker build -t p2p-sender-relay .
```

Pushing to `main` or a `v*` tag publishes the image to `ghcr.io/lamziiii/p2p-sender-relay` (see `.github/workflows/docker.yml`).

## License

MIT, see [LICENSE](LICENSE).
