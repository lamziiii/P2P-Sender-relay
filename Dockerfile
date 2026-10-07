# Static binary on an empty image (about 3 MB).
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/p2p-relay /p2p-relay

FROM scratch
COPY --from=build /p2p-relay /p2p-relay
USER 65532:65532
ENV LISTEN_ADDR=0.0.0.0:3340
EXPOSE 3340
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["/p2p-relay", "healthcheck"]
ENTRYPOINT ["/p2p-relay"]
