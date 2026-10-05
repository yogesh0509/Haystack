# syntax=docker/dockerfile:1
# check=skip=FromPlatformFlagConstDisallowed
# (The fixed platform below is deliberate: electrs ships for x86-64 Linux only.)

# Haystack in one container, so the same Linux build runs on Linux, macOS and Windows.
#
#   docker build -t haystack .
#   docker run -it --rm -p 127.0.0.1:7878:7878 -v haystack-out:/haystack/out haystack
#   # then open http://127.0.0.1:7878
#
# The local test chain's electrs is published for x86-64 Linux only, so the image is x86-64 on
# every machine. Docker Desktop on Apple Silicon runs it under emulation, which is slower.

FROM --platform=linux/amd64 rust:1.97-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /haystack
# Only what the Rust build reads, so editing a document doesn't rebuild everything.
COPY Cargo.toml Cargo.lock ./
COPY capture capture
COPY demo demo
COPY haystack-electrum haystack-electrum
COPY regtest regtest
# The build downloads bitcoind and electrs, each checked against a pinned SHA-256 hash
# (regtest/README.md), and keeps them beside the Haystack binaries.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --locked -p haystack-demo -p haystack-capture -p haystack-regtest --bins \
 && mkdir -p /dist \
 && cp target/release/haystack-demo target/release/haystack-capture target/release/sessions /dist/ \
 && cp target/release/build/bitcoind-*/out/bitcoin/bitcoin-*/bin/bitcoind /dist/ \
 && cp target/release/build/electrsd-*/out/electrs/*/electrs /dist/

FROM --platform=linux/amd64 debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 libssl3 ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /dist/ /usr/local/bin/
# The test chain's programs, found through these instead of the build directory.
ENV BITCOIND_EXE=/usr/local/bin/bitcoind \
    ELECTRS_EXE=/usr/local/bin/electrs
RUN useradd --create-home haystack
WORKDIR /haystack
# The demo runs the attacker (python3 -m attack) from the repository root it was built in, so the
# sources sit at the same path. out/ holds wallets, session logs and the training set; mount a
# volume there to keep them between runs.
COPY --chown=haystack . .
RUN mkdir -p out && chown haystack out
USER haystack
EXPOSE 7878
# tini passes Ctrl-C and `docker stop` on to the demo, which then stops bitcoind and electrs.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["haystack-demo", "--regtest", "--mean-minutes", "2", "--host", "0.0.0.0"]
