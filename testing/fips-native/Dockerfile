FROM rust:1.97.1-slim-trixie AS builder

ARG FIPS_GIT_REV=1ec62e51192a3ed49792e177c8c88d8176647133
ARG WOK_GIT_REV=957d22c296e8053c7d01c80f15a3ae9b2b5f2fca
ENV RUSTUP_TOOLCHAIN=1.97.1
ENV CARGO_TARGET_DIR=/build/target

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        git \
        libclang-dev \
        libdbus-1-dev \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src/mdk
COPY . .
RUN grep -Fq "${FIPS_GIT_REV}" Cargo.lock && \
    grep -Fq "${WOK_GIT_REV}" Cargo.lock && \
    cargo build --release --locked \
        -p transport-fips-native --example relay-smoke \
        -p wn-cli --bins

RUN git init /src/wok && \
    git -C /src/wok remote add origin https://github.com/erskingardner/wok.git && \
    git -C /src/wok fetch --depth 1 origin "${WOK_GIT_REV}" && \
    git -C /src/wok checkout --detach FETCH_HEAD && \
    test "$(git -C /src/wok rev-parse HEAD)" = "${WOK_GIT_REV}"

WORKDIR /src/wok
RUN cargo build --release --locked -p wok-cli --bin wok

RUN git init /src/fips && \
    git -C /src/fips remote add origin https://github.com/jmcorgan/fips.git && \
    git -C /src/fips fetch --depth 1 origin "${FIPS_GIT_REV}" && \
    git -C /src/fips checkout --detach FETCH_HEAD && \
    test "$(git -C /src/fips rev-parse HEAD)" = "${FIPS_GIT_REV}"

WORKDIR /src/fips
RUN cargo build --release --locked --bin fips --bin fipsctl

FROM debian:trixie-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl jq libdbus-1-3 python3 tini && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system fips && \
    install -d -o root -g fips -m 0750 /run/fips /etc/fips /etc/wok /var/lib/wok

COPY --from=builder /build/target/release/examples/relay-smoke /usr/local/bin/mdk-fips-relay-smoke
COPY --from=builder /build/target/release/wn /usr/local/bin/wn
COPY --from=builder /build/target/release/wnd /usr/local/bin/wnd
COPY --from=builder /build/target/release/wok /usr/local/bin/wok
COPY --from=builder /build/target/release/fips /usr/local/bin/fips
COPY --from=builder /build/target/release/fipsctl /usr/local/bin/fipsctl
COPY testing/fips-native/relay-fips.yaml /etc/fips/relay-fips.yaml
COPY testing/fips-native/client-fips.yaml /etc/fips/client-fips.yaml
COPY testing/fips-native/remote-client-fips.yaml /etc/fips/remote-client-fips.yaml
COPY testing/fips-native/wok.toml /etc/wok/wok.toml
COPY testing/fips-native/discovery-wok.toml /etc/wok/discovery-wok.toml
COPY testing/fips-native/benchmark.py /usr/local/bin/mdk-relay-benchmark

ENTRYPOINT []
