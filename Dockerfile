# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin breadbug \
    && mkdir /data && chown breadbug /data
COPY --from=build /src/target/release/breadbug-server /usr/local/bin/breadbug-server
USER breadbug
ENV BREADBUG_DATA_DIR=/data \
    BREADBUG_PUBLIC_ADDR=0.0.0.0:8120 \
    BREADBUG_ADMIN_ADDR=0.0.0.0:8121 \
    BREADBUG_TRUST_PROXY=1
VOLUME /data
EXPOSE 8120 8121
ENTRYPOINT ["/usr/local/bin/breadbug-server"]
