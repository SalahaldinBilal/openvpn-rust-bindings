# Builds and tests the crate on Linux. The source is mounted at /src, the build goes to /target in the container.
FROM debian:trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential perl curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH=/root/.cargo/bin:$PATH \
    CARGO_TARGET_DIR=/target

WORKDIR /src
CMD ["cargo", "test"]
