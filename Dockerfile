# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Build the cpp-sbom-builder binary (statically linked, no CGO)
# ─────────────────────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Copy dependency manifests first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build a fully static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /cpp-sbom-builder .

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Runtime image
# All analysis tools are pre-installed so the customer needs nothing on their
# machine except Docker.
# ─────────────────────────────────────────────────────────────────────────────
FROM ubuntu:22.04

LABEL org.opencontainers.image.title="cpp-sbom-builder" \
      org.opencontainers.image.description="C++ SBOM Generation Engine — scans a C++ project and produces a CycloneDX 1.4 JSON SBOM" \
      org.opencontainers.image.source="https://github.com/StinkyLord/IBuildHW" \
      org.opencontainers.image.vendor="Philip Abed"

# Prevent interactive prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive

# ── System packages ──────────────────────────────────────────────────────────
# cmake / ninja      — configure-only step (generates compile_commands.json)
# gcc / g++ / clang  — needed by cmake configure to detect compiler
# binutils           — nm, objdump, readelf, ld (binary analysis)
# file               — MIME type detection for binary files
# python3 / pip      — required by Conan
# git                — some cmake FetchContent / conan recipes need it
# ca-certificates    — HTTPS for conan center downloads
# pkg-config         — library metadata queries
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        ninja-build \
        gcc \
        g++ \
        clang \
        binutils \
        file \
        python3 \
        python3-pip \
        git \
        ca-certificates \
        pkg-config \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ── Conan (C++ package manager) ───────────────────────────────────────────────
# Installed at image build time — nothing is installed on the customer's machine.
RUN pip3 install --no-cache-dir "conan>=2.0"

# Initialise a default Conan profile so `conan graph info` works out of the box
RUN conan profile detect --force

# ── cpp-sbom-builder binary ───────────────────────────────────────────────────
COPY --from=builder /cpp-sbom-builder /usr/local/bin/cpp-sbom-builder

# ── Entrypoint script ─────────────────────────────────────────────────────────
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# ── Conventions ───────────────────────────────────────────────────────────────
# /project  — customer mounts their C++ project here (read-only recommended)
# /output   — SBOM JSON is written here
VOLUME ["/project", "/output"]
WORKDIR /project

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default: scan /project, write to /output/sbom.json
CMD ["scan", "--dir", "/project", "--output", "/output/sbom.json"]
