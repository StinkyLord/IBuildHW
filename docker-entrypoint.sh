#!/usr/bin/env bash
# docker-entrypoint.sh
# Usage (inside the container — driven by docker run flags):
#
#   docker run --rm \
#     -v /my/project:/project:ro \
#     -v $(pwd):/output \
#     $(image) \
#     scan --dir /project --output /output/sbom.json \
#          [--cmake-configure] [--conan-graph] [--ldd]
#
# Environment variables (alternative to flags):
#   SBOM_CMAKE_CONFIGURE=1   — same as --cmake-configure
#   SBOM_CONAN_GRAPH=1       — same as --conan-graph
#   SBOM_LDD=1               — same as --ldd
#   SBOM_VERBOSE=1           — same as --verbose

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

log()  { echo "[entrypoint] $*" >&2; }
warn() { echo "[entrypoint] WARNING: $*" >&2; }

# ─────────────────────────────────────────────────────────────────────────────
# Parse flags from the command line
# We intercept our own flags and pass the rest through to cpp-sbom-builder.
# ─────────────────────────────────────────────────────────────────────────────

DO_CMAKE_CONFIGURE="${SBOM_CMAKE_CONFIGURE:-0}"
DO_CONAN_GRAPH="${SBOM_CONAN_GRAPH:-0}"
DO_LDD="${SBOM_LDD:-0}"
VERBOSE="${SBOM_VERBOSE:-0}"

PROJECT_DIR="/project"
OUTPUT_DIR="/output"
PASSTHROUGH_ARGS=()

# Walk through all arguments and extract our pre-scan flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cmake-configure)
            DO_CMAKE_CONFIGURE=1
            shift
            ;;
        --conan-graph)
            DO_CONAN_GRAPH=1
            # Also pass through to cpp-sbom-builder so it picks up graph.json
            PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
        --ldd)
            DO_LDD=1
            # Also pass through so the LddStrategy is activated
            PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
        --dir)
            PROJECT_DIR="$2"
            PASSTHROUGH_ARGS+=("$1" "$2")
            shift 2
            ;;
        --dir=*)
            PROJECT_DIR="${1#--dir=}"
            PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
        --output)
            OUTPUT_DIR="$(dirname "$2")"
            PASSTHROUGH_ARGS+=("$1" "$2")
            shift 2
            ;;
        --output=*)
            OUTPUT_DIR="$(dirname "${1#--output=}")"
            PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
        --verbose|-v)
            VERBOSE=1
            PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
        *)
            PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
    esac
done

BUILD_TMP="/tmp/sbom-build-$$"
mkdir -p "$BUILD_TMP"
mkdir -p "$OUTPUT_DIR"

vlog() { [[ "$VERBOSE" == "1" ]] && log "$*" || true; }

log "cpp-sbom-builder Docker entrypoint"
log "Project dir : $PROJECT_DIR"
log "Output dir  : $OUTPUT_DIR"
log "Build tmp   : $BUILD_TMP"


# ─────────────────────────────────────────────────────────────────────────────
# Run cpp-sbom-builder
#
# We pass the original args plus inject extra scan paths via env vars.
# The scanner reads SBOM_EXTRA_BUILD_DIR and SBOM_EXTRA_GRAPH_JSON to pick up
# files generated in the pre-scan steps.
# ─────────────────────────────────────────────────────────────────────────────

log "Running: cpp-sbom-builder ${PASSTHROUGH_ARGS[*]:-scan --dir /project --output /output/sbom.json}"
exec /usr/local/bin/cpp-sbom-builder "${PASSTHROUGH_ARGS[@]:-scan --dir /project --output /output/sbom.json}"
