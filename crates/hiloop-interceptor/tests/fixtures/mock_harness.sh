#!/bin/sh
set -eu

mode="${1:-}"
if [ "$#" -gt 0 ]; then
    shift
fi

case "$mode" in
    context)
        exit_code="${1:-0}"
        printf 'HILOOP_RUN_ID=%s\n' "${HILOOP_RUN_ID:-}"
        printf 'HILOOP_FORK_NODE_ID=%s\n' "${HILOOP_FORK_NODE_ID:-}"
        printf 'HILOOP_FORK_PATH=%s\n' "${HILOOP_FORK_PATH:-}"
        printf 'OTEL_RESOURCE_ATTRIBUTES=%s\n' "${OTEL_RESOURCE_ATTRIBUTES:-}"
        printf 'context-stderr\n' >&2
        exit "$exit_code"
        ;;
    mixed)
        printf 'out1\npartial'
        printf 'err1\nerr-partial' >&2
        ;;
    binary)
        printf '\377\000A\n\n'
        ;;
    line-boundaries)
        printf 'lf\ncrlf\r\n\npartial'
        ;;
    lines)
        count="${1:?lines requires a count}"
        index=0
        while [ "$index" -lt "$count" ]; do
            printf 'stdout-%04d\n' "$index"
            printf 'stderr-%04d\n' "$index" >&2
            index=$((index + 1))
        done
        ;;
    exit)
        exit_code="${1:?exit requires an exit code}"
        printf 'stdout-before-exit\n'
        printf 'stderr-before-exit\n' >&2
        exit "$exit_code"
        ;;
    marker)
        marker="${1:?marker requires a path}"
        : > "$marker"
        ;;
    trap)
        started="${1:?trap requires a started-marker path}"
        terminated="${2:?trap requires a terminated-marker path}"
        # Record that the trap is installed, then block until SIGTERM arrives.
        trap ': > "$terminated"; exit 143' TERM
        : > "$started"
        while true; do
            sleep 0.05
        done
        ;;
    otlp)
        fixture="${1:?otlp requires a fixture path}"
        : "${OTEL_EXPORTER_OTLP_ENDPOINT:?otlp mode needs OTEL_EXPORTER_OTLP_ENDPOINT}"
        command -v curl >/dev/null 2>&1 || { printf 'curl not found\n' >&2; exit 69; }
        curl -s -X POST -H 'Content-Type: application/x-protobuf' \
            --data-binary @"$fixture" \
            "$OTEL_EXPORTER_OTLP_ENDPOINT/v1/traces" >/dev/null
        ;;
    *)
        printf 'unknown mock harness mode: %s\n' "$mode" >&2
        exit 64
        ;;
esac
