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
        printf 'HILOOP_LINEAGE_PATH=%s\n' "${HILOOP_LINEAGE_PATH:-}"
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
    proxy)
        url="${1:?proxy requires a url}"
        : "${HTTPS_PROXY:?proxy mode needs HTTPS_PROXY}"
        command -v curl >/dev/null 2>&1 || { printf 'curl not found\n' >&2; exit 69; }
        # curl picks up HTTPS_PROXY and the injected CURL_CA_BUNDLE from the env.
        # Upstream is expected to fail; the decrypted request is what we capture.
        curl -s -o /dev/null --max-time 5 "$url" || true
        ;;
    proxy-http)
        # Like `proxy`, but targets a plain-HTTP upstream that returns a real
        # (chunked) response, so both the request and its response are captured
        # and can be checked for a shared exchange id. The hop is not TLS-
        # intercepted, so no CA is involved.
        url="${1:?proxy-http requires a url}"
        : "${HTTP_PROXY:?proxy-http mode needs HTTP_PROXY}"
        command -v curl >/dev/null 2>&1 || { printf 'curl not found\n' >&2; exit 69; }
        curl -s -o /dev/null --max-time 5 "$url" || true
        ;;
    proxy-http-hang)
        # Like `proxy-http`, then linger: fetch the URL, mark completion, and stay
        # alive (bounded, so a hard-killed wrapper cannot leak it forever) while a
        # test kills the wrapper mid-run.
        url="${1:?proxy-http-hang requires a url}"
        marker="${2:?proxy-http-hang requires a marker path}"
        : "${HTTP_PROXY:?proxy-http-hang mode needs HTTP_PROXY}"
        command -v curl >/dev/null 2>&1 || { printf 'curl not found\n' >&2; exit 69; }
        curl -s -o /dev/null --max-time 5 "$url" || true
        : > "$marker"
        index=0
        while [ "$index" -lt 300 ]; do
            sleep 0.1
            index=$((index + 1))
        done
        ;;
    *)
        printf 'unknown mock harness mode: %s\n' "$mode" >&2
        exit 64
        ;;
esac
