#!/usr/bin/env bash
set -euo pipefail

scenario="${!#}"
case "$scenario" in
    stream-text)
        printf '%s\n' '{"type":"step_start","sessionID":"ses_mock"}'
        printf '%s\n' '{"type":"text","part":{"text":"hello"}}'
        ;;
    idle)
        printf '%s\n' '{"type":"step_start","sessionID":"ses_idle"}'
        exec sleep 2
        ;;
    streaming)
        for i in 1 2 3 4 5; do
            printf '%s\n' "{\"type\":\"text\",\"part\":{\"text\":\"chunk$i\"}}"
            sleep 0.15
        done
        ;;
    total-cap)
        printf '%s\n' '{"type":"step_start","sessionID":"ses_total"}'
        for _ in $(seq 1 60); do
            printf '%s\n' '{"type":"step_finish"}'
            sleep 0.05
        done
        ;;
    stdout-close-live)
        exec 1>&-
        exec sleep 2
        ;;
    session-backpressure)
        printf '%s\n' '{"type":"step_start","sessionID":"ses_backpressure"}'
        printf '%s\n' '{"type":"text","part":{"text":"first"}}'
        printf '%s\n' '{"type":"text","part":{"text":"second"}}'
        exec sleep 2
        ;;
    *)
        printf 'unknown mock scenario: %s\n' "$scenario" >&2
        exit 2
        ;;
esac
