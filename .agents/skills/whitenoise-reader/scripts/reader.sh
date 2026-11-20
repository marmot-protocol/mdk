#!/usr/bin/env bash
# Call the White Noise audit reader without exposing the bearer token.
#
#   reader.sh GET  /v1/contract
#   reader.sh POST /v1/investigations request.json
#   reader.sh POST /v1/records request.json
#
# The token comes from AUDIT_READER_TOKEN, the macOS Keychain or Linux Secret
# Service (service "whitenoise-data"), or
# ~/.config/whitenoise-data/reader.token. It is passed to curl on stdin, so it
# never appears in argv. The response body goes to stdout and "HTTP <status>"
# to stderr.
set -euo pipefail

usage() {
	echo "usage: reader.sh GET /v1/contract | reader.sh POST /v1/<endpoint> <body.json>" >&2
	exit 2
}

[ $# -ge 2 ] || usage
method=$1
path=$2
base=${AUDIT_READER_URL:-https://goggles.ipf.dev}
base=${base%/}

case $path in
/v1/*) ;;
*) usage ;;
esac
case $path in
*'?'*)
	echo "reader.sh: send parameters in the JSON body, not the URL" >&2
	exit 2
	;;
esac

load_token() {
	if [ -n "${AUDIT_READER_TOKEN:-}" ]; then
		printf '%s' "$AUDIT_READER_TOKEN"
		return
	fi
	if command -v security >/dev/null 2>&1 &&
		security find-generic-password -s whitenoise-data -w 2>/dev/null; then
		return
	fi
	if command -v secret-tool >/dev/null 2>&1 &&
		secret-tool lookup service whitenoise-data 2>/dev/null; then
		return
	fi
	local file=${XDG_CONFIG_HOME:-$HOME/.config}/whitenoise-data/reader.token
	if [ -r "$file" ]; then
		cat "$file"
	fi
}

token=$(load_token | tr -d '[:space:]')
if [ -z "$token" ]; then
	echo "reader.sh: no reader token found (checked AUDIT_READER_TOKEN, Keychain, Secret Service, ~/.config/whitenoise-data/reader.token)" >&2
	exit 3
fi
if ! [[ $token =~ ^wnar_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$ ]]; then
	echo "reader.sh: the stored reader token is malformed (expected wnar_...)" >&2
	exit 3
fi

args=(--silent --show-error --max-time 300 --config - -w '%{stderr}HTTP %{http_code}\n')
case $method in
GET)
	[ $# -eq 2 ] || usage
	;;
POST)
	[ $# -eq 3 ] || usage
	[ -r "$3" ] || {
		echo "reader.sh: cannot read request body file" >&2
		exit 2
	}
	args+=(-X POST -H 'Content-Type: application/json' --data-binary "@$3")
	;;
*) usage ;;
esac

printf 'header = "Authorization: Bearer %s"\n' "$token" |
	curl "${args[@]}" "$base$path"
