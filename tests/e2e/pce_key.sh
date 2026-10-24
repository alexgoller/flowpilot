#!/bin/sh
# Usage: pce_key.sh ENV_FILE
# Prints "$API_KEY $API_SECRET" from an env file (sourced in a subshell).
# Intended for a config value like: api_key: $tests/e2e/pce_key.sh <envfile>
[ -n "$1" ] || { echo "usage: $0 ENV_FILE" >&2; exit 2; }
( set -a; . "$1"; set +a; printf '%s %s\n' "$API_KEY" "$API_SECRET" )
