#!/usr/bin/env bash
# Installed by the deployment operator in an immutable, reviewed AUTH toolkit.
set -euo pipefail
[[ $# == 2 && "$1" =~ ^(candidate|serving)$ && "$2" =~ ^[a-f0-9]{40}$ ]] || exit 64
: "${AUTH_RELIABILITY_TOOLKIT:?reviewed toolkit required}"
: "${AUTH_RELIABILITY_HOST_CONFIG:?protected configuration required}"
: "${AUTH_RELIABILITY_HOST_CONFIG_SHA256:?reviewed configuration digest required}"
: "${AUTH_RELIABILITY_MANIFEST:?reviewed manifest required}"
exec /usr/bin/node "$AUTH_RELIABILITY_TOOLKIT/scripts/auth-production-gate.mjs" "$1" \
 "$AUTH_RELIABILITY_HOST_CONFIG" "$AUTH_RELIABILITY_HOST_CONFIG_SHA256" "$2" "$AUTH_RELIABILITY_MANIFEST"
