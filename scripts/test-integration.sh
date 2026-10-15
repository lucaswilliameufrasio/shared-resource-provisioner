#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project_name="srp-integration-${UID}-$$"
compose=(docker compose --project-name "$project_name" --file "$repository_root/compose.integration.yaml")

cleanup() {
	"${compose[@]}" down --remove-orphans >/dev/null || true
}
trap cleanup EXIT

"${compose[@]}" up --detach --wait --wait-timeout 90

postgres_port="$("${compose[@]}" port postgres 5432 | awk -F: 'END { print $NF }')"
valkey_port="$("${compose[@]}" port valkey 6379 | awk -F: 'END { print $NF }')"
if [[ -z "$postgres_port" || -z "$valkey_port" ]]; then
	printf '%s\n' "Could not determine local integration service ports." >&2
	exit 1
fi

cd "$repository_root"
SRP_TEST_POSTGRES_DSN="postgres://postgres@127.0.0.1:${postgres_port}/postgres?sslmode=disable" \
SRP_TEST_VALKEY_URL="redis://@127.0.0.1:${valkey_port}/0" \
	go test -tags=integration -count=1 \
		./internal/drivers/postgresql \
		./internal/drivers/valkey \
		./internal/drivers/nats
