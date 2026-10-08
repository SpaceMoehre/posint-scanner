#!/usr/bin/env bash
# Convenience launcher for posint-scanner.
#
# With arguments: forwards them straight to the CLI, e.g.
#   ./launch.sh scan example.com
#   ./launch.sh export --format json --output results.json
#
# With no arguments: interactive mode - prompts for a domain (or a
# domains file). `scan` already auto-exports an Obsidian markdown report,
# so this just offers an additional json/csv export on top of that.
#
# Either way it handles first-run setup: installs dependencies, creates
# config.yaml from the example if missing, and initializes the database.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v uv >/dev/null 2>&1; then
    echo "error: uv is not installed - see https://docs.astral.sh/uv/" >&2
    exit 1
fi

uv sync --quiet

if [ ! -f config.yaml ]; then
    cp config.example.yaml config.yaml
    echo "created config.yaml from the example - edit it to add Shodan/Qualys credentials if you have them, then re-run"
fi

if ! command -v subfinder >/dev/null 2>&1; then
    echo "note: subfinder is not on PATH - that source will be skipped (https://github.com/projectdiscovery/subfinder)"
fi

DB_PATH="${POSINT_DB:-posint.db}"
VAULT_PATH="${POSINT_VAULT:-./vault}"

if [ ! -f "$DB_PATH" ] && [ "${1:-}" != "db" ]; then
    uv run posint-scanner db init --db "$DB_PATH"
fi

if [ "$#" -gt 0 ]; then
    exec uv run posint-scanner "$@"
fi

echo "posint-scanner - interactive mode"
echo "(pass arguments directly to skip this, e.g. ./launch.sh scan example.com)"
echo

read -rp "Domain to scan, or path to a file with one domain per line: " target
if [ -z "$target" ]; then
    echo "no domain given, exiting"
    exit 1
fi

if [ -f "$target" ]; then
    uv run posint-scanner scan --domains-file "$target" --db "$DB_PATH" --report-output "$VAULT_PATH"
else
    uv run posint-scanner scan "$target" --db "$DB_PATH" --report-output "$VAULT_PATH"
fi

echo
read -rp "Also export as json/csv? [json/csv/skip] (default: skip): " fmt
fmt="${fmt:-skip}"

case "$fmt" in
    json)
        uv run posint-scanner export --format json --output results.json --db "$DB_PATH"
        echo "exported to results.json"
        ;;
    csv)
        uv run posint-scanner export --format csv --output results.csv --db "$DB_PATH"
        echo "exported to results.csv"
        ;;
    skip) ;;
    *)
        echo "unrecognized format '$fmt', skipping"
        ;;
esac
