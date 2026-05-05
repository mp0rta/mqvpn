#!/usr/bin/env bash
# Publish ci_bench_results/*.json to Cloudflare R2.
#
# Usage: publish_to_r2.sh <prefix> <run_type>
#   prefix:   "perf-data" (per-commit) or "perf-data/weekly"
#   run_type: "push" or "weekly"
#
# Required env:
#   R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET
#
# Reads from: ci_bench_results/*.json (in cwd)

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <prefix> <run_type>" >&2
  exit 2
fi

PREFIX="$1"
RUN_TYPE="$2"

: "${R2_ACCOUNT_ID:?R2_ACCOUNT_ID env required}"
: "${R2_ACCESS_KEY_ID:?R2_ACCESS_KEY_ID env required}"
: "${R2_SECRET_ACCESS_KEY:?R2_SECRET_ACCESS_KEY env required}"
: "${R2_BUCKET:?R2_BUCKET env required}"

COMMIT_SHORT=$(git rev-parse --short HEAD)
TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
ENDPOINT="https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION=auto

# 1. Upload new JSONs (immutable: filename has timestamp, long cache)
aws s3 cp ci_bench_results/ "s3://${R2_BUCKET}/${PREFIX}/" \
  --endpoint-url "$ENDPOINT" --recursive \
  --exclude '*' --include '*.json' \
  --cache-control "public, max-age=31536000, immutable"

# 2. Read current index.json. Distinguish 404 (initial state) from real errors:
#    silently treating auth/network failure as "empty" would wipe the entire index.
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

if aws s3api head-object \
     --bucket "$R2_BUCKET" \
     --key "${PREFIX}/index.json" \
     --endpoint-url "$ENDPOINT" >/dev/null 2>"$TMPDIR/head.err"; then
  aws s3 cp "s3://${R2_BUCKET}/${PREFIX}/index.json" "$TMPDIR/index.json" \
    --endpoint-url "$ENDPOINT"
else
  if grep -qE '404|Not Found' "$TMPDIR/head.err"; then
    echo "[]" > "$TMPDIR/index.json"
  else
    echo "::error::head-object failed (not a 404):"
    cat "$TMPDIR/head.err" >&2
    exit 1
  fi
fi

# 3. Update index + extract orphans
python3 "${SCRIPT_DIR}/update_perf_index.py" \
  --index "$TMPDIR/index.json" \
  --new-files-dir ci_bench_results \
  --commit "$COMMIT_SHORT" \
  --timestamp "$TIMESTAMP" \
  --type "$RUN_TYPE" \
  --output "$TMPDIR/index.new.json" \
  --orphans "$TMPDIR/orphans.txt"

# 4. Write updated index (short cache: 60 s for new-data visibility)
aws s3 cp "$TMPDIR/index.new.json" "s3://${R2_BUCKET}/${PREFIX}/index.json" \
  --endpoint-url "$ENDPOINT" \
  --content-type application/json \
  --cache-control "public, max-age=60"

# 5. Delete orphan JSONs that fell out of the top-100 window.
#    Failure here is non-fatal: lifecycle rule (365d) acts as a backstop.
while IFS= read -r f; do
  [ -z "$f" ] && continue
  aws s3 rm "s3://${R2_BUCKET}/${PREFIX}/${f}" --endpoint-url "$ENDPOINT" || \
    echo "::warning::failed to delete orphan ${f} (lifecycle will reap)"
done < "$TMPDIR/orphans.txt"

echo "Published ${RUN_TYPE} results to s3://${R2_BUCKET}/${PREFIX}/"
