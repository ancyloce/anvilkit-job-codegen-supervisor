#!/bin/sh
# Copies (default) or verifies (--check) this repository's copy of the codegen
# process protocol against its single source, a checkout of
# anvilkit-agent-contracts: jobs/codegen/{protocol.schema.json,fixtures.json}
# into internal/protocol/contract/, with their digests in SOURCE. --check
# changes nothing and fails on any difference.
#
#   sh tools/sync-protocol.sh [--check] <contracts-checkout>
set -eu
check=0
if [ "${1:-}" = "--check" ]; then check=1; shift; fi
src=${1:?usage: sync-protocol.sh [--check] <contracts-checkout>}
here=$(cd "$(dirname "$0")/.." && pwd)
dest="$here/internal/protocol/contract"
files="protocol.schema.json fixtures.json"
status=0
for f in $files; do
  if [ ! -f "$src/jobs/codegen/$f" ]; then
    echo "FAIL: $src/jobs/codegen/$f does not exist (a contracts checkout with the codegen protocol is required)" >&2
    exit 1
  fi
done
source_text() {
  echo "# Verbatim copies of anvilkit-agent-contracts jobs/codegen/ (the single source of the"
  echo "# codegen process protocol). Refresh and verify with tools/sync-protocol.sh; never edit here."
  for f in $files; do
    echo "jobs/codegen/$f sha256:$(sha256sum "$src/jobs/codegen/$f" | cut -d' ' -f1)"
  done
}
if [ "$check" -eq 1 ]; then
  for f in $files; do
    if ! cmp -s "$src/jobs/codegen/$f" "$dest/$f"; then
      echo "FAIL: internal/protocol/contract/$f differs from $src/jobs/codegen/$f" >&2
      status=1
    fi
  done
  if ! source_text | cmp -s - "$dest/SOURCE"; then
    echo "FAIL: internal/protocol/contract/SOURCE does not record the source digests" >&2
    status=1
  fi
  [ "$status" -eq 0 ] && echo "protocol copy matches $src/jobs/codegen"
  exit "$status"
fi
mkdir -p "$dest"
for f in $files; do cp "$src/jobs/codegen/$f" "$dest/$f"; done
source_text > "$dest/SOURCE"
echo "copied the codegen protocol from $src/jobs/codegen"
