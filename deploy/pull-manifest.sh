#!/usr/bin/env bash
#
# Mirrors the update manifest from the newest GitHub release.
#
# Pull rather than push, deliberately. The origin has no public port, so a push
# from CI would have to jump through the Proxmox host — which means putting a
# key that opens beta into GitHub Actions secrets in order to publish a
# 300-byte JSON file. That is a large grant for a small errand, and it points
# the wrong way: a compromised workflow would reach the infrastructure instead
# of just the release.
#
# Nothing fetched here is trusted. A hostile manifest cannot produce a hostile
# update, because the installer it names still has to carry a signature the
# client accepts, and the signing key is not on GitHub's side of this either.
# The worst a bad manifest achieves is withholding an update or offering one
# that fails verification on the client.
set -euo pipefail

REPO="${YARA_REPO:-sf0rzin/yara}"
DEST="${YARA_MANIFEST:-/srv/yara/updates/latest.json}"

release="$(mktemp)"
manifest="$(mktemp)"
trap 'rm -f "$release" "$manifest" "${DEST}.new"' EXIT

# Distinguish the three outcomes rather than collapsing them: "no releases
# yet" is the normal state of a new deployment and should not read like a
# failure in the journal, and a rate limit should not read like an outage.
status="$(curl -sSL --max-time 20 -o "$release" -w '%{http_code}' \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${REPO}/releases/latest" || echo 000)"

case "$status" in
  200) ;;
  404)
    echo "${REPO} has no published releases yet"
    exit 0
    ;;
  403 | 429)
    echo "rate limited by the releases API; keeping the current manifest"
    exit 0
    ;;
  *)
    # A GitHub outage is not a reason to stop serving the manifest we already
    # have, so none of these are errors.
    echo "releases API returned ${status}; keeping the current manifest"
    exit 0
    ;;
esac

url="$(python3 - "$release" <<'PY'
import json, sys
release = json.load(open(sys.argv[1]))
asset = next((a for a in release.get("assets", []) if a["name"] == "latest.json"), None)
print(asset["browser_download_url"] if asset else "")
PY
)"

if [ -z "$url" ]; then
  echo "newest release has no latest.json asset; keeping the current manifest"
  exit 0
fi

curl -fsSL --max-time 30 -o "$manifest" "$url"

# Parse before publishing. Serving a truncated or non-JSON manifest turns every
# client's update check into an error, which is worse than serving nothing.
version="$(python3 - "$manifest" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
if not m.get("version") or not m.get("platforms"):
    raise SystemExit("manifest is missing version or platforms")
print(m["version"])
PY
)"

if [ -f "$DEST" ] && cmp -s "$manifest" "$DEST"; then
  exit 0
fi

# Same filesystem, so the rename is atomic: a client polling mid-write reads
# either the old manifest or the new one, never half of either.
install -m 0644 "$manifest" "${DEST}.new"
mv -f "${DEST}.new" "$DEST"
echo "manifest now advertises ${version}"
