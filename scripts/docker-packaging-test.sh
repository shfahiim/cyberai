#!/usr/bin/env bash
# Run the isolated packaging smoke test inside Docker.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${CYBERAI_PACKAGING_IMAGE:-cyberai-packaging-test:local}"

echo "==> building image: $image"
docker build \
  -f "$repo_root/scripts/Dockerfile.packaging-test" \
  -t "$image" \
  "$repo_root"

echo
echo "==> running isolated packaging test in container"
docker run --rm \
  --network host \
  "$image"
