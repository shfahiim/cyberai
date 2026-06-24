#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
CyberAI setup

Usage:
  ./setup.sh [flags]

Flags:
  --system              Install to /usr/local/bin/cyberai
  --prefix DIR          Install to DIR/cyberai
  --skip-tests          Skip go test ./...
  --install-tools       Run cyberai tools install after installing the binary
  --keep-build          Keep the temporary built binary
  -h, --help            Show this help

Default install path:
  $GOBIN/cyberai, or $GOPATH/bin/cyberai when GOBIN is empty.
EOF
}

log() {
  printf '==> %s\n' "$*"
}

fail() {
  printf 'setup: %s\n' "$*" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install_prefix=""
system_install=false
skip_tests=false
install_tools=false
keep_build=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --system)
      system_install=true
      shift
      ;;
    --prefix)
      [[ $# -ge 2 ]] || fail "--prefix requires a directory"
      install_prefix="$2"
      shift 2
      ;;
    --skip-tests)
      skip_tests=true
      shift
      ;;
    --install-tools)
      install_tools=true
      shift
      ;;
    --keep-build)
      keep_build=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown flag: $1"
      ;;
  esac
done

command -v go >/dev/null 2>&1 || fail "Go is required but was not found on PATH"

cd "$repo_root"

if [[ "$skip_tests" == false ]]; then
  log "running tests"
  go test ./...
fi

tmpdir="$(mktemp -d)"
if [[ "$keep_build" == false ]]; then
  trap 'rm -rf "$tmpdir"' EXIT
fi

build_bin="$tmpdir/cyberai"
log "building $build_bin"
go build -o "$build_bin" ./cmd/cyberai

if [[ -n "$install_prefix" && "$system_install" == true ]]; then
  fail "use either --prefix or --system, not both"
fi

if [[ -n "$install_prefix" ]]; then
  dest_dir="$install_prefix"
elif [[ "$system_install" == true ]]; then
  dest_dir="/usr/local/bin"
else
  gobin="$(go env GOBIN)"
  if [[ -n "$gobin" ]]; then
    dest_dir="$gobin"
  else
    gopath="$(go env GOPATH)"
    [[ -n "$gopath" ]] || fail "could not resolve GOPATH"
    dest_dir="$gopath/bin"
  fi
fi

dest="$dest_dir/cyberai"
log "installing to $dest"

if [[ ! -d "$dest_dir" ]]; then
  mkdir -p "$dest_dir" 2>/dev/null || sudo mkdir -p "$dest_dir"
fi

if [[ -w "$dest_dir" ]]; then
  install -m 0755 "$build_bin" "$dest"
else
  command -v sudo >/dev/null 2>&1 || fail "$dest_dir is not writable and sudo is unavailable"
  sudo install -m 0755 "$build_bin" "$dest"
fi

log "installed binary"
"$dest" --version

if [[ "$install_tools" == true ]]; then
  log "installing scanner tools"
  "$dest" tools install
fi

if command -v cyberai >/dev/null 2>&1; then
  resolved="$(command -v cyberai)"
  log "current shell resolves cyberai to $resolved"
  if [[ "$resolved" != "$dest" ]]; then
    printf 'note: installed %s, but PATH currently resolves cyberai to %s\n' "$dest" "$resolved"
  fi
else
  printf 'note: cyberai is installed at %s, but that directory is not on PATH\n' "$dest"
fi

log "done"
