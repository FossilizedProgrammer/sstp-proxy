#!/bin/sh
# Build fully static, dependency-free sstp-proxy binaries for all targets.
# POSIX sh compatible (works with sh, dash, bash, etc.).
set -eu

cd "$(dirname "$0")"
mkdir -p dist

VERSION="$(grep -m1 'version =' main.go | sed 's/.*"\(.*\)".*/\1/' || echo dev)"
LDFLAGS="-s -w -X main.version=${VERSION}"

# Space-separated "OS/ARCH" targets; iterate without bash arrays.
TARGETS="linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64"

for t in $TARGETS; do
  os="${t%/*}"
  arch="${t#*/}"
  out="dist/sstp-proxy-${os}-${arch}"
  [ "$os" = "windows" ] && out="${out}.exe"
  echo "building ${out}"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$out" .
done

echo "done -> dist/"
ls -la dist/
