#!/bin/bash
# Build dwarf2json from a PINNED source commit with a VERIFIED Go toolchain, as the unprivileged user `nobody`.
#
#   sudo bash scripts/m3_build_dwarf2json.sh          -> .local/m3/build/dwarf2json + dwarf2json.provenance.txt
#
# Trust chain (nothing unverified runs as root; no system package is installed):
#   Go       go${GO_VERSION}.linux-amd64.tar.gz from go.dev; its sha256 must equal BOTH the pinned GO_SHA256 below and
#            the value go.dev publishes (https://go.dev/dl/?mode=json&include=all).
#   source   github.com/volatilityfoundation/dwarf2json, tag v0.9.0, which must resolve to commit D2J_COMMIT.
#   deps     verified by Go's checksum database (go.sum + sum.golang.org, GOFLAGS=-mod=readonly, GOTOOLCHAIN=local).
#   build    runs as `nobody` in a private 0700 directory under /var/tmp; the result is copied back by root.
set -euo pipefail
GO_VERSION=1.26.11
GO_SHA256=9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec
D2J_REPO=https://github.com/volatilityfoundation/dwarf2json.git
D2J_TAG=v0.9.0
D2J_COMMIT=9f14607e0d339d463ea725fbd5c08aa7b7d40f75
cd "$(dirname "$0")/.."
OUT=.local/m3/build; mkdir -p "$OUT"; umask 077
TAR=go${GO_VERSION}.linux-amd64.tar.gz

echo "[1/4] Go $GO_VERSION"
PUBLISHED=$(curl -fsS "https://go.dev/dl/?mode=json&include=all" | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    for f in r['files']:
        if f['filename']=='$TAR': print(f['sha256'])")
[ "$PUBLISHED" = "$GO_SHA256" ] || { echo "go.dev publishes $PUBLISHED for $TAR, pinned $GO_SHA256" >&2; exit 1; }
[ -f "$OUT/$TAR" ] || curl -fL -o "$OUT/$TAR" "https://go.dev/dl/$TAR"
[ "$(sha256sum "$OUT/$TAR" | cut -d' ' -f1)" = "$GO_SHA256" ] || { echo "Go tarball sha256 mismatch" >&2; exit 1; }

echo "[2/4] private build dir for nobody"
B=$(mktemp -d /var/tmp/vsec-d2j.XXXXXX)
trap 'rm -rf "$B"' EXIT
tar -C "$B" -xzf "$OUT/$TAR"
chown -R nobody:nogroup "$B"; chmod 700 "$B"
asnobody() { runuser -u nobody -- env -i PATH="$B/go/bin:/usr/bin:/bin" HOME="$B" GOPATH="$B/gopath" \
             GOCACHE="$B/cache" GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOSUMDB=sum.golang.org \
             GOPROXY=https://proxy.golang.org,direct "$@"; }

echo "[3/4] source $D2J_TAG"
asnobody git clone -q --depth 1 --branch "$D2J_TAG" "$D2J_REPO" "$B/src"
HEAD=$(asnobody git -C "$B/src" rev-parse HEAD)
[ "$HEAD" = "$D2J_COMMIT" ] || { echo "tag $D2J_TAG is $HEAD, pinned $D2J_COMMIT" >&2; exit 1; }

echo "[4/4] build (as nobody)"
asnobody sh -c "cd '$B/src' && go mod verify && go build -trimpath -o '$B/dwarf2json' ."
install -m 700 "$B/dwarf2json" "$OUT/dwarf2json"
SHA=$(sha256sum "$OUT/dwarf2json" | cut -d' ' -f1)
{
  echo "dwarf2json source: $D2J_REPO tag $D2J_TAG commit $HEAD (pinned)"
  echo "go: $TAR sha256 $GO_SHA256 (pinned, equals go.dev published)"
  echo "go mod verify: ok (deps checked against go.sum / sum.golang.org)"
  echo "built as: nobody, flags -trimpath"
  echo "dwarf2json_sha256: $SHA"
} | tee "$OUT/dwarf2json.provenance.txt"
