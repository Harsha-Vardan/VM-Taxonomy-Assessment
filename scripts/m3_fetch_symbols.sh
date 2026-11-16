#!/bin/bash
# HOST-side: fetch and verify the debug kernel of the M3 guest, then build its Volatility 3 ISF with build_symbols.sh.
#
#   sudo bash scripts/m3_fetch_symbols.sh [kernel-version] [package-version] [out-dir]
#   defaults: 5.15.0-71-generic  5.15.0-71.78  .local/m3/symbols      (CirrOS 0.6.2 x86_64 runs 5.15.0-71-generic)
#
# Provenance chain:
#   1. linux-image-unsigned-<kver>-dbgsym_<pkgver>_amd64.ddeb from the Launchpad librarian (ddebs.ubuntu.com no longer
#      carries this superseded version). Its SHA-256 is taken from the Launchpad API (binaryFileUrls include_meta)
#      for the jammy/amd64 publication and checked before use.
#   2. vmlinux-<kver> is extracted from that verified package (sha256 recorded).
#   3. dwarf2json built from pinned source by scripts/m3_build_dwarf2json.sh (run it first); its sha256 is taken
#      from .local/m3/build/dwarf2json.provenance.txt and re-checked. dwarf2json runs as `nobody`, never as root.
# Writes <out-dir>/provenance.txt with every URL and hash. Large files stay under .local/ (gitignored).
set -euo pipefail
KVER=${1:-5.15.0-71-generic}
PKGVER=${2:-5.15.0-71.78}
OUT=${3:-.local/m3/symbols}
cd "$(dirname "$0")/.."
WORK=.local/m3/build; mkdir -p "$WORK" "$OUT"; umask 077
PKG=linux-image-unsigned-${KVER}-dbgsym
DEB=${PKG}_${PKGVER}_amd64.ddeb
API="https://api.launchpad.net/1.0/ubuntu/+archive/primary?ws.op=getPublishedBinaries&binary_name=${PKG}&exact_match=true&version=${PKGVER}"

echo "[1/4] expected sha256 of $DEB from the Launchpad API"
# binaryFileUrls exists only in the devel API: the publication link is rewritten from /1.0/ to /devel/
PUB=$(curl -fsS "$API" | python3 -c "import json,sys; e=[x for x in json.load(sys.stdin)['entries'] if x['distro_arch_series_link'].endswith('/jammy/amd64')]; print(e[0]['self_link'])")
EXPECT=$(curl -fsS "${PUB/\/1.0\//\/devel\/}?ws.op=binaryFileUrls&include_meta=true" | python3 -c "
import json,sys
for f in json.load(sys.stdin):
    if f['url'].endswith('/$DEB'): print(f['sha256'] if 'sha256' in f else ''); break")
[ "${#EXPECT}" -eq 64 ] || { echo "no sha256 from the Launchpad API for $DEB" >&2; exit 1; }

echo "[2/4] download (about 1 GB) and verify"
[ -f "$WORK/$DEB" ] || curl -fsSL --retry 3 -o "$WORK/$DEB" "https://launchpad.net/ubuntu/+archive/primary/+files/$DEB"
GOT=$(sha256sum "$WORK/$DEB" | cut -d' ' -f1)
[ "$GOT" = "$EXPECT" ] || { echo "sha256 mismatch for $DEB: got $GOT expected $EXPECT" >&2; exit 1; }

echo "[3/4] extract vmlinux-$KVER"
rm -rf "$WORK/x"; mkdir -p "$WORK/x"; dpkg-deb -x "$WORK/$DEB" "$WORK/x"
VMLINUX=$(find "$WORK/x" -name "vmlinux-$KVER" -type f | head -1)
[ -n "$VMLINUX" ] || { echo "vmlinux-$KVER not in the package" >&2; exit 1; }
cp "$VMLINUX" "$WORK/vmlinux-$KVER"; rm -rf "$WORK/x"
VM_SHA=$(sha256sum "$WORK/vmlinux-$KVER" | cut -d' ' -f1)

echo "[4/4] ISF with the source-built dwarf2json, as nobody"
D2J_SHA=$(sed -n 's/^dwarf2json_sha256: //p' "$WORK/dwarf2json.provenance.txt" 2>/dev/null || true)
[ "${#D2J_SHA}" -eq 64 ] || { echo "run scripts/m3_build_dwarf2json.sh first" >&2; exit 1; }
[ "$(sha256sum "$WORK/dwarf2json" | cut -d' ' -f1)" = "$D2J_SHA" ] || { echo "dwarf2json changed since it was built" >&2; exit 1; }
B=$(mktemp -d /var/tmp/vsec-isf.XXXXXX)
trap 'rm -rf "$B"' EXIT
cp "$WORK/vmlinux-$KVER" "$WORK/dwarf2json" scripts/build_symbols.sh "$B/"; mkdir "$B/out"
chown -R nobody:nogroup "$B"; chmod 700 "$B"
runuser -u nobody -- env -i PATH=/usr/bin:/bin sh -c "cd '$B' && sh ./build_symbols.sh ./vmlinux-$KVER $VM_SHA ./dwarf2json $D2J_SHA ./out"
install -m 600 "$B"/out/* "$OUT/"
ISF=$(ls "$OUT"/*.json | head -1)
{
  echo "kernel: $KVER"; echo "package: $DEB ($PKGVER)"; echo "package_url: https://launchpad.net/ubuntu/+archive/primary/+files/$DEB"
  echo "package_sha256 (Launchpad API, verified): $EXPECT"; echo "vmlinux_sha256: $VM_SHA"
  cat "$WORK/dwarf2json.provenance.txt"
  echo "isf: $(basename "$ISF")"; echo "isf_sha256: $(sha256sum "$ISF" | cut -d' ' -f1)"
} | tee "$OUT/provenance.txt"
rm -f "$WORK/vmlinux-$KVER"   # 400+ MB; the verified .ddeb stays in .local/m3/build for a rebuild
