#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: package-agent.sh BINARY OUTPUT_DIR ARCH" >&2
  exit 2
fi
binary="$(realpath "$1")"
out="$2"
arch="$3"
version="$("$binary" --version)"
version="${version#rooster }"
case "$version" in ''|*[!A-Za-z0-9._-]*) echo "invalid binary version: $version" >&2; exit 1;; esac
case "$arch" in x86_64|aarch64) ;; *) echo "unsupported architecture: $arch" >&2; exit 1;; esac
"$binary" agent upgrade-guard --help >/dev/null
mkdir -p "$out"
name="rooster-$version-$arch"
cp "$binary" "$out/$name"
chmod 0755 "$out/$name"
gzip -9 -c "$out/$name" > "$out/$name.gz"
# Single-thread level 6 avoids the large dictionary allocation of xz -9.
xz -6 -T1 -c "$out/$name" > "$out/$name.xz"
(cd "$out" && sha256sum "$name" "$name.gz" "$name.xz" > "SHA256SUMS-$arch")
cp "$out/SHA256SUMS-$arch" "$out/SHA256SUMS"
printf '{"version":"%s","arch":"%s","binary":"%s"}\n' "$version" "$arch" "$name" > "$out/manifest.json"
