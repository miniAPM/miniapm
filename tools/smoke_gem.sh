#!/bin/sh
# Installs built gems with no Rust in reach and runs every binary through its gem executable.
set -eu
bindir="$(mktemp -d)"
for gem in "$@"; do
  gem install --local --no-document --bindir "$bindir" "$gem"
  for bin in miniapm miniapm-admin miniapm-cli; do
    "$bindir/$bin" --help >/dev/null
    echo "$(basename "$gem"): $bin runs"
  done
  gem uninstall --all --executables --bindir "$bindir" "$(basename "$gem" | sed -E 's/-[0-9].*//')"
done
