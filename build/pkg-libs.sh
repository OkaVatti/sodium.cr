#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Shard directory passed as first argument when called from lib_sodium.cr
if [ "${1:-}" != "" ]; then
  cd "$1"
fi

# shellcheck source=build/env.sh
. "$script_dir/env.sh"

if [ "${LIBSODIUM_INSTALL:-0}" = "1" ]; then
  if [ -f "$LIBSODIUM_INSTALL_PATH/lib/libsodium.a" ]; then
    printf '%s\n' "-L$LIBSODIUM_INSTALL_PATH/lib -lsodium"
  else
    echo "Error: Custom libsodium not found at $LIBSODIUM_INSTALL_PATH/lib/libsodium.a" >&2
    echo "Run 'export LIBSODIUM_INSTALL=1 && ./build/libsodium_install.sh' first." >&2
    exit 1
  fi
else
  pkg-config --libs libsodium
fi
