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
  ensure_explicit_bzero_shim

  if [ -f "$LIBSODIUM_INSTALL_PATH/lib/libsodium.a" ]; then
    if is_macos; then
      printf '%s
' "-L$LIBSODIUM_BUILD_DIR -lexplicit_bzero_shim -L$LIBSODIUM_INSTALL_PATH/lib -lsodium"
    else
      printf '%s
' "-L$LIBSODIUM_INSTALL_PATH/lib -lsodium"
    fi
  else
    echo "Error: Custom libsodium not found at $LIBSODIUM_INSTALL_PATH/lib/libsodium.a" >&2
    echo "Run 'export LIBSODIUM_INSTALL=1 && ./build/libsodium_install.sh' first." >&2
    exit 1
  fi
else
  if is_macos; then
    ensure_explicit_bzero_shim
    printf '%s
' "$(pkg-config --libs libsodium) -L$LIBSODIUM_BUILD_DIR -lexplicit_bzero_shim"
  else
    pkg-config --libs libsodium
  fi
fi
