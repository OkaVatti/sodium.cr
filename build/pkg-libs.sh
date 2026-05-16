#!/bin/bash
set -e

# Shard directory passed as first argument when called from lib_sodium.cr
[ ! -z "$1" ] && cd "$1"

. ./build/env.sh

if [ "$LIBSODIUM_INSTALL" = "1" ]; then
  # Directly return the static library path, ignoring pkg-config
  if [ -f "$LIBSODIUM_INSTALL_PATH/lib/libsodium.a" ]; then
    echo "-L$LIBSODIUM_INSTALL_PATH/lib -lsodium"
  else
    echo "Error: Custom libsodium not found at $LIBSODIUM_INSTALL_PATH/lib/libsodium.a" >&2
    echo "Run 'export LIBSODIUM_INSTALL=1 && ./build/libsodium_install.sh' first." >&2
    exit 1
  fi
else
  pkg-config --libs libsodium
fi