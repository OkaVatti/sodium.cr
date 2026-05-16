#!/bin/bash
set -e

. ./build/env.sh

if [ "$LIBSODIUM_INSTALL" != "1" ]; then
  [ ! -z "$SODIUM_BUILD_VERBOSE" ] && echo "Skipping libsodium build." 1>&2
  exit 0
fi

mkdir -p "$LIBSODIUM_BUILD_DIR"
cd "$LIBSODIUM_BUILD_DIR"

LIBSODIUM_MINISIGN_KEY=RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
LIBSODIUM_SHA256="adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349"

if [ ! -f "$LIBSODIUM_INSTALL_PATH/include/sodium.h" ]; then
  [ ! -z "$SODIUM_BUILD_DEBUG" ] && set -x

  DIRNAME="libsodium-$MIN_LIBSODIUM_VERSION"
  TGZ_FILENAME="$DIRNAME.tar.gz"

  if [ ! -f "$TGZ_FILENAME" ]; then
    wget "https://download.libsodium.org/libsodium/releases/$TGZ_FILENAME.minisig"
    wget "https://download.libsodium.org/libsodium/releases/$TGZ_FILENAME"
  fi

  if command -v minisign >/dev/null 2>&1; then
    minisign -V -P "$LIBSODIUM_MINISIGN_KEY" -m "$TGZ_FILENAME"
  fi

  SHA=$(openssl sha256 -hex < "$TGZ_FILENAME" | sed 's/^.* //')
  if [ "$SHA" != "$LIBSODIUM_SHA256" ]; then
    echo "SHA256 mismatch. Expected $LIBSODIUM_SHA256, got $SHA" >&2
    exit 1
  fi

  if [ ! -d "$DIRNAME" ]; then
    tar xfz "$TGZ_FILENAME"
  fi

  cd "$DIRNAME"
  if [ ! -f ".configure.done" ]; then
    ./configure --prefix="$LIBSODIUM_INSTALL_PATH" --disable-shared
    touch .configure.done
  fi
  if [ ! -f ".make.done" ]; then
    make -j$(nproc)
    touch .make.done
  fi
  if [ ! -f ".make.install.done" ]; then
    make install
    touch .make.install.done
  fi

  [ ! -z "$SODIUM_BUILD_VERBOSE" ] && echo "Custom libsodium built at $LIBSODIUM_INSTALL_PATH" 1>&2
else
  [ ! -z "$SODIUM_BUILD_VERBOSE" ] && echo "Custom libsodium already exists at $LIBSODIUM_INSTALL_PATH" 1>&2
fi

exit 0