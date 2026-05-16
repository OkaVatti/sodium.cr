#!/bin/sh

# Overridable.
[ -z "$LIBSODIUM_BUILD_DIR" ] && LIBSODIUM_BUILD_DIR=`pwd`/build

# Custom installation prefix inside the build directory.
[ -z "$LIBSODIUM_INSTALL_PATH" ] && LIBSODIUM_INSTALL_PATH="$LIBSODIUM_BUILD_DIR/libsodium"

# Minimum required version.
export MIN_LIBSODIUM_VERSION=1.0.22

version() {
  echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'
}

if [ "$LIBSODIUM_INSTALL" = "1" ]; then
  # Forced custom build: set environment and return (do not exit)
  PKG_CONFIG_PATH="$LIBSODIUM_INSTALL_PATH/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
  export PKG_CONFIG_PATH
  export LIBSODIUM_INSTALL_PATH
  [ ! -z "$SODIUM_BUILD_VERBOSE" ] && echo "Will use custom libsodium from $LIBSODIUM_INSTALL_PATH" 1>&2
  return 0 2>/dev/null || true   # exit the sourced script gracefully
fi

# Otherwise, use system libsodium and verify version.
if pkg-config libsodium --exists; then
  PKG_VER=`pkg-config libsodium --modversion`
  if [ $(version "$PKG_VER") -ge $(version "$MIN_LIBSODIUM_VERSION") ]; then
    [ ! -z "$SODIUM_BUILD_VERBOSE" ] && echo "Using system libsodium $PKG_VER." 1>&2
  else
    echo "System libsodium $PKG_VER is too old. libsodium >= $MIN_LIBSODIUM_VERSION is required." 1>&2
    exit 1
  fi
else
  echo "libsodium not found. Install it with your package manager." 1>&2
  echo "  macOS:  brew install libsodium" 1>&2
  echo "  Debian/Ubuntu:  apt install libsodium-dev" 1>&2
  echo "  Fedora:  dnf install libsodium-devel" 1>&2
  exit 1
fi