#!/bin/sh

# Overridable.
[ -z "$LIBSODIUM_BUILD_DIR" ] && LIBSODIUM_BUILD_DIR=`pwd`/build

# Upgraded from time to time.
export MIN_LIBSODIUM_VERSION=1.0.22
export LIBSODIUM_SHA256=4f5e89fa84ce1d178a6765b8b46f2b5f912166e8648142f9a23e1b3e4e4b6e4c

[ ! -z "$SODIUM_BUILD_DEBUG" ] && export SODIUM_BUILD_VERBOSE=1

function version {
  echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }';
}

if `pkg-config libsodium --exists`; then
  PKG_VER=`pkg-config libsodium --modversion`
  if [ $(version "$PKG_VER") -ge $(version "$MIN_LIBSODIUM_VERSION") ]; then
    [ ! -z "$SODIUM_BUILD_VERBOSE" ] && echo "Using system libsodium $PKG_VER." 1>&2
  else
    echo "System libsodium $PKG_VER is too old.  libsodium >= $MIN_LIBSODIUM_VERSION is required." 1>&2
    echo "Install it with your package manager (e.g. apt install libsodium-dev, brew install libsodium)." 1>&2
    exit 1
  fi
else
  echo "libsodium not found.  Install it with your package manager." 1>&2
  echo "  macOS:  brew install libsodium" 1>&2
  echo "  Debian/Ubuntu:  apt install libsodium-dev" 1>&2
  echo "  Fedora:  dnf install libsodium-devel" 1>&2
  exit 1
fi