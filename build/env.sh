#!/bin/sh
set -eu

# Overridable paths.
[ -z "${LIBSODIUM_BUILD_DIR:-}" ] && LIBSODIUM_BUILD_DIR="$(pwd)/build"
[ -z "${LIBSODIUM_INSTALL_PATH:-}" ] && LIBSODIUM_INSTALL_PATH="$LIBSODIUM_BUILD_DIR/libsodium"

# Minimum required version.
MIN_LIBSODIUM_VERSION="1.0.22"
export MIN_LIBSODIUM_VERSION

sodium_version() {
  echo "$1" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'
}

sodium_cpu_count() {
  if command -v getconf >/dev/null 2>&1; then
    n="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
    if [ -n "${n:-}" ] && [ "$n" -gt 0 ] 2>/dev/null; then
      echo "$n"
      return 0
    fi
  fi

  if command -v sysctl >/dev/null 2>&1; then
    n="$(sysctl -n hw.logicalcpu 2>/dev/null || true)"
    if [ -n "${n:-}" ] && [ "$n" -gt 0 ] 2>/dev/null; then
      echo "$n"
      return 0
    fi
  fi

  echo 1
}

sodium_macos_needs_explicit_bzero_shim() {
  [ "$(uname -s 2>/dev/null || echo unknown)" = "Darwin" ]
}

if [ "${LIBSODIUM_INSTALL:-}" = "1" ]; then
  PKG_CONFIG_PATH="$LIBSODIUM_INSTALL_PATH/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
  export PKG_CONFIG_PATH
  export LIBSODIUM_INSTALL_PATH
  [ -n "${SODIUM_BUILD_VERBOSE:-}" ] && echo "Will use custom libsodium from $LIBSODIUM_INSTALL_PATH" 1>&2
  return 0 2>/dev/null || true
fi

if pkg-config --exists libsodium; then
  PKG_VER="$(pkg-config --modversion libsodium)"
  if [ "$(sodium_version "$PKG_VER")" -ge "$(sodium_version "$MIN_LIBSODIUM_VERSION")" ]; then
    [ -n "${SODIUM_BUILD_VERBOSE:-}" ] && echo "Using system libsodium $PKG_VER." 1>&2
  else
    echo "System libsodium $PKG_VER is too old. libsodium >= $MIN_LIBSODIUM_VERSION is required." 1>&2
    exit 1
  fi
else
  echo "libsodium not found. Install it with your package manager." 1>&2
  echo " macOS: brew install libsodium pkgconf" 1>&2
  echo " Debian/Ubuntu: apt install libsodium-dev pkg-config" 1>&2
  echo " Fedora: dnf install libsodium-devel pkgconf-pkg-config" 1>&2
  exit 1
fi
