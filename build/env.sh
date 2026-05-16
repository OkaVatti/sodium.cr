#!/usr/bin/env sh
set -eu

# Overridable.
if [ -z "${LIBSODIUM_BUILD_DIR:-}" ]; then
  LIBSODIUM_BUILD_DIR="$(pwd)/build"
fi

# Custom installation prefix inside the build directory.
if [ -z "${LIBSODIUM_INSTALL_PATH:-}" ]; then
  LIBSODIUM_INSTALL_PATH="$LIBSODIUM_BUILD_DIR/libsodium"
fi

# Minimum required version.
MIN_LIBSODIUM_VERSION="${MIN_LIBSODIUM_VERSION:-1.0.22}"

EXPLICIT_BZERO_SHIM_C="$LIBSODIUM_BUILD_DIR/explicit_bzero_shim.c"
EXPLICIT_BZERO_SHIM_O="$LIBSODIUM_BUILD_DIR/explicit_bzero_shim.o"
EXPLICIT_BZERO_SHIM_A="$LIBSODIUM_BUILD_DIR/libexplicit_bzero_shim.a"

export LIBSODIUM_BUILD_DIR
export LIBSODIUM_INSTALL_PATH
export MIN_LIBSODIUM_VERSION
export EXPLICIT_BZERO_SHIM_C
export EXPLICIT_BZERO_SHIM_O
export EXPLICIT_BZERO_SHIM_A

version() {
  echo "$1" | awk -F. '{ printf("%d%03d%03d%03d\n", $1, $2, $3, $4); }'
}

is_macos() {
  [ "$(uname -s 2>/dev/null || printf '')" = "Darwin" ]
}

write_explicit_bzero_shim_source() {
  mkdir -p "$LIBSODIUM_BUILD_DIR"

  cat > "$EXPLICIT_BZERO_SHIM_C" <<'EOF'
#include <stddef.h>

void explicit_bzero(void *buf, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len-- > 0) {
        *p++ = 0;
    }
}
EOF
}

ensure_explicit_bzero_shim() {
  if ! is_macos; then
    return 0
  fi

  mkdir -p "$LIBSODIUM_BUILD_DIR"

  if [ ! -f "$EXPLICIT_BZERO_SHIM_C" ]; then
    write_explicit_bzero_shim_source
  fi

  if [ ! -f "$EXPLICIT_BZERO_SHIM_A" ] || [ "$EXPLICIT_BZERO_SHIM_C" -nt "$EXPLICIT_BZERO_SHIM_A" ]; then
    : "${CC:=cc}"
    "${CC}" -std=c11 -O2 -c "$EXPLICIT_BZERO_SHIM_C" -o "$EXPLICIT_BZERO_SHIM_O"
    ar rcs "$EXPLICIT_BZERO_SHIM_A" "$EXPLICIT_BZERO_SHIM_O"
  fi
}

if [ "${LIBSODIUM_INSTALL:-0}" = "1" ]; then
  PKG_CONFIG_DIR="$LIBSODIUM_INSTALL_PATH/lib/pkgconfig"
  if [ -z "${PKG_CONFIG_PATH:-}" ]; then
    PKG_CONFIG_PATH="$PKG_CONFIG_DIR"
  else
    PKG_CONFIG_PATH="$PKG_CONFIG_DIR:$PKG_CONFIG_PATH"
  fi

  export PKG_CONFIG_PATH

  if [ -n "${SODIUM_BUILD_VERBOSE:-}" ]; then
    echo "Will use custom libsodium from $LIBSODIUM_INSTALL_PATH" >&2
  fi

  return 0 2>/dev/null || exit 0
fi

if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libsodium; then
  PKG_VER="$(pkg-config --modversion libsodium)"
  if [ "$(version "$PKG_VER")" -ge "$(version "$MIN_LIBSODIUM_VERSION")" ]; then
    if [ -n "${SODIUM_BUILD_VERBOSE:-}" ]; then
      echo "Using system libsodium $PKG_VER." >&2
    fi
    return 0 2>/dev/null || exit 0
  fi

  echo "System libsodium $PKG_VER is too old. libsodium >= $MIN_LIBSODIUM_VERSION is required." >&2
else
  echo "libsodium not found." >&2
  echo "Install it with your package manager." >&2
  echo " macOS: brew install libsodium" >&2
  echo " Debian/Ubuntu: apt install libsodium-dev" >&2
  echo " Fedora: dnf install libsodium-devel" >&2
fi

exit 1
