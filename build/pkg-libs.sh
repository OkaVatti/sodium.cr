#!/bin/sh
set -eu

# Shard directory passed as first argument when called from lib_sodium.cr.
[ -n "${1:-}" ] && cd "$1"

. ./build/env.sh

if [ "${LIBSODIUM_INSTALL:-}" = "1" ]; then
  if [ ! -f "$LIBSODIUM_INSTALL_PATH/lib/libsodium.a" ]; then
    echo "Error: Custom libsodium not found at $LIBSODIUM_INSTALL_PATH/lib/libsodium.a" >&2
    echo "Run 'export LIBSODIUM_INSTALL=1 && ./build/libsodium_install.sh' first." >&2
    exit 1
  fi

  if sodium_macos_needs_explicit_bzero_shim; then
    SHIM_DIR="$LIBSODIUM_BUILD_DIR/compat"
    SHIM_SRC="$SHIM_DIR/explicit_bzero_compat.c"
    SHIM_OBJ="$SHIM_DIR/explicit_bzero_compat.o"
    SHIM_LIB="$SHIM_DIR/libexplicit_bzero_compat.a"

    mkdir -p "$SHIM_DIR"

    if [ ! -f "$SHIM_SRC" ]; then
      cat > "$SHIM_SRC" <<'EOF'
#include <stddef.h>

#if defined(__APPLE__)

__attribute__((visibility("default")))
void explicit_bzero(void *buf, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len--) {
        *p++ = 0;
    }
}

#endif
EOF
    fi

    if [ ! -f "$SHIM_LIB" ] || [ "$SHIM_SRC" -nt "$SHIM_LIB" ]; then
      cc -c -o "$SHIM_OBJ" "$SHIM_SRC"
      ar rcs "$SHIM_LIB" "$SHIM_OBJ"
    fi

    echo "-L$SHIM_DIR -lexplicit_bzero_compat -L$LIBSODIUM_INSTALL_PATH/lib -lsodium"
  else
    echo "-L$LIBSODIUM_INSTALL_PATH/lib -lsodium"
  fi
else
  pkg-config --libs libsodium
fi
