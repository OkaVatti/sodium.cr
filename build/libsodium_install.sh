#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"

if [ "${LIBSODIUM_INSTALL:-0}" != "1" ]; then
  if [ -n "${SODIUM_BUILD_VERBOSE:-}" ]; then
    echo "Skipping libsodium build." >&2
  fi
  exit 0
fi

cd "$repo_root"

# shellcheck source=build/env.sh
. "$script_dir/env.sh"

mkdir -p "$LIBSODIUM_BUILD_DIR"
cd "$LIBSODIUM_BUILD_DIR"

LIBSODIUM_MINISIGN_KEY='RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
LIBSODIUM_SHA256='adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349'

get_cpu_count() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
    return
  fi

  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.logicalcpu 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1
    return
  fi

  if command -v getconf >/dev/null 2>&1; then
    getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1
    return
  fi

  echo 1
}

build_explicit_bzero_shim() {
  if ! is_macos; then
    return 0
  fi

  ensure_explicit_bzero_shim
}

if [ ! -f "$LIBSODIUM_INSTALL_PATH/include/sodium.h" ]; then
  [ -n "${SODIUM_BUILD_DEBUG:-}" ] && set -x

  DIRNAME="libsodium-$MIN_LIBSODIUM_VERSION"
  TGZ_FILENAME="$DIRNAME.tar.gz"

  if [ ! -f "$TGZ_FILENAME" ]; then
    wget "https://download.libsodium.org/libsodium/releases/$TGZ_FILENAME.minisig"
    wget "https://download.libsodium.org/libsodium/releases/$TGZ_FILENAME"
  fi

  if command -v minisign >/dev/null 2>&1; then
    minisign -V -P "$LIBSODIUM_MINISIGN_KEY" -m "$TGZ_FILENAME"
  fi

  SHA="$(shasum -a 256 "$TGZ_FILENAME" | awk '{print $1}')"
  if [ "$SHA" != "$LIBSODIUM_SHA256" ]; then
    echo "SHA256 mismatch." >&2
    echo "Expected $LIBSODIUM_SHA256, got $SHA" >&2
    exit 1
  fi

  if [ ! -d "$DIRNAME" ]; then
    tar xzf "$TGZ_FILENAME"
  fi

  cd "$DIRNAME"

  if [ ! -f ".configure.done" ]; then
    ./configure --prefix="$LIBSODIUM_INSTALL_PATH" --disable-shared
    touch .configure.done
  fi

  if [ ! -f ".make.done" ]; then
    make -j"$(get_cpu_count)"
    touch .make.done
  fi

  if [ ! -f ".make.install.done" ]; then
    make install
    touch .make.install.done
  fi

  build_explicit_bzero_shim

  if [ -n "${SODIUM_BUILD_VERBOSE:-}" ]; then
    echo "Custom libsodium built at $LIBSODIUM_INSTALL_PATH" >&2
  fi
else
  build_explicit_bzero_shim

  if [ -n "${SODIUM_BUILD_VERBOSE:-}" ]; then
    echo "Custom libsodium already exists at $LIBSODIUM_INSTALL_PATH" >&2
  fi
fi

exit 0
