#!/bin/bash
set -e

# Shard directory passed as first argument when called from lib_sodium.cr
[ ! -z "$1" ] && cd "$1"

. ./build/env.sh

pkg-config libsodium --libs