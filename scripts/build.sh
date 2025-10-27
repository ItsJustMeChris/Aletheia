#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
ARCH="$(uname -m)"
ENTITLEMENTS="${PROJECT_ROOT}/scripts/entitlements.plist"

echo "[build] Project root: ${PROJECT_ROOT}"

mkdir -p "${BUILD_DIR}"

echo "[build] Compiling parent binary (bootstrap pass)..."
clang "${PROJECT_ROOT}/parent/main.c" -Wl,-segprot,__TEXT,rwx,r-x -o "${BUILD_DIR}/parent_binary"

echo "[build] Generating import manifest..."
python3 "${PROJECT_ROOT}/scripts/encrypt_binary.py" --manifest-only

echo "[build] Compiling parent binary with runtime imports..."
clang "${PROJECT_ROOT}/parent/main.c" "${PROJECT_ROOT}/parent/import_runtime.c" \
  -I "${BUILD_DIR}" -Wl,-segprot,__TEXT,rwx,r-x -o "${BUILD_DIR}/parent_binary"

echo "[build] Encrypting __TEXT,__text segment..."
python3 "${PROJECT_ROOT}/scripts/encrypt_binary.py"

echo "[build] Building watcher dylib for arch ${ARCH}..."
clang -dynamiclib -I "${BUILD_DIR}" -o "${BUILD_DIR}/libwatcher.dylib" "${PROJECT_ROOT}/dylib/watcher.c" -arch "${ARCH}"

if command -v codesign >/dev/null 2>&1; then
  echo "[build] Applying ad-hoc code signatures..."
  codesign -f -s - --timestamp=none --entitlements "${ENTITLEMENTS}" "${BUILD_DIR}/parent_binary" >/dev/null
  codesign -f -s - --timestamp=none --entitlements "${ENTITLEMENTS}" "${BUILD_DIR}/parent_binary_encrypted" >/dev/null
  codesign -f -s - --timestamp=none "${BUILD_DIR}/libwatcher.dylib" >/dev/null
else
  echo "[build] Skipping codesign: codesign tool not found."
fi

chmod +x "${BUILD_DIR}/parent_binary" "${BUILD_DIR}/parent_binary_encrypted" "${BUILD_DIR}/libwatcher.dylib"

echo "[build] Build complete."
