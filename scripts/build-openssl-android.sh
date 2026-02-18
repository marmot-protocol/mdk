#!/usr/bin/env bash
# Build OpenSSL for Android
#
# Usage: ./build-openssl-android.sh <ABI> <OUTPUT_DIR>
#
# Example:
#   ./build-openssl-android.sh arm64-v8a /path/to/output
#
# This script builds OpenSSL from source for the specified Android ABI.
# It requires the Android NDK to be installed and NDK_HOME to be set.

set -euo pipefail

ABI="${1:-}"
OUTPUT_DIR="${2:-}"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.3.2}"

if [ -z "$ABI" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <ABI> <OUTPUT_DIR>"
    echo "  ABI: arm64-v8a, armeabi-v7a, x86_64, x86"
    echo "  OUTPUT_DIR: Directory to install OpenSSL to"
    exit 1
fi

if [ -z "${NDK_HOME:-}" ]; then
    echo "Error: NDK_HOME environment variable is not set"
    exit 1
fi

# Map ABI to OpenSSL target and NDK clang triple
case "$ABI" in
    arm64-v8a)
        OPENSSL_TARGET="android-arm64"
        ANDROID_API=21
        CLANG_TRIPLE="aarch64-linux-android"
        ;;
    armeabi-v7a)
        OPENSSL_TARGET="android-arm"
        ANDROID_API=21
        CLANG_TRIPLE="armv7a-linux-androideabi"
        ;;
    x86_64)
        OPENSSL_TARGET="android-x86_64"
        ANDROID_API=21
        CLANG_TRIPLE="x86_64-linux-android"
        ;;
    x86)
        OPENSSL_TARGET="android-x86"
        ANDROID_API=21
        CLANG_TRIPLE="i686-linux-android"
        ;;
    *)
        echo "Error: Unknown ABI: $ABI"
        exit 1
        ;;
esac

# Detect host platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
    linux*)
        NDK_HOST="linux-x86_64"
        ;;
    darwin*)
        NDK_HOST="darwin-x86_64"
        ;;
    *)
        echo "Error: Unsupported host OS: $OS"
        exit 1
        ;;
esac

# Set up paths
TOOLCHAIN="${NDK_HOME}/toolchains/llvm/prebuilt/${NDK_HOST}"
export PATH="${TOOLCHAIN}/bin:$PATH"
export ANDROID_NDK_ROOT="${NDK_HOME}"

# NDK r23+ removed standalone GCC toolchains. OpenSSL's android-* targets
# look for <triple>-gcc by default, so we explicitly set CC/AR/RANLIB to
# point at the LLVM/Clang equivalents shipped with modern NDKs.
export CC="${CLANG_TRIPLE}${ANDROID_API}-clang"
export AR="llvm-ar"
export RANLIB="llvm-ranlib"

# Create temporary build directory
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "${BUILD_DIR}"' EXIT

echo "Building OpenSSL ${OPENSSL_VERSION} for ${ABI}..."
echo "  Target: ${OPENSSL_TARGET}"
echo "  NDK: ${NDK_HOME}"
echo "  Output: ${OUTPUT_DIR}"

# Download OpenSSL source
cd "${BUILD_DIR}"
curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    -o openssl.tar.gz
tar -xzf openssl.tar.gz
cd "openssl-${OPENSSL_VERSION}"

# Configure OpenSSL
./Configure "${OPENSSL_TARGET}" \
    -D__ANDROID_API__="${ANDROID_API}" \
    --prefix="${OUTPUT_DIR}" \
    --openssldir="${OUTPUT_DIR}/ssl" \
    no-shared \
    no-tests \
    no-ui-console

# Build and install
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)"
make install_sw

echo "OpenSSL ${OPENSSL_VERSION} for ${ABI} installed to ${OUTPUT_DIR}"
ls -la "${OUTPUT_DIR}/lib/"
