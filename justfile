#!/usr/bin/env just --justfile

default:
    @just --list

# ==============================================================================
# TESTING
# ==============================================================================

# Run tests with all features (default)
test:
    cargo test --all-features --all-targets
    cargo test --all-features --doc

# Run tests without optional features
test-no-features:
    cargo test --all-targets --no-default-features

# Run tests with only mip04 feature
test-mip04:
    cargo test --all-targets --no-default-features --features mip04

# Run all test combinations (like CI)
test-all:
    @echo "Testing with all features..."
    @just test
    @echo "Testing without optional features..."
    @just test-no-features
    @echo "Testing with mip04 feature only..."
    @just test-mip04

# ==============================================================================
# LINTING & FORMATTING
# ==============================================================================

# Check clippy for all feature combinations (uses stable by default)
lint:
    @bash scripts/check-clippy.sh

# Check clippy without features (for individual testing)
lint-no-features:
    cargo clippy --all-targets --no-default-features --no-deps -- -D warnings

# Check clippy with mip04 feature only (for individual testing)
lint-mip04:
    cargo clippy --all-targets --no-default-features --features mip04 --no-deps -- -D warnings

# Check fmt (uses stable by default)
fmt:
    @bash scripts/check-fmt.sh

# Check docs (uses stable by default)
docs:
    @bash scripts/check-docs.sh

# ==============================================================================
# PRE-COMMIT CHECKS
# ==============================================================================

# Pre-commit checks: quiet mode with minimal output (recommended for agents/CI)
precommit:
    @just _run-quiet "fmt"               "fmt (stable)"
    @just _run-quiet "docs"              "docs (stable)"
    @just _run-quiet "lint"              "clippy (stable)"
    @just _run-quiet "_fmt-msrv"         "fmt (msrv)"
    @just _run-quiet "_docs-msrv"        "docs (msrv)"
    @just _run-quiet "_lint-msrv"        "clippy (msrv)"
    @just _run-quiet "test"              "test (all features)"
    @just _run-quiet "test-no-features"  "test (no features)"
    @just _run-quiet "test-mip04"        "test (mip04)"
    @echo "PRECOMMIT PASSED"

# Pre-commit checks with verbose output (shows all command output)
precommit-verbose:
    @echo "=========================================="
    @echo "Running pre-commit checks (stable + MSRV)"
    @echo "=========================================="
    @echo ""
    @echo "→ Checking with stable Rust..."
    @bash scripts/check-all.sh stable
    @echo ""
    @echo "→ Checking with MSRV (1.90.0)..."
    @bash scripts/check-msrv.sh
    @echo ""
    @echo "→ Running tests..."
    @just test-all
    @echo ""
    @echo "=========================================="
    @echo "✓ All pre-commit checks passed!"
    @echo "=========================================="

# Quick check with stable (fast for local development)
check:
    @bash scripts/check-all.sh
    @just test-all

# Full comprehensive check including all feature combinations (same as check for now)
check-full:
    @just check

# ==============================================================================
# MSRV CHECK RECIPES (used by precommit quiet mode)
# ==============================================================================

# Check fmt with MSRV
[private]
_fmt-msrv:
    @bash scripts/check-fmt.sh 1.90.0

# Check docs with MSRV
[private]
_docs-msrv:
    @bash scripts/check-docs.sh 1.90.0

# Check clippy with MSRV
[private]
_lint-msrv:
    @bash scripts/check-clippy.sh 1.90.0

_build-uniffi needs_android="false" needs_ios="false":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building mdk-uniffi library..."
    cargo build --release --lib -p mdk-uniffi
    if [ "{{needs_android}}" = "true" ]; then
        just _build-uniffi-android aarch64-linux-android aarch64-linux-android21-clang
        just _build-uniffi-android armv7-linux-androideabi armv7a-linux-androideabi21-clang
        just _build-uniffi-android x86_64-linux-android x86_64-linux-android21-clang
    fi
    if [ "{{needs_ios}}" = "true" ] && [ "{{os()}}" = "macos" ]; then
        just _build-uniffi-ios aarch64-apple-ios
        just _build-uniffi-ios aarch64-apple-ios-sim
    fi

_build-uniffi-ios TARGET:
    #!/usr/bin/env bash
    set -euo pipefail

    # Check if the iOS target is installed
    if ! rustup target list --installed | grep -q "{{TARGET}}"; then
        echo "Error: Rust target '{{TARGET}}' is not installed." >&2
        echo "" >&2
        echo "Install it with:" >&2
        echo "  rustup target add {{TARGET}}" >&2
        echo "" >&2
        echo "For iOS development, you typically need:" >&2
        echo "  rustup target add aarch64-apple-ios        # iOS devices" >&2
        echo "  rustup target add aarch64-apple-ios-sim    # iOS Simulator (Apple Silicon)" >&2
        echo "  rustup target add x86_64-apple-ios         # iOS Simulator (Intel)" >&2
        exit 1
    fi

    cargo build --release --lib -p mdk-uniffi --target {{TARGET}}

_build-uniffi-android TARGET CLANG_PREFIX:
    #!/usr/bin/env bash
    set -euo pipefail

    # Check if the Android target is installed
    if ! rustup target list --installed | grep -q "{{TARGET}}"; then
        echo "Error: Rust target '{{TARGET}}' is not installed." >&2
        echo "" >&2
        echo "Install it with:" >&2
        echo "  rustup target add {{TARGET}}" >&2
        echo "" >&2
        echo "For Android development, you typically need:" >&2
        echo "  rustup target add aarch64-linux-android      # ARM64 devices" >&2
        echo "  rustup target add armv7-linux-androideabi    # ARM32 devices" >&2
        echo "  rustup target add x86_64-linux-android       # x86_64 emulator" >&2
        exit 1
    fi

    # Normalize platform detection to match NDK host-tag naming
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    # Map OS variants to canonical NDK host tags
    case "$OS" in
        linux*)
            NDK_OS="linux"
            ;;
        darwin*)
            NDK_OS="darwin"
            # NDK uses darwin-x86_64 even on Apple Silicon (Universal binaries)
            ARCH="x86_64"
            ;;
        mingw*|msys*|cygwin*|windows*)
            NDK_OS="windows"
            ARCH="x86_64"
            ;;
        *)
            echo "Error: Unsupported OS: $OS" >&2
            exit 1
            ;;
    esac

    NDK_HOST="${NDK_OS}-${ARCH}"
    NDK_PREBUILT="${NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/${NDK_HOST}"

    # Verify NDK directory exists
    if [ ! -d "$NDK_PREBUILT" ]; then
        echo "Error: NDK prebuilt directory not found: $NDK_PREBUILT" >&2
        echo "Please ensure NDK_HOME is set correctly or NDK is installed at /opt/android-ndk" >&2
        exit 1
    fi

    LLVM_BIN="${NDK_PREBUILT}/bin"

    TARGET_UPPER=$(echo "{{TARGET}}" | tr '[:lower:]-' '[:upper:]_')
    TARGET_UNDER=$(echo "{{TARGET}}" | tr '-' '_')

    export CC_${TARGET_UNDER}="${LLVM_BIN}/{{CLANG_PREFIX}}"
    export AR_${TARGET_UNDER}="${LLVM_BIN}/llvm-ar"
    export RANLIB_${TARGET_UNDER}="${LLVM_BIN}/llvm-ranlib"
    export CARGO_TARGET_${TARGET_UPPER}_LINKER="${LLVM_BIN}/{{CLANG_PREFIX}}"

    # Map target triple to Android ABI for OpenSSL directory lookup
    case "{{TARGET}}" in
        aarch64-linux-android)
            ANDROID_ABI="arm64-v8a"
            ;;
        armv7-linux-androideabi)
            ANDROID_ABI="armeabi-v7a"
            ;;
        x86_64-linux-android)
            ANDROID_ABI="x86_64"
            ;;
        i686-linux-android)
            ANDROID_ABI="x86"
            ;;
        *)
            echo "Error: Unknown Android target: {{TARGET}}" >&2
            exit 1
            ;;
    esac

    # Check for OpenSSL installation for Android
    # Look for target-specific dir first, then fall back to base ANDROID_OPENSSL_DIR
    if [ -n "${ANDROID_OPENSSL_DIR:-}" ]; then
        # Support both flat structure (ANDROID_OPENSSL_DIR/include, lib) and
        # per-ABI structure (ANDROID_OPENSSL_DIR/<abi>/include, lib)
        if [ -d "${ANDROID_OPENSSL_DIR}/${ANDROID_ABI}" ]; then
            OPENSSL_DIR="${ANDROID_OPENSSL_DIR}/${ANDROID_ABI}"
        else
            OPENSSL_DIR="${ANDROID_OPENSSL_DIR}"
        fi
    fi

    if [ -z "${OPENSSL_DIR:-}" ]; then
        echo "Error: OpenSSL for Android not found." >&2
        echo "" >&2
        echo "SQLCipher requires OpenSSL headers and libraries for Android builds." >&2
        echo "Please set ANDROID_OPENSSL_DIR to a directory containing prebuilt OpenSSL" >&2
        echo "for Android, with the following structure:" >&2
        echo "" >&2
        echo "  \$ANDROID_OPENSSL_DIR/" >&2
        echo "    arm64-v8a/" >&2
        echo "      include/openssl/*.h" >&2
        echo "      lib/libcrypto.a" >&2
        echo "    armeabi-v7a/" >&2
        echo "      include/openssl/*.h" >&2
        echo "      lib/libcrypto.a" >&2
        echo "    x86_64/" >&2
        echo "      include/openssl/*.h" >&2
        echo "      lib/libcrypto.a" >&2
        echo "" >&2
        echo "You can build OpenSSL for Android using the OpenSSL build system:" >&2
        echo "  <https://github.com/ArmynC/ArsLern-OpenSSL-Android>" >&2
        echo "  or follow the official docs: <https://wiki.openssl.org/index.php/Android>" >&2
        exit 1
    fi

    if [ ! -d "${OPENSSL_DIR}/include/openssl" ]; then
        echo "Error: OpenSSL headers not found at ${OPENSSL_DIR}/include/openssl" >&2
        exit 1
    fi

    # Set OpenSSL environment variables for the target
    # The openssl-sys crate looks for these target-prefixed variables
    export OPENSSL_DIR_${TARGET_UNDER}="${OPENSSL_DIR}"
    export OPENSSL_INCLUDE_DIR_${TARGET_UNDER}="${OPENSSL_DIR}/include"
    export OPENSSL_LIB_DIR_${TARGET_UNDER}="${OPENSSL_DIR}/lib"
    # Also set the non-prefixed versions as fallback
    export OPENSSL_DIR="${OPENSSL_DIR}"
    export OPENSSL_INCLUDE_DIR="${OPENSSL_DIR}/include"
    export OPENSSL_LIB_DIR="${OPENSSL_DIR}/lib"
    # Tell openssl-sys to use static linking
    export OPENSSL_STATIC=1

    cargo build --release --lib -p mdk-uniffi --target {{TARGET}}

uniffi-bindgen: (gen-binding "python") gen-binding-kotlin gen-binding-ruby
    @if [ "{{os()}}" = "macos" ]; then just gen-binding-swift; fi


lib_filename := if os() == "windows" {
    "mdk_uniffi.dll"
} else if os() == "macos" {
    "libmdk_uniffi.dylib"
} else {
    "libmdk_uniffi.so"
}

gen-binding lang: (_build-uniffi "false" "false")
    @echo "Generating {{lang}} bindings..."
    cd crates/mdk-uniffi && cargo run --bin uniffi-bindgen generate \
        -l {{lang}} \
        --library ../../target/release/{{lib_filename}} \
        --out-dir bindings/{{lang}}
    cp target/release/{{lib_filename}} crates/mdk-uniffi/bindings/{{lang}}/{{lib_filename}}
    @echo "✓ Bindings generated in crates/mdk-uniffi/bindings/{{lang}}/"

gen-binding-kotlin: (_build-uniffi "true") (gen-binding "kotlin")
    #!/usr/bin/env bash
    set -euo pipefail
    BINDINGS_DIR="crates/mdk-uniffi/bindings/kotlin"
    PROJECT_DIR="crates/mdk-uniffi/src/kotlin"

    mkdir -p "$PROJECT_DIR/src/main/jniLibs/arm64-v8a"
    mkdir -p "$PROJECT_DIR/src/main/jniLibs/armeabi-v7a"
    # mkdir -p "$PROJECT_DIR/src/main/jniLibs/x86-64"

    test -f target/aarch64-linux-android/release/libmdk_uniffi.so || (echo "Error: aarch64 Android library not found. Did the build succeed?" && exit 1)
    test -f target/armv7-linux-androideabi/release/libmdk_uniffi.so || (echo "Error: armv7 Android library not found. Did the build succeed?" && exit 1)

    cp target/aarch64-linux-android/release/libmdk_uniffi.so "$PROJECT_DIR/src/main/jniLibs/arm64-v8a/libmdk_uniffi.so"
    cp target/armv7-linux-androideabi/release/libmdk_uniffi.so "$PROJECT_DIR/src/main/jniLibs/armeabi-v7a/libmdk_uniffi.so"
    # cp target/x86_64-linux-android/release/libmdk_uniffi.so "$PROJECT_DIR/src/main/jniLibs/x86-64/libmdk_uniffi.so"
    rm -f "$BINDINGS_DIR/libmdk_uniffi.so"
    echo "✓ Kotlin bindings generated and moved to Android project"

build-android-lib: gen-binding-kotlin
    @echo "Building Android AAR..."
    cd crates/mdk-uniffi/src/kotlin && ./gradlew build
    @echo "✓ Android library built"

gen-binding-swift: (_build-uniffi "false" "true") (gen-binding "swift")
    @echo "Creating iOS xcframework..."
    mkdir -p ios-artifacts/headers
    cp crates/mdk-uniffi/bindings/swift/mdk_uniffiFFI.h ios-artifacts/headers/
    xcodebuild -create-xcframework \
        -library target/aarch64-apple-ios/release/libmdk_uniffi.a -headers ios-artifacts/headers \
        -library target/aarch64-apple-ios-sim/release/libmdk_uniffi.a -headers ios-artifacts/headers \
        -output ios-artifacts/mdk_uniffi.xcframework
    @echo "✓ Swift bindings and xcframework ready"

gen-binding-ruby: (gen-binding "ruby")
    #!/usr/bin/env bash
    set -euo pipefail
    RUBY_BINDING="$(pwd)/crates/mdk-uniffi/bindings/ruby/mdk_uniffi.rb"
    if [ ! -f "$RUBY_BINDING" ]; then
        echo "Ruby binding not found at $RUBY_BINDING" >&2
        exit 1
    fi
    # Use portable sed approach: detect OS and use appropriate syntax
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS requires empty string argument for -i
        sed -i '' '/^module MdkUniffiError$/,/^end$/c\
    module MdkUniffiError\
      class Storage < StandardError; end\
      class Mdk < StandardError; end\
      class InvalidInput < StandardError; end\
    end' "$RUBY_BINDING"
    else
        # Linux/GNU sed
        sed -i '/^module MdkUniffiError$/,/^end$/c\
    module MdkUniffiError\
      class Storage < StandardError; end\
      class Mdk < StandardError; end\
      class InvalidInput < StandardError; end\
    end' "$RUBY_BINDING"
    fi
    # Validate the Ruby file parses correctly
    ruby -c "$RUBY_BINDING" || (echo "Error: Ruby binding file does not parse correctly after patching" >&2 && exit 1)
    echo "✓ Ruby binding patched (MdkUniffiError classes)"
# Run test coverage with summary output
coverage:
    @bash scripts/coverage.sh

coverage-during-dev:
    @bash scripts/get-coverage.sh

# Generate HTML coverage report
coverage-html:
    @bash scripts/coverage.sh --html

# Run the key package inspection example
example-keypackage:
    cargo run -p mdk-core --example key_package_inspection

# Run the group inspection example (requires debug-examples feature)
example-group:
    cargo run -p mdk-core --example group_inspection --features debug-examples

# Run the MLS memory storage example
example-memory:
    cargo run -p mdk-core --example mls_memory

# Run the MLS SQLite storage example
example-sqlite:
    cargo run -p mdk-core --example mls_sqlite

# Run all examples
examples:
    @echo "→ Running key package inspection example..."
    @just example-keypackage
    @echo ""
    @echo "→ Running group inspection example..."
    @just example-group
    @echo ""
    @echo "→ Running memory storage example..."
    @just example-memory
    @echo ""
    @echo "→ Running SQLite storage example..."
    @just example-sqlite

# Trigger TestPyPI publish workflow (requires gh CLI and appropriate permissions)
publish-test-pypi:
    @echo "Triggering TestPyPI publish workflow..."
    gh workflow run package-mdk-bindings.yml -f publish_test_pypi=true
    @echo "✓ Workflow triggered. Check status at: https://github.com/marmot-protocol/mdk/actions"

# ==============================================================================
# HELPER RECIPES
# ==============================================================================

# Run a recipe quietly, showing only name and pass/fail status (internal use)
[private]
_run-quiet recipe label:
    #!/usr/bin/env bash
    TMPFILE=$(mktemp)
    trap 'rm -f "$TMPFILE"' EXIT
    printf "  %-25s" "{{label}}..."
    if just {{recipe}} > "$TMPFILE" 2>&1; then
        echo "✓"
    else
        echo "✗"
        echo ""
        cat "$TMPFILE"
        exit 1
    fi

