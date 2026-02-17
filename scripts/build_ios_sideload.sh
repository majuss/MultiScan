#!/usr/bin/env bash
set -euo pipefail

# Build artifacts for iOS sideloading.
# - unsigned (default): creates an IPA that users can re-sign with AltStore/Sideloadly.
# - signed-development: creates a development-signed IPA via Xcode export.

MODE="unsigned"
BUILD_NAME=""
BUILD_NUMBER=""
TARGET="lib/main.dart"

usage() {
  cat <<'EOF'
Usage: scripts/build_ios_sideload.sh [options]

Options:
  --mode <unsigned|signed-development>  Build mode (default: unsigned)
  --build-name <x.y.z>                  Override CFBundleShortVersionString
  --build-number <n>                    Override CFBundleVersion
  --target <path>                       Dart entrypoint (default: lib/main.dart)
  -h, --help                            Show this help

Outputs:
  - build/ios/ipa/MultiScan-unsigned.ipa
  - build/ios/ipa/MultiScan-development.ipa
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --build-name)
      BUILD_NAME="${2:-}"
      shift 2
      ;;
    --build-number)
      BUILD_NUMBER="${2:-}"
      shift 2
      ;;
    --target)
      TARGET="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ "$MODE" != "unsigned" && "$MODE" != "signed-development" ]]; then
  echo "Invalid mode: $MODE" >&2
  usage
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p build/ios/ipa

common_args=(
  --release
  --target "$TARGET"
)

if [[ -n "$BUILD_NAME" ]]; then
  common_args+=(--build-name "$BUILD_NAME")
fi

if [[ -n "$BUILD_NUMBER" ]]; then
  common_args+=(--build-number "$BUILD_NUMBER")
fi

if [[ "$MODE" == "unsigned" ]]; then
  echo "==> Building iOS app without codesign"
  flutter build ios "${common_args[@]}" --no-codesign

  APP_PATH="build/ios/iphoneos/Runner.app"
  if [[ ! -d "$APP_PATH" ]]; then
    echo "Runner.app not found at $APP_PATH" >&2
    exit 1
  fi

  STAGE_DIR="$(mktemp -d)"
  trap 'rm -rf "$STAGE_DIR"' EXIT
  mkdir -p "$STAGE_DIR/Payload"
  cp -R "$APP_PATH" "$STAGE_DIR/Payload/Runner.app"

  OUT_IPA="build/ios/ipa/MultiScan-unsigned.ipa"
  rm -f "$OUT_IPA"
  (
    cd "$STAGE_DIR"
    /usr/bin/zip -qry "$ROOT_DIR/$OUT_IPA" Payload
  )

  echo "Created unsigned IPA: $OUT_IPA"
  echo "Install by re-signing with AltStore/Sideloadly."
  exit 0
fi

echo "==> Building development-signed IPA"
flutter build ipa "${common_args[@]}" --export-method development

IPA_PATH="$(find build/ios/ipa -maxdepth 1 -name '*.ipa' -print -quit || true)"
if [[ -z "$IPA_PATH" ]]; then
  echo "No IPA produced in build/ios/ipa" >&2
  exit 1
fi

OUT_IPA="build/ios/ipa/MultiScan-development.ipa"
cp -f "$IPA_PATH" "$OUT_IPA"
echo "Created development IPA: $OUT_IPA"
