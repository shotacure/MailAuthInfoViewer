#!/usr/bin/env bash
set -euo pipefail

# --- manifest から version を取得 ---
VERSION=$(python3 -c "import json; print(json.load(open('manifest.json'))['version'])" 2>/dev/null \
  || node -e "console.log(require('./manifest.json').version)" 2>/dev/null \
  || grep '"version"' manifest.json | head -1 | sed 's/.*: *"\([^"]*\)".*/\1/')

if [ -z "$VERSION" ]; then
  echo "Error: Could not read version from manifest.json" >&2
  exit 1
fi

# --- 出力パス定義 ---
OUT_DIR=".release"
FILE_NAME="MailAuthInfoViewer-${VERSION}.xpi"
OUT_FILE="${OUT_DIR}/${FILE_NAME}"
STAGE_DIR="${OUT_DIR}/_stage"

# --- クリーンアップ ---
mkdir -p "$OUT_DIR"
rm -f "$OUT_FILE"
rm -rf "$STAGE_DIR"

# --- ステージング（階層維持） ---
mkdir -p "${STAGE_DIR}/images"

cp manifest.json     "$STAGE_DIR/"
cp background.js     "$STAGE_DIR/"
cp psl_data.js       "$STAGE_DIR/"
cp messagedisplay.js "$STAGE_DIR/"
cp LICENSE           "$STAGE_DIR/"
cp images/icon.svg   "${STAGE_DIR}/images/"

# --- _locales ディレクトリをコピー ---
cp -r _locales       "${STAGE_DIR}/_locales"

# --- 圧縮 (zip → xpi) ---
(cd "$STAGE_DIR" && zip -r -q "../../${OUT_FILE}" .)

# --- ステージ削除 ---
rm -rf "$STAGE_DIR"

# --- SHA256 生成 ---
if command -v sha256sum &>/dev/null; then
  HASH=$(sha256sum "$OUT_FILE" | awk '{print $1}')
elif command -v shasum &>/dev/null; then
  HASH=$(shasum -a 256 "$OUT_FILE" | awk '{print $1}')
else
  echo "Warning: No sha256sum or shasum found, skipping checksum." >&2
  HASH="(unavailable)"
fi

HASH_FILE="${OUT_FILE}.sha256"
echo "${HASH}  ${FILE_NAME}" > "$HASH_FILE"

# --- 出力 ---
echo "Created: ${OUT_FILE}"
echo "SHA256:  ${HASH}"
echo "Checksum file created: ${HASH_FILE}"
