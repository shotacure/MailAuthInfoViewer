## Required Libraries / 必要なライブラリ

This directory should contain the following third-party library:
このディレクトリには以下のサードパーティライブラリを配置してください:

### jsQR.js
- **Source:** https://github.com/cozmo/jsQR
- **Version:** 1.4.0 (see `VENDOR.md` for the exact URL and SHA-256)
- **License:** Apache-2.0 (place a copy of the license as `jsQR-LICENSE.txt`)
- **Purpose:** Reading QR codes in images contained in the message (QR code link analysis)

### How to obtain / 入手方法

```bash
# npm 経由
npm install
cp node_modules/jsqr/dist/jsQR.js lib/
cp node_modules/jsqr/LICENSE lib/jsQR-LICENSE.txt

# または CDN から直接ダウンロード
curl -o lib/jsQR.js https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js
curl -o lib/jsQR-LICENSE.txt https://cdn.jsdelivr.net/npm/jsqr@1.4.0/LICENSE
```
