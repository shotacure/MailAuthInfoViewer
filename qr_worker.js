// qr_worker.js
// Mail Auth Info Viewer — QR コード読み取り用の Worker
// Copyright (C) 2025 Shota (SHOWTIME)
// License: GPL-3.0
//
// 攻撃者が作った画像を解析するため、デコーダ（lib/jsQR.js）は background 本体ではなくこの Worker で動かす。
// jsQR の処理は同期的で途中で止められないため、病的な画像で時間がかかっても、
// background 側が時間切れで Worker ごと破棄できるようにしている（他のメールのパネル表示を巻き込まない）。
// jsQR は QR コードの読み取りが必要になったときだけ読み込まれる。

importScripts("lib/jsQR.js");

// 受信: { id, pixels: Uint8ClampedArray (RGBA), width, height }
// 返信: { id, text }（QR コードが見つからなければ text は null）
self.onmessage = (event) => {
  const { id, pixels, width, height } = event.data;
  let text = null;
  try {
    const result = jsQR(pixels, width, height);
    if (result) text = result.data;
  } catch { /* 読み取れない画像は QR コード無しとして扱う */ }
  self.postMessage({ id, text });
};
