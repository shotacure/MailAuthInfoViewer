// メール表示画面(メッセージペインや別ウィンドウ)の読み込み完了時に、
// PSLデータとUI操作用スクリプトを自動的に注入・実行するよう登録。
// psl_data.js は messagedisplay.js が参照する getOrganizationalDomain() を提供するため、
// 先に読み込む必要がある。
browser.messageDisplayScripts.register({
  js: [
    { file: "psl_data.js" },
    { file: "messagedisplay.js" }
  ],
  runAt: "document_end"
}).catch((e) => {
  console.warn("MailAuthInfoViewer: Failed to register messageDisplayScripts:", e);
});

// リクエスト元のコンテンツスクリプトが動いているタブで表示中のメールを取得する。
// getDisplayedMessage() をタブ指定なしで呼ぶと「アクティブなタブ」のメールが返るため、
// 背景タブで開いたメールに前面タブのメールの判定が表示されてしまう。
// タブを特定できない場合は別のメールを解析しないよう、エラーとして扱う（安全側）。
const getSenderDisplayedMessage = (sender) => {
  const tabId = sender?.tab?.id;
  if (typeof tabId !== "number") return Promise.reject(new Error("Unknown sender tab."));
  return browser.messageDisplay.getDisplayedMessage(tabId);
};

// =========================================================
// QR コードの読み取り
// =========================================================
// 本文に埋め込まれた画像（data: URI）と画像パート（インライン画像・画像添付）から QR コードを読み取る。
// 画像のデコード（ピクセル化）は Thunderbird 自身の画像処理（createImageBitmap）で行い、
// QR コードの解析は Worker（qr_worker.js → lib/jsQR.js）に任せる。
// 外部サーバ上の画像は取得しない（リモートコンテンツを読み込まない Thunderbird の方針を守るため）。
// 大きな写真や大量の画像でメール表示が遅れないよう、対象の数と大きさに上限を設ける。
const QR_MAX_IMAGES = 10;
const QR_MAX_BYTES = 5 * 1024 * 1024;
const QR_MAX_DIMENSION = 1600;  // これより大きい画像は縮小してから読み取る
const QR_MIN_DIMENSION = 40;    // アイコン程度の小さな画像は QR コードとして読めないため対象外
const QR_DECODE_TIMEOUT_MS = 1000; // 1 枚あたりの解析の上限。超えたら Worker ごと破棄する
const QR_IMAGE_TYPE = /^image\/(png|jpe?g|gif|webp|bmp)$/i;

// QR コード解析用の Worker を 1 回の読み取り（1 通のメール）ごとに用意する。
// 別のタブの読み取りと Worker を共有しないため、時間切れで Worker を破棄しても他のメールの解析を巻き込まない。
// 読み取りが終わったら破棄し、使わない間はデコーダをメモリに残さない。
const createQrDecoder = () => {
  let worker = null;
  let nextId = 0;

  // ピクセル列を Worker に渡し、QR コードの内容を返す。見つからない・時間切れの場合は null。
  // 時間切れの Worker は解析を止められないため破棄し、次の画像では作り直す。
  const decode = (pixels, width, height) => new Promise((resolve) => {
    if (!worker) worker = new Worker("qr_worker.js");
    const id = ++nextId;
    const current = worker;
    const timer = setTimeout(() => {
      current.terminate();
      if (worker === current) worker = null;
      resolve(null);
    }, QR_DECODE_TIMEOUT_MS);
    current.onmessage = (event) => {
      if (event.data.id !== id) return;
      clearTimeout(timer);
      resolve(event.data.text);
    };
    current.postMessage({ id, pixels, width, height }, [pixels.buffer]);
  });

  const close = () => {
    if (worker) worker.terminate();
    worker = null;
  };

  return { decode, close };
};

// 画像 1 枚を読み取り、QR コードの内容（文字列）を返す。見つからなければ null。
const decodeQrFromBlob = async (blob, decoder) => {
  const bitmap = await createImageBitmap(blob);
  let pixels, width, height;
  try {
    if (bitmap.width < QR_MIN_DIMENSION || bitmap.height < QR_MIN_DIMENSION) return null;
    const scale = Math.min(1, QR_MAX_DIMENSION / Math.max(bitmap.width, bitmap.height));
    width = Math.max(1, Math.round(bitmap.width * scale));
    height = Math.max(1, Math.round(bitmap.height * scale));
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    // 透過 PNG の QR コード（透明地に黒）を読めるよう、白地の上に描画する
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, width, height);
    ctx.drawImage(bitmap, 0, 0, width, height);
    pixels = ctx.getImageData(0, 0, width, height).data;
  } finally {
    bitmap.close();
  }
  return decoder.decode(pixels, width, height);
};

// data: URI（base64）の画像を Blob に変換する
const dataUriToBlob = (mimeType, base64) => {
  const binary = atob(base64.replace(/\s+/g, ""));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new Blob([bytes], { type: mimeType });
};

// 表示中のメールに含まれる QR コードの内容を配列で返す
const scanQrCodes = async (messageId) => {
  const full = await browser.messages.getFull(messageId);
  const sources = []; // { kind: "data", mimeType, base64 } | { kind: "part", partName }
  const walk = (parts) => {
    for (const part of (parts || [])) {
      const ct = (part.contentType || "").toLowerCase();
      if (ct === "text/html" && typeof part.body === "string") {
        for (const m of part.body.matchAll(/data:(image\/(?:png|jpe?g|gif|webp|bmp));base64,([A-Za-z0-9+/=\s]+)/gi)) {
          if (m[2].length * 3 / 4 <= QR_MAX_BYTES) sources.push({ kind: "data", mimeType: m[1], base64: m[2] });
        }
      } else if (QR_IMAGE_TYPE.test(ct) && part.partName && !(part.size > QR_MAX_BYTES)) {
        sources.push({ kind: "part", partName: part.partName });
      }
      if (part.parts) walk(part.parts);
    }
  };
  walk(full.parts);

  const qrCodes = [];
  if (sources.length === 0) return qrCodes;
  const decoder = createQrDecoder();
  try {
    for (const src of sources.slice(0, QR_MAX_IMAGES)) {
      try {
        const blob = (src.kind === "data")
          ? dataUriToBlob(src.mimeType, src.base64)
          : await browser.messages.getAttachmentFile(messageId, src.partName);
        if (!blob || blob.size > QR_MAX_BYTES) continue;
        const text = await decodeQrFromBlob(blob, decoder);
        if (text !== null) qrCodes.push(text);
      } catch { /* 壊れた画像や未対応の形式は読み飛ばす */ }
    }
  } finally {
    decoder.close();
  }
  return qrCodes;
};

// 注入されたコンテンツスクリプトからの「メッセージ詳細取得」リクエストを待ち受け
browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.command === "getMessageDetails") {
    let currentMsg; // デコード済みの基本情報を保持する変数

    // リクエスト元のタブに表示されているメールの基本情報（メッセージIDなど）を取得
    getSenderDisplayedMessage(sender)
      .then(msg => {
        if (!msg?.id) {
          sendResponse({ error: "No displayed message." });
          return;
        }
        currentMsg = msg; // 取得した基本情報(文字化け解決用のデコード済データ含む)を保存
        // メッセージIDをもとに、ヘッダー等を含む完全なメールデータを取得
        return browser.messages.getFull(msg.id);
      })
      .then(full => {
        // 文字化け対策として、Thunderbirdがパース・デコード済みの currentMsg も一緒に返す
        if (full) sendResponse({ fullMessage: full, messageHeader: currentMsg });
      })
      .catch(e => sendResponse({ error: e.toString() }));
      
    // 非同期処理 (Promise) の完了後に sendResponse を呼び出すため、true を返す
    return true;
  }

  // 生ヘッダ（ヘッダ部のみ）の取得リクエスト。
  // getFull のヘッダはヘッダ名ごとにまとめられ、異なるヘッダ間の前後関係が失われるため、
  // 「Authentication-Results が受信境界の Received より上にあるか」の検証用に
  // 生のヘッダ順序を返す。本文や添付は不要なので最初の空行までに切り詰めて返す。
  if (request.command === "getRawHeaders") {
    getSenderDisplayedMessage(sender)
      .then(msg => {
        if (!msg?.id) throw new Error("No displayed message.");
        return browser.messages.getRaw(msg.id);
      })
      .then(async raw => {
        // Thunderbird のバージョン・オプションにより文字列または File で返る
        const text = (typeof raw === "string") ? raw : await raw.text();
        const end = text.search(/\r?\n\r?\n/);
        sendResponse({ rawHeaders: end >= 0 ? text.slice(0, end) : text });
      })
      .catch(e => sendResponse({ error: e.toString() }));
    return true;
  }

  // QR コードの読み取りリクエスト。リクエスト元のタブに表示中のメールだけを対象にする。
  if (request.command === "scanQrCodes") {
    getSenderDisplayedMessage(sender)
      .then(msg => {
        if (!msg?.id) throw new Error("No displayed message.");
        return scanQrCodes(msg.id);
      })
      .then(qrCodes => sendResponse({ qrCodes }))
      .catch(e => sendResponse({ error: e.toString() }));
    return true;
  }
});
