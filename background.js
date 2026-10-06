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

// 注入されたコンテンツスクリプトからの「メッセージ詳細取得」リクエストを待ち受け
browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.command === "getMessageDetails") {
    let currentMsg; // デコード済みの基本情報を保持する変数

    // 現在表示されているメールの基本情報（メッセージIDなど）を取得
    browser.messageDisplay.getDisplayedMessage()
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
    browser.messageDisplay.getDisplayedMessage()
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
});
