// メール表示画面(メッセージペインや別ウィンドウ)の読み込み完了時に、
// UI操作用スクリプト (messagedisplay.js) を自動的に注入・実行するよう登録
browser.messageDisplayScripts.register({
  js: [{ file: "messagedisplay.js" }],
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
});
