// メール表示画面(メッセージペインや別ウィンドウ)の読み込み完了時に、
// UI操作用スクリプト (messagedisplay.js) を自動的に注入・実行するよう登録
browser.messageDisplayScripts.register({
  js: [{ file: "messagedisplay.js" }],
  runAt: "document_end"
}).catch(() => {});

// 注入されたコンテンツスクリプトからの「メッセージ詳細取得」リクエストを待ち受け
browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.command === "getMessageDetails") {
    // 現在表示されているメールの基本情報（メッセージIDなど）を取得
    browser.messageDisplay.getDisplayedMessage()
      .then(msg => {
        if (!msg?.id) {
          sendResponse({ error: "No displayed message." });
          return;
        }
        // メッセージIDをもとに、ヘッダー等を含む完全なメールデータを取得
        return browser.messages.getFull(msg.id);
      })
      .then(full => {
        if (full) sendResponse({ fullMessage: full });
      })
      .catch(e => sendResponse({ error: e.toString() }));
      
    // 非同期処理 (Promise) の完了後に sendResponse を呼び出すため、true を返す
    return true;
  }
});