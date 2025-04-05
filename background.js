// プログラム的に messagedisplay.js を注入
browser.messageDisplayScripts.register({
  js: [{ file: "messagedisplay.js" }],
  runAt: "document_end"
}).catch(() => {});

// コンテンツスクリプトからの「メッセージ詳細取得」リクエストに応答
browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.command === "getMessageDetails") {
    browser.messageDisplay.getDisplayedMessage()
      .then(msg => {
        if (!msg?.id) {
          sendResponse({ error: "No displayed message." });
          return;
        }
        return browser.messages.getFull(msg.id);
      })
      .then(full => {
        if (full) sendResponse({ fullMessage: full });
      })
      .catch(e => sendResponse({ error: e.toString() }));
    return true; // 非同期応答
  }
});
