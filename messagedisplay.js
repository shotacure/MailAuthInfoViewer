// messagedisplay.js

(async () => {
  try {
    // バックグラウンドからメッセージ詳細を取得
    const resp = await browser.runtime.sendMessage({ command: "getMessageDetails" });
    if (resp.error || !resp.fullMessage) return;

    const fullMsg = resp.fullMessage;
    const headers = fullMsg.headers || {};

    // ---------------------------------------------------------
    // 1. データ解析ロジック
    // ---------------------------------------------------------

    // ■ エンベロープ情報の整理
    const envelopeFrom =
      fullMsg.envelope?.from ||
      headers["return-path"]?.[0]?.replace(/^<|>$/g, "") ||
      fullMsg.author ||
      "Unknown";
      
    const envelopeTo =
      (headers["delivered-to"] || []).join(", ") ||
      fullMsg.envelope?.to?.join(", ") ||
      (fullMsg.recipients || []).join(", ") ||
      "Unknown";

    // ■ 送達経路 (Received) の解析
    // 重要: Receivedヘッダは「新しい順」なので、reverse()して「送信元→受信先」にする
    const rawReceived = headers["received"] || [];
    const routeHops = rawReceived.slice().reverse().map(line => {
      // "from [ホスト名] by [ホスト名]" の形式を簡易解析
      const fromMatch = line.match(/\bfrom\s+([^\s;]+)/i);
      const byMatch = line.match(/\bby\s+([^\s;]+)/i);
      return {
        from: fromMatch ? fromMatch[1] : null,
        by: byMatch ? byMatch[1] : null,
        raw: line
      };
    }).filter(hop => hop.from || hop.by);

    // ■ 認証結果 (Authentication-Results) の解析
    // 最も信頼できるのは、通常一番上（index 0）にあるヘッダ（自サーバが付与したもの）
    const arRaw = headers["authentication-results"]?.[0] || "";
    
    // 簡易パーサ: "spf=pass", "dkim=pass" などを抽出
    const parseAuthStatus = (text, type) => {
      // 例: "spf=pass (google.com: domain of...)"
      const regex = new RegExp(`${type}\\s*=\\s*([a-zA-Z0-9]+)`, "i");
      const match = text.match(regex);
      return match ? match[1].toLowerCase() : "none";
    };

    // 詳細情報抽出
    const extractDetail = (text, type) => {
      if (type === 'spf') {
         const mailFrom = text.match(/smtp\.mailfrom=([^;\s]+)/i)?.[1];
         return mailFrom ? `domain: ${mailFrom}` : "";
      }
      if (type === 'dkim') {
        const headerD = text.match(/header\.d=([^;\s]+)/i)?.[1];
        return headerD ? `domain: ${headerD}` : "";
      }
      if (type === 'dmarc') {
        const headerFrom = text.match(/header\.from=([^;\s]+)/i)?.[1];
        return headerFrom ? `domain: ${headerFrom}` : "";
      }
      return "";
    };

    const authResults = {
      spf: { status: parseAuthStatus(arRaw, "spf"), detail: extractDetail(arRaw, "spf") },
      dkim: { status: parseAuthStatus(arRaw, "dkim"), detail: extractDetail(arRaw, "dkim") },
      dmarc: { status: parseAuthStatus(arRaw, "dmarc"), detail: extractDetail(arRaw, "dmarc") }
    };

    // 総合判定 (全部 pass なら OK)
    const isSpfOk = authResults.spf.status === "pass";
    const isDkimOk = authResults.dkim.status === "pass";
    const isDmarcOk = authResults.dmarc.status === "pass" || authResults.dmarc.status === "none"; // DMARCなしは許容する場合が多い
    
    // 簡易的な安全評価
    const isSecure = isSpfOk && isDkimOk; 

    // ---------------------------------------------------------
    // 2. UI構築 (HTML/CSS)
    // ---------------------------------------------------------

    // スタイル定義 (Flexbox/Grid使用)
    const style = document.createElement('style');
    style.textContent = `
      .maiv-container {
        font-family: "Segoe UI", Meiryo, sans-serif;
        background-color: #f9f9fa;
        border-bottom: 1px solid #ccc;
        padding: 12px;
        margin-bottom: 15px;
        color: #333;
        font-size: 13px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
      }
      .maiv-header {
        display: flex;
        align-items: center;
        margin-bottom: 10px;
      }
      .maiv-badge {
        font-weight: bold;
        padding: 4px 8px;
        border-radius: 4px;
        margin-right: 10px;
        color: white;
      }
      .maiv-badge.secure { background-color: #2e7d32; } /* Green */
      .maiv-badge.warning { background-color: #ed6c02; } /* Orange */
      .maiv-badge.danger { background-color: #d32f2f; } /* Red */
      
      .maiv-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 10px;
      }
      .maiv-card {
        background: white;
        border: 1px solid #e0e0e0;
        border-radius: 4px;
        padding: 8px;
      }
      .maiv-card-title {
        font-weight: bold;
        color: #555;
        margin-bottom: 4px;
        font-size: 11px;
        text-transform: uppercase;
      }
      .maiv-status-row {
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .maiv-status-icon { font-size: 14px; }
      
      .maiv-route-list {
        margin-top: 10px;
        background: white;
        border: 1px solid #e0e0e0;
        border-radius: 4px;
        padding: 8px;
        font-family: monospace;
        font-size: 11px;
        overflow-x: auto;
      }
      .maiv-route-step {
        display: flex;
        align-items: center;
      }
      .maiv-route-arrow {
        color: #999;
        margin: 0 5px;
      }
      
      /* ステータス別の色 */
      .status-pass { color: #2e7d32; font-weight: bold; }
      .status-fail { color: #d32f2f; font-weight: bold; }
      .status-none { color: #757575; }
    `;
    document.head.appendChild(style);

    // コンテナ作成
    const container = document.createElement("div");
    container.className = "maiv-container";

    // ■ ヘッダーエリア（総合判定）
    let badgeClass = "warning";
    let badgeText = "UNVERIFIED";
    if (isSecure) {
      badgeClass = "secure";
      badgeText = "AUTHENTICATED";
    } else if (authResults.spf.status === "fail" || authResults.dkim.status === "fail") {
      badgeClass = "danger";
      badgeText = "AUTH FAILED";
    }

    const headerHTML = `
      <div class="maiv-header">
        <span class="maiv-badge ${badgeClass}">${badgeText}</span>
        <span style="flex-grow:1;"></span>
        <small style="color:#666;">Auth Info Viewer</small>
      </div>
    `;

    // ■ 認証カード作成ヘルパー
    const createAuthCard = (title, data) => {
      let icon = "❓";
      let sClass = "status-none";
      if (data.status === "pass") { icon = "✅"; sClass = "status-pass"; }
      else if (data.status === "fail") { icon = "❌"; sClass = "status-fail"; }
      else if (data.status === "softfail") { icon = "⚠️"; sClass = "status-none"; }

      return `
        <div class="maiv-card">
          <div class="maiv-card-title">${title}</div>
          <div class="maiv-status-row">
            <span class="maiv-status-icon">${icon}</span>
            <span class="${sClass}">${data.status.toUpperCase()}</span>
          </div>
          <div style="font-size:11px; color:#666; margin-top:2px;">${data.detail}</div>
        </div>
      `;
    };

    // ■ エンベロープ情報カード
    const envelopeHTML = `
      <div class="maiv-card">
        <div class="maiv-card-title">ENVELOPE</div>
        <div style="font-size:11px;">
          <div><b style="color:#555">From:</b> ${envelopeFrom}</div>
          <div style="margin-top:2px;"><b style="color:#555">To:</b> ${envelopeTo}</div>
        </div>
      </div>
    `;

    // ■ 経路情報の構築
    // 最後のホップ(受信)を強調、それ以外は矢印でつなぐ
    let routeHTML = `<div class="maiv-route-list"><div class="maiv-card-title">DELIVERY ROUTE (Oldest &rarr; Newest)</div>`;
    routeHops.forEach((hop, idx) => {
      const isLast = idx === routeHops.length - 1;
      const label = hop.from ? `${hop.from}` : `(by ${hop.by})`;
      routeHTML += `
        <div class="maiv-route-step" style="${isLast ? 'font-weight:bold; color:#000;' : 'color:#666;'}">
           ${idx + 1}. ${label}
           ${hop.by && hop.from ? `<span style='color:#999; font-size:0.9em; margin-left:4px;'>(by ${hop.by})</span>` : ''}
        </div>
      `;
    });
    routeHTML += `</div>`;

    // HTML組み立て
    container.innerHTML = `
      ${headerHTML}
      <div class="maiv-grid">
        ${createAuthCard("SPF", authResults.spf)}
        ${createAuthCard("DKIM", authResults.dkim)}
        ${createAuthCard("DMARC", authResults.dmarc)}
        ${envelopeHTML}
      </div>
      ${routeHTML}
    `;

    // 挿入
    const existing = document.querySelector(".maiv-container");
    if (existing) existing.remove();
    document.body.insertAdjacentElement("afterbegin", container);

  } catch (e) {
    console.error("MailAuthInfoViewer Error:", e);
  }
})();