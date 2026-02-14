// messagedisplay.js

(async () => {
  try {
    // バックグラウンドスクリプトへメッセージ詳細情報の取得をリクエスト
    const resp = await browser.runtime.sendMessage({ command: "getMessageDetails" });
    if (resp.error || !resp.fullMessage) return;

    const fullMsg = resp.fullMessage;
    const headers = fullMsg.headers || {};

    // ---------------------------------------------------------
    // 1. データ解析ロジック
    // ---------------------------------------------------------

    // ■ エンベロープ情報の抽出
    // envelope.from、return-path、またはauthorを評価し、送信元アドレスを特定
    const envelopeFrom =
      fullMsg.envelope?.from ||
      headers["return-path"]?.[0]?.replace(/^<|>$/g, "") ||
      fullMsg.author ||
      "Unknown";
      
    // delivered-to、envelope.to、またはrecipientsを評価し、宛先アドレスを特定
    const envelopeTo =
      (headers["delivered-to"] || []).join(", ") ||
      fullMsg.envelope?.to?.join(", ") ||
      (fullMsg.recipients || []).join(", ") ||
      "Unknown";

    // ■ 送達経路 (Receivedヘッダ) の解析
    // Receivedヘッダは「新しい順(受信側→送信元)」で記録されるため、
    // reverse()を用いて「時系列順(送信元→受信側)」に並び替えて処理する
    const rawReceived = headers["received"] || [];
    
    // 日時文字列パース用ヘルパー関数
    const parseReceivedDate = (str) => {
      // Receivedヘッダの末尾（セミコロン以降）に記録されている日時文字列を抽出・Date化
      const match = str.match(/;\s*([^;]+)$/);
      return match ? new Date(match[1]) : null;
    };

    // 経路情報(ホップごとの通過サーバと日時)のオブジェクト配列を生成
    const routeHops = rawReceived.slice().reverse().map(line => {
      // "from" から始まり、"by"、セミコロン、または行末までの範囲を取得し、IPアドレス等の詳細情報を含める
      const fromMatch = line.match(/\bfrom\s+(.+?)(?=\s+by\s+|;|$)/i);
      // "by" に続くホスト名（受信したMTA）を取得
      const byMatch = line.match(/\bby\s+([^\s;]+)/i);
      const date = parseReceivedDate(line);

      return {
        // 正規表現でキャプチャした値の前後の空白を除去して格納
        from: fromMatch ? fromMatch[1].trim() : null,
        by: byMatch ? byMatch[1] : null,
        date: date,
        raw: line
      };
    }).filter(hop => hop.from || hop.by);

    // ■ メール認証結果 (Authentication-Results / ARC) の解析
    // Authentication-Results および ARC-Authentication-Results ヘッダを配列として結合し、
    // 複数行に跨る場合やARC側にしか結果が存在しない場合に対応
    const authHeaders = [
      ...(headers["authentication-results"] || []),
      ...(headers["arc-authentication-results"] || [])
    ];
    
    // 結合したヘッダ群から特定の認証タイプ(spf, dkim, dmarc)のステータス(pass, fail等)を抽出するヘルパー
    const parseAuthStatus = (type) => {
      const regex = new RegExp(`${type}\\s*=\\s*([a-zA-Z0-9]+)`, "i");
      for (const h of authHeaders) {
        const match = h.match(regex);
        if (match) return match[1].toLowerCase();
      }
      return "none";
    };

    // 結合したヘッダ群から特定の認証タイプに関連する詳細情報(ドメイン等)を抽出するヘルパー
    const extractDetail = (type) => {
      for (const h of authHeaders) {
        if (type === 'spf') {
           const match = h.match(/smtp\.mailfrom=([^;\s]+)/i);
           if (match) return `domain: ${match[1]}`;
        }
        if (type === 'dkim') {
          const match = h.match(/header\.d=([^;\s]+)/i);
          if (match) return `domain: ${match[1]}`;
        }
        if (type === 'dmarc') {
          const match = h.match(/header\.from=([^;\s]+)/i);
          if (match) return `domain: ${match[1]}`;
        }
      }
      return "";
    };

    // 各認証プロトコルの判定結果をオブジェクト化
    const authResults = {
      spf: { status: parseAuthStatus("spf"), detail: extractDetail("spf") },
      dkim: { status: parseAuthStatus("dkim"), detail: extractDetail("dkim") },
      dmarc: { status: parseAuthStatus("dmarc"), detail: extractDetail("dmarc") }
    };

    // 総合的なセキュリティ判定用フラグ
    const isSpfOk = authResults.spf.status === "pass";
    const isDkimOk = authResults.dkim.status === "pass";
    // DMARCはポリシー未設定(none)の場合も許容する運用が一般的なため条件に含める
    const isDmarcOk = authResults.dmarc.status === "pass" || authResults.dmarc.status === "none";
    
    // SPFとDKIMが共にpassである場合を「安全」とみなす
    const isSecure = isSpfOk && isDkimOk; 

    // ---------------------------------------------------------
    // 2. UI構築 (HTML/CSS)
    // ---------------------------------------------------------

    // スタイル定義 (FlexboxとCSS Gridを併用し、モダンなレイアウトを構成)
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
      .maiv-header { display: flex; align-items: center; margin-bottom: 10px; }
      .maiv-badge { font-weight: bold; padding: 4px 8px; border-radius: 4px; margin-right: 10px; color: white; }
      .maiv-badge.secure { background-color: #2e7d32; }
      .maiv-badge.warning { background-color: #ed6c02; }
      .maiv-badge.danger { background-color: #d32f2f; }
      
      .maiv-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; }
      .maiv-card { background: white; border: 1px solid #e0e0e0; border-radius: 4px; padding: 8px; }
      .maiv-card-title { font-weight: bold; color: #555; margin-bottom: 4px; font-size: 11px; text-transform: uppercase; }
      .maiv-status-row { display: flex; align-items: center; gap: 6px; }
      .maiv-status-icon { font-size: 14px; }
      
      .maiv-route-list { margin-top: 10px; background: white; border: 1px solid #e0e0e0; border-radius: 4px; padding: 8px; font-family: monospace; font-size: 11px; overflow-x: auto; }
      .maiv-route-table { width: 100%; border-collapse: collapse; }
      .maiv-route-table td { padding: 4px; border-bottom: 1px solid #eee; vertical-align: middle; }
      
      /* 認証ステータスごとのテキストカラー設定 */
      .status-pass { color: #2e7d32; font-weight: bold; }
      .status-fail { color: #d32f2f; font-weight: bold; }
      .status-none { color: #757575; }
    `;
    document.head.appendChild(style);

    // アドオンのUIを格納するルートコンテナの作成
    const container = document.createElement("div");
    container.className = "maiv-container";

    // ■ ヘッダーエリア（総合判定バッジとリンクの生成）
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
        <a href="https://github.com/shotacure/MailAuthInfoViewer" target="_blank"><small style="color:#666;">Auth Info Viewer</small></a>
      </div>
    `;

    // ■ 各認証プロトコル用カードコンポーネント生成ヘルパー
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

    // ■ エンベロープ情報表示用カードコンポーネント生成
    const envelopeHTML = `
      <div class="maiv-card">
        <div class="maiv-card-title">ENVELOPE</div>
        <div style="font-size:11px;">
          <div><b style="color:#555">From:</b> ${envelopeFrom}</div>
          <div style="margin-top:2px;"><b style="color:#555">To:</b> ${envelopeTo}</div>
        </div>
      </div>
    `;

    // ■ 送達経路表示テーブルの構築 (ホップごとの遅延時間計算処理を含む)
    let routeRows = "";
    let prevDate = null;

    routeHops.forEach((hop, idx) => {
      const isFirst = idx === 0;
      
      // 遅延時間(秒単位)の計算および表示テキスト・カラーの決定
      let delayText = "--";
      let delayColor = "#ccc";
      
      if (hop.date && prevDate) {
        const diffMs = hop.date - prevDate;
        const diffSec = Math.floor(diffMs / 1000);
        
        if (diffSec < 60) {
            // 1分未満の遅延
            delayText = `+${diffSec}s`;
            delayColor = "#666";
        } else {
            // 1分以上の遅延は「分秒」形式に整形し、5分以上なら警告色(赤)を適用
            const min = Math.floor(diffSec / 60);
            const sec = diffSec % 60;
            delayText = `+${min}m${sec}s`;
            delayColor = diffSec > 300 ? "#d32f2f" : "#e65100";
        }
      } else if (isFirst) {
        // 時系列の起点(最初のホップ)の表示
        delayText = "ORIGIN"; 
        delayColor = "#000";
      }
      prevDate = hop.date; // 次の反復処理における差分計算のため現在日時を保持

      // ホスト名およびリレー先情報のフォーマット
      const hostLabel = hop.from || 'unknown';
      const byLabel = hop.by ? `(by ${hop.by})` : '';
      
      // 送信元(最初のホップ)の視認性を高めるためのスタイル定義
      const rowBg = isFirst ? 'background-color:#f0f8ff;' : '';
      const rowStyle = isFirst ? 'font-weight:bold; color:#000; background-color:#f0f8ff;' : 'color:#555;';

      // タイムスタンプの整形 (yyyy-MM-dd HH:mm:ss 形式)
      let timeStr = "--:--:--";
      if (hop.date) {
        const pad = (n) => n.toString().padStart(2, '0');
        timeStr = `${hop.date.getFullYear()}-${pad(hop.date.getMonth() + 1)}-${pad(hop.date.getDate())} ${pad(hop.date.getHours())}:${pad(hop.date.getMinutes())}:${pad(hop.date.getSeconds())}`;
      }

      // テーブル行のHTMLを構築
      routeRows += `
        <tr style="${isFirst ? 'border-left: 3px solid #2196f3;' : ''} ${rowBg}">
          <td style="width:60px; text-align:right; color:${delayColor}; font-weight:bold; font-size:0.9em;">${delayText}</td>
          <td style="${rowStyle}">
             <div>${hostLabel} ${isFirst ? '🚀' : ''}</div>
             <div style="color:#999; font-size:0.9em; font-weight:normal;">${byLabel}</div>
          </td>
          <td style="text-align:right; color:#999; white-space:nowrap;">${timeStr}</td>
        </tr>
      `;
    });

    const routeHTML = `
      <div class="maiv-route-list">
        <div class="maiv-card-title">DELIVERY ROUTE (Sender &rarr; Recipient)</div>
        <table class="maiv-route-table">
          ${routeRows}
        </table>
      </div>
    `;

    // 最終的なUIコンポーネント群をコンテナに組み込み
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

    // 既存の要素(以前の表示内容)が存在する場合は削除し、新たにコンテナをDOMへ挿入
    const existing = document.querySelector(".maiv-container");
    if (existing) existing.remove();
    document.body.insertAdjacentElement("afterbegin", container);

  } catch (e) {
    console.error("MailAuthInfoViewer Error:", e);
  }
})();