// messagedisplay.js

(async () => {
  try {
    // HTMLエスケープ用ヘルパー関数 (XSS対策: ATN審査必須要件)
    const escapeHTML = (str) => {
      if (!str) return "";
      return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    };

    // バックグラウンドスクリプトへメッセージ詳細情報の取得をリクエスト
    const resp = await browser.runtime.sendMessage({ command: "getMessageDetails" });
    if (resp.error || !resp.fullMessage) return;

    const fullMsg = resp.fullMessage;
    const msgHeader = resp.messageHeader || {}; // 文字化け対策: Thunderbirdパース済みのヘッダー情報
    const headers = fullMsg.headers || {};

    // ---------------------------------------------------------
    // 1. データ解析ロジック
    // ---------------------------------------------------------

    // ■ エンベロープ情報の抽出
    // envelope.from、return-path、またはauthorを評価し、送信元アドレスを特定
    const envelopeFromRaw =
      fullMsg.envelope?.from ||
      headers["return-path"]?.[0]?.replace(/^<|>$/g, "") ||
      fullMsg.author ||
      "Unknown";
    // 後のドメイン比較とUI表示のため、余分な括弧や空白を完全に除去
    const envelopeFrom = envelopeFromRaw.replace(/^<|>$/g, "").trim();
      
    // delivered-to、envelope.to、またはrecipientsを評価し、宛先アドレスを特定
    const envelopeToRaw =
      (headers["delivered-to"] || []).join(", ") ||
      fullMsg.envelope?.to?.join(", ") ||
      (fullMsg.recipients || []).join(", ") ||
      "Unknown";
    const envelopeTo = envelopeToRaw.replace(/^<|>$/g, "").trim();

    // ■ ヘッダFrom（表示名とアドレス）の抽出とドメインアライメントの検証
    // ヘッダFrom(ユーザーに見えるアドレス)を取得し、エンベロープ(実際の送信元)と比較する
    // ※ rawヘッダのままだと文字化け(MIMEエンコードや生UTF-8)が発生するため、Thunderbirdがデコード済みの author 情報を優先する
    const headerFromRaw = msgHeader.author || headers["from"]?.[0] || "Unknown";
    let headerFromName = "";
    let headerFromAddress = "";
    // "Display Name <user@domain.com>" の形式をパース
    const fromMatch = headerFromRaw.match(/(.*?)<([^>]+)>/);
    if (fromMatch) {
      headerFromName = fromMatch[1].replace(/"/g, '').trim();
      headerFromAddress = fromMatch[2].trim();
    } else {
      // < > で囲まれていない場合でも、念のため端の括弧を除去
      headerFromAddress = headerFromRaw.replace(/^<|>$/g, "").trim();
    }

    // 比較用にドメイン部分を抽出して小文字化
    const headerFromDomain = headerFromAddress.includes('@') ? headerFromAddress.split('@')[1].toLowerCase() : headerFromAddress.toLowerCase();
    const envelopeFromDomain = envelopeFrom.includes('@') ? envelopeFrom.split('@')[1].toLowerCase() : envelopeFrom.toLowerCase();

    // ドメインのアライメント（一致）判定: 詐欺メールの多くはここで不一致になる
    // DMARCの「Relaxed」アライメントに準拠させるため、
    // エンベロープがヘッダのサブドメインの場合、およびその逆の場合も「一致」とみなす
    const isDomainAligned = (headerFromDomain === envelopeFromDomain) || 
                            (envelopeFromDomain.endsWith("." + headerFromDomain)) ||
                            (headerFromDomain.endsWith("." + envelopeFromDomain));

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
      if (type === 'spf') {
        let domain = "";
        let ip = "";
        
        for (const h of authHeaders) {
          // 1. ドメインの抽出 (smtp.mailfrom= または コメント内の domain of から取得)
          const mailfromMatch = h.match(/smtp\.mailfrom=([^;\s()]+)/i);
          if (mailfromMatch) {
            // < > が付いている場合の除去
            const fromStr = mailfromMatch[1].replace(/^<|>$/g, '');
            // メールアドレス形式の場合は @ 以降のドメイン部分のみ抽出
            domain = fromStr.includes('@') ? fromStr.split('@')[1] : fromStr;
          } else {
             // フォールバック: (domain of xxx@example.com ...) などのコメントから取得
             const domainOfMatch = h.match(/domain of ([^;\s()]+)/i);
             if (domainOfMatch) {
               const fromStr = domainOfMatch[1];
               domain = fromStr.includes('@') ? fromStr.split('@')[1] : fromStr;
             }
          }

          // 2. IPアドレスの抽出 (Google形式: designates [IP] as... または 標準的な client-ip= から取得)
          const ipMatch = h.match(/designates\s+([a-fA-F0-9.:]+)\s+as\s+permitted\s+sender/i) || 
                          h.match(/client-ip=([a-fA-F0-9.:]+)/i);
          if (ipMatch) {
            ip = ipMatch[1];
          }

          // どちらか一方でも見つかれば結果を返す (<br>タグで改行してHTML出力)
          if (domain || ip) {
            const parts = [];
            if (domain) parts.push(`domain: ${escapeHTML(domain)}`);
            if (ip) parts.push(`IP address: ${escapeHTML(ip)}`);
            return parts.join("<br>");
          }
        }
        return "";
      }

      if (type === 'dkim') {
        const domains = new Set(); // 重複排除用にSetを使用
        
        for (const h of authHeaders) {
          // header.d= と header.i= の両方をすべて抽出
          const regex = /header\.(?:d|i)=([^;\s()]+)/ig;
          let match;
          
          while ((match = regex.exec(h)) !== null) {
            let dkimDomain = match[1];
            
            // header.i=@example.com や user@example.com の場合は @ 以降を取得
            if (dkimDomain.includes('@')) {
              dkimDomain = dkimDomain.split('@')[1];
            }
            if (dkimDomain) {
               domains.add(dkimDomain);
            }
          }
        }
        
        // 複数ある場合は " / " で結合して出力
        if (domains.size > 0) {
          return `domain: ${escapeHTML(Array.from(domains).join(" / "))}`;
        }
        return "";
      }

      if (type === 'dmarc') {
        for (const h of authHeaders) {
          const match = h.match(/header\.from=([^;\s()]+)/i);
          if (match) return `domain: ${escapeHTML(match[1])}`;
        }
        return "";
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
    
    // SPFとDKIMが共にpassであり、かつドメインアライメントが一致している場合を「安全」とみなす
    const isSecure = isSpfOk && isDkimOk && isDomainAligned; 

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
        padding: 10px 12px;
        margin-bottom: 15px;
        color: #333;
        font-size: 13px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
      }
      
      /* アコーディオン(開閉)用のヘッダースタイル */
      .maiv-header { 
        display: flex; align-items: center; 
        cursor: pointer; user-select: none;
        padding: 4px 0; transition: opacity 0.2s;
      }
      .maiv-header:hover { opacity: 0.8; }
      
      .maiv-badge { font-weight: bold; padding: 6px 10px; border-radius: 4px; margin-right: 8px; color: white; font-size: 14px; letter-spacing: 0.5px;}
      .maiv-badge.secure { background-color: #2e7d32; }
      .maiv-badge.warning { background-color: #ed6c02; }
      .maiv-badge.danger { background-color: #d32f2f; }
      
      /* バッジの右側に表示する大きなドメインテキスト用のスタイル */
      .maiv-header-domain { font-size: 17px; font-weight: bold; color: #222; }
      .maiv-header-mismatch { font-size: 13px; color: #e65100; font-weight: bold; margin-left: 6px; }

      /* 開閉トグルアイコン */
      .maiv-toggle-icon { margin-left: 15px; margin-right: 15px; color: #999; font-size: 12px; transition: transform 0.35s cubic-bezier(0.4, 0, 0.2, 1); }
      .maiv-toggle-icon.expanded { transform: rotate(180deg); }
      .maiv-link { color: #666; text-decoration: none; }
      .maiv-link:hover { text-decoration: underline; color: #2196f3; }

      /* 開閉アニメーション(スライドダウン)用のラッパー */
      .maiv-body-wrapper {
        display: grid;
        grid-template-rows: 0fr;
        transition: grid-template-rows 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      }
      .maiv-body-wrapper.expanded {
        grid-template-rows: 1fr;
      }
      .maiv-body-inner {
        overflow: hidden;
      }
      /* コンテンツの実態。開いたときの余白を設定 */
      .maiv-body-content {
        padding-top: 12px;
      }

      /* minmaxを150pxに下げて、横一列に並びやすく調整 */
      .maiv-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 10px; }
      .maiv-card { background: white; border: 1px solid #e0e0e0; border-radius: 4px; padding: 8px; }
      .maiv-card-title { font-weight: bold; color: #555; margin-bottom: 6px; font-size: 11px; text-transform: uppercase; border-bottom: 1px solid #eee; padding-bottom: 4px;}
      .maiv-status-row { display: flex; align-items: center; gap: 6px; }
      .maiv-status-icon { font-size: 14px; }
      
      .maiv-route-list { background: white; border: 1px solid #e0e0e0; border-radius: 4px; padding: 8px; font-family: monospace; font-size: 11px; overflow-x: auto; }
      .maiv-route-table { width: 100%; border-collapse: collapse; }
      .maiv-route-table td { padding: 4px; border-bottom: 1px solid #eee; vertical-align: middle; }
      
      /* 認証ステータスごとのテキストカラー設定 */
      .status-pass { color: #2e7d32; font-weight: bold; }
      .status-fail { color: #d32f2f; font-weight: bold; }
      .status-none { color: #757575; }

      /* ドメインアライメント判定用スタイル */
      .align-ok { color: #2e7d32; font-weight: bold; font-size: 11px; margin-top: 6px;}
      .align-ng { background-color: #ffebee; color: #c62828; font-weight: bold; padding: 6px; border-radius: 4px; font-size: 12px; margin-top: 6px; display: block;}
      .align-warn { background-color: #fff3e0; color: #e65100; font-weight: bold; padding: 6px; border-radius: 4px; font-size: 12px; margin-top: 6px; display: block;}
      
      /* アドレス表示用スタイル */
      .address-row { margin-bottom: 6px; display: flex; align-items: center; }
      .address-label { color: #666; width: 110px; display: inline-block; font-size: 11px; text-transform: uppercase; flex-shrink: 0; }
      /* Display Name, Header From, Envelope From を一貫して強調表示するクラス */
      .address-highlight { 
        font-size: 13px; 
        font-weight: bold; 
        color: #111; 
        background-color: #f1f3f4; 
        padding: 4px 8px; 
        border-radius: 3px;
        border: 1px solid #ccc;
        word-break: break-all;
      }
    `;
    document.head.appendChild(style);

    // アドオンのUIを格納するルートコンテナの作成
    const container = document.createElement("div");
    container.className = "maiv-container";

    // ■ ヘッダーエリア（総合判定バッジとドメイン名表示の生成）
    let badgeClass = "warning";
    let badgeText = "UNVERIFIED";
    let headerDomainText = "";
    
    if (isSecure) {
      // 予断を排除するため、ただのAUTHENTICATEDではなく「どのドメインが認証されたか」を明記する
      badgeClass = "secure";
      badgeText = `✅ AUTH PASS`;
      // バッジの横に大きな文字でドメインを表示
      headerDomainText = escapeHTML(headerFromDomain);
    } else if (authResults.spf.status === "fail" || authResults.dkim.status === "fail" || authResults.dmarc.status === "fail") {
      badgeClass = "danger";
      badgeText = "❌ AUTH FAILED";
      // 認証失敗時はドメインを強調表示しない
      headerDomainText = "";
    } else if ((isSpfOk || isDkimOk) && !isDomainAligned && envelopeFrom !== "Unknown") {
      // 認証は通っているがドメインが不一致の場合（配信サービスやメルマガ等）は、赤色(danger)ではなくオレンジ(warning)にする
      badgeClass = "warning";
      badgeText = `⚠️ AUTH PASS`;
      // ドメイン名の横にオレンジ色でMISMATCHの警告を追加
      headerDomainText = `${escapeHTML(headerFromDomain)} <span class="maiv-header-mismatch">(DOMAIN MISMATCH)</span>`;
    }

    // 「安全(secure)」でない場合は、自動で展開(展開用のアニメーションをトリガー)するフラグ
    const shouldAutoExpand = (badgeClass !== "secure");

    const headerHTML = `
      <div class="maiv-header" id="maiv-header-toggle" title="Click to toggle details">
        <span class="maiv-badge ${badgeClass}">${badgeText}</span>
        <span class="maiv-header-domain">${headerDomainText}</span>
        <span style="flex-grow:1;"></span>
        <span class="maiv-toggle-icon" id="maiv-toggle-icon">▼</span>
        <a href="https://github.com/shotacure/MailAuthInfoViewer" class="maiv-link" target="_blank"><small>Mail Auth Info Viewer</small></a>
      </div>
    `;

    // ■ 各認証プロトコル用カードコンポーネント生成ヘルパー
    const createAuthCard = (title, data) => {
      let icon = "❓";
      let sClass = "status-none";
      let displayStatus = data.status.toUpperCase();
      
      if (data.status === "pass") { icon = "✅"; sClass = "status-pass"; }
      else if (data.status === "fail") { icon = "❌"; sClass = "status-fail"; }
      else if (data.status === "softfail" || data.status === "none") { icon = "⚠️"; sClass = "status-none"; }

      return `
        <div class="maiv-card">
          <div class="maiv-card-title">${escapeHTML(title)}</div>
          <div class="maiv-status-row">
            <span class="maiv-status-icon">${icon}</span>
            <span class="${sClass}">${escapeHTML(displayStatus)}</span>
          </div>
          <div style="font-size:11px; color:#666; margin-top:4px;">${data.detail}</div>
        </div>
      `;
    };

    // ■ アドレス＆アライメント表示用カードコンポーネント生成 (エンベロープとヘッダの比較)
    
    // 予断を与えないための厳密なアライメント警告ロジック（UIテキストは英語で統一）
    let alignmentWarningHTML = "";
    
    if (!isDomainAligned && envelopeFrom !== "Unknown") {
      if (isSpfOk || isDkimOk) {
        // 認証は通っているが不一致（正当な配信サービスの可能性あり）-> オレンジ色の警告
        alignmentWarningHTML = `<div class="align-warn">⚠️ Domain mismatch between Header From and Envelope</div>`;
      } else {
        // 認証も通っておらず不一致 -> 赤色の警告
        alignmentWarningHTML = `<div class="align-ng">⚠️ Domain mismatch between Header From and Envelope</div>`;
      }
    } else if (isDomainAligned && isSecure) {
      alignmentWarningHTML = `<div class="align-ok">✅ Domain aligned (Authenticated)</div>`;
    } else if (isDomainAligned && !isSecure) {
      // ドメインは一致しているが認証NGの場合は予断を与えない警告表示
      alignmentWarningHTML = `<div class="align-warn">⚠️ Domain aligned, but sender is not authenticated</div>`;
    }

    // 表示名(名乗り)の偽装対策: ユーザーが違和感に気づけるように、アドレス項目すべてに一貫した強調スタイルを適用
    const displayNameHTML = headerFromName ? `<span class="address-highlight">${escapeHTML(headerFromName)}</span>` : `<span style="color:#999; font-weight:normal;">(None)</span>`;
    
    // ADDRESSカードは2枠分(span 2)の幅を取り、中の表示は縦に並べる
    const addressHTML = `
      <div class="maiv-card" style="grid-column: span 2; border-left: 4px solid #2196f3;">
        <div class="maiv-card-title">ADDRESS & ALIGNMENT (SENDER IDENTITY)</div>
        <div style="font-size:11px; margin-top: 8px;">
          
          <div class="address-row">
            <span class="address-label">Display Name:</span> 
            ${displayNameHTML}
          </div>

          <div class="address-row">
            <span class="address-label">Header From:</span> 
            <span class="address-highlight">${escapeHTML(headerFromAddress)}</span>
          </div>
          
          <div class="address-row">
            <span class="address-label">Envelope From:</span> 
            <span class="address-highlight">${escapeHTML(envelopeFrom)}</span>
          </div>

          ${alignmentWarningHTML}
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
             <div>${escapeHTML(hostLabel)} ${isFirst ? '🚀' : ''}</div>
             <div style="color:#999; font-size:0.9em; font-weight:normal;">${escapeHTML(byLabel)}</div>
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
    // アニメーション用に、詳細部分をマウント時は一旦閉じた状態（クラスなし）のラッパーで囲む
    const markup = `
      ${headerHTML}
      <div class="maiv-body-wrapper" id="maiv-body-wrapper">
        <div class="maiv-body-inner">
          <div class="maiv-body-content">
            <div class="maiv-grid">
              ${addressHTML}
              ${createAuthCard("SPF", authResults.spf)}
              ${createAuthCard("DKIM", authResults.dkim)}
              ${createAuthCard("DMARC", authResults.dmarc)}
            </div>
            ${routeHTML}
          </div>
        </div>
      </div>
    `;

    // DOMParserでパースして挿入
    const doc = new DOMParser().parseFromString(markup, "text/html");
    container.replaceChildren(...doc.body.childNodes);

    // 既存の要素(以前の表示内容)が存在する場合は削除し、新たにコンテナをDOMへ挿入
    const existing = document.querySelector(".maiv-container");
    if (existing) existing.remove();
    document.body.insertAdjacentElement("afterbegin", container);

    // --- インタラクション (アコーディオンの開閉) の設定 ---
    const headerToggle = container.querySelector('#maiv-header-toggle');
    const bodyWrapper = container.querySelector('#maiv-body-wrapper');
    const toggleIcon = container.querySelector('#maiv-toggle-icon');

    // クリックによる手動開閉
    headerToggle.addEventListener('click', (e) => {
      // リンク部分(Mail Auth Info Viewer)をクリックした時は開閉しないようにする
      if (e.target.closest('.maiv-link')) return;
      bodyWrapper.classList.toggle('expanded');
      toggleIcon.classList.toggle('expanded');
    });

    // 「安全」以外の場合は、描画完了の直後にクラスを付与して「スルッと開く」アニメーションを発火させる
    if (shouldAutoExpand) {
      setTimeout(() => {
        bodyWrapper.classList.add('expanded');
        toggleIcon.classList.add('expanded');
      }, 50); // DOMレンダリング直後にトリガーするためのわずかな遅延
    }

  } catch (e) {
    console.error("MailAuthInfoViewer Error:", e);
  }
})();