// messagedisplay.js

(async () => {
  try {
    // =========================================================
    // ヘルパー関数
    // =========================================================

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

    // 日時文字列パース用ヘルパー関数
    // Receivedヘッダの末尾（セミコロン以降）に記録されている日時文字列を抽出・Date化
    const parseReceivedDate = (str) => {
      const match = str.match(/;\s*([^;]+)$/);
      return match ? new Date(match[1]) : null;
    };

    // タイムスタンプの整形 (yyyy-MM-dd HH:mm:ss 形式)
    const formatTimestamp = (date) => {
      if (!date) return "--:--:--";
      const pad = (n) => n.toString().padStart(2, '0');
      return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
    };

    // =========================================================
    // 1. parseEnvelope - エンベロープ情報とアドレスアライメントの解析
    // =========================================================
    const parseEnvelope = (fullMsg, headers, msgHeader) => {
      // ■ エンベロープ情報の抽出
      // envelope.from、return-path、またはauthorを評価し、送信元アドレスを特定
      const envelopeFromRaw =
        fullMsg.envelope?.from ||
        headers["return-path"]?.[0]?.replace(/^<|>$/g, "") ||
        fullMsg.author ||
        "Unknown";
      const envelopeFrom = envelopeFromRaw.replace(/^<|>$/g, "").trim();

      // delivered-to、envelope.to、またはrecipientsを評価し、宛先アドレスを特定
      const envelopeToRaw =
        (headers["delivered-to"] || []).join(", ") ||
        fullMsg.envelope?.to?.join(", ") ||
        (fullMsg.recipients || []).join(", ") ||
        "Unknown";
      const envelopeTo = envelopeToRaw.replace(/^<|>$/g, "").trim();

      // ■ ヘッダFrom（表示名とアドレス）の抽出
      // ※ rawヘッダのままだと文字化け(MIMEエンコードや生UTF-8)が発生するため、
      //   Thunderbirdがデコード済みの author 情報を優先する
      const headerFromRaw = msgHeader.author || headers["from"]?.[0] || "Unknown";
      let headerFromName = "";
      let headerFromAddress = "";

      // "Display Name <user@domain.com>" の形式をパース
      const fromMatch = headerFromRaw.match(/(.*?)<([^>]+)>/);
      if (fromMatch) {
        headerFromName = fromMatch[1].replace(/"/g, '').trim();
        headerFromAddress = fromMatch[2].trim();
      } else {
        headerFromAddress = headerFromRaw.replace(/^<|>$/g, "").trim();
      }

      // 比較用にドメイン部分を抽出して小文字化
      const headerFromDomain = headerFromAddress.includes('@')
        ? headerFromAddress.split('@')[1].toLowerCase()
        : headerFromAddress.toLowerCase();
      const envelopeFromDomain = envelopeFrom.includes('@')
        ? envelopeFrom.split('@')[1].toLowerCase()
        : envelopeFrom.toLowerCase();

      // ■ ドメインのアライメント（一致）判定
      // DMARCの「Relaxed」アライメントに準拠: サブドメインも「一致」とみなす
      //
      // [制限事項] Public Suffix (co.jp, com.au 等) は考慮していません。
      // 例えば evil.co.jp と legit.co.jp は理論上サブドメイン判定で一致する可能性があります。
      // 完全な対応には Public Suffix List の組み込みが必要ですが、
      // ローカル処理・軽量維持のためここでは簡易判定としています。
      const isDomainAligned =
        (headerFromDomain === envelopeFromDomain) ||
        (envelopeFromDomain.endsWith("." + headerFromDomain)) ||
        (headerFromDomain.endsWith("." + envelopeFromDomain));

      return {
        envelopeFrom,
        envelopeTo,
        headerFromName,
        headerFromAddress,
        headerFromDomain,
        envelopeFromDomain,
        isDomainAligned
      };
    };

    // =========================================================
    // 2. parseAuthResults - メール認証結果の解析
    // =========================================================
    const parseAuthResults = (headers) => {
      // Authentication-Results および ARC-Authentication-Results ヘッダを配列として結合し、
      // 複数行に跨る場合やARC側にしか結果が存在しない場合に対応
      const authHeaders = [
        ...(headers["authentication-results"] || []),
        ...(headers["arc-authentication-results"] || [])
      ];

      // セミコロンで区切ってメソッド単位に分割し、指定の認証タイプのステータスを抽出する。
      // 先頭のセグメント(authserv-id)はスキップすることで、
      // 攻撃者が注入した Authentication-Results との誤マッチリスクを軽減する。
      const parseAuthStatus = (type) => {
        const regex = new RegExp(`\\b${type}\\s*=\\s*([a-zA-Z0-9]+)`, "i");
        for (const h of authHeaders) {
          const methods = h.split(';').slice(1); // 先頭の authserv-id をスキップ
          for (const m of methods) {
            const match = m.match(regex);
            if (match) return match[1].toLowerCase();
          }
        }
        return "none";
      };

      // ■ 複数 DKIM 署名への対応
      // メールによっては複数の DKIM 署名があり、一部は pass・一部は fail のことがある。
      // 全結果を収集し、「1つでも pass なら pass」とする。
      const parseDkimResults = () => {
        const results = []; // { status, domains }[]
        const regex = /\bdkim\s*=\s*([a-zA-Z0-9]+)/ig;

        for (const h of authHeaders) {
          const methods = h.split(';').slice(1);
          for (const m of methods) {
            const match = m.match(regex);
            if (match) {
              // ステータスを抽出
              const statusMatch = m.match(/\bdkim\s*=\s*([a-zA-Z0-9]+)/i);
              if (statusMatch) {
                results.push({
                  status: statusMatch[1].toLowerCase(),
                  segment: m
                });
              }
            }
          }
        }

        // 集約: 1つでも pass なら pass
        if (results.length === 0) return "none";
        if (results.some(r => r.status === "pass")) return "pass";
        if (results.some(r => r.status === "fail")) return "fail";
        return results[0].status;
      };

      // 認証タイプに関連する詳細情報(ドメイン, IP等)を構造化データとして抽出する
      const extractDetail = (type) => {
        if (type === 'spf') {
          let domain = "";
          let ip = "";

          for (const h of authHeaders) {
            const methods = h.split(';').slice(1);
            for (const m of methods) {
              if (!/\bspf\s*=/i.test(m)) continue;

              // ドメイン: smtp.mailfrom= から取得
              const mailfromMatch = m.match(/smtp\.mailfrom=([^;\s()]+)/i);
              if (mailfromMatch) {
                const fromStr = mailfromMatch[1].replace(/^<|>$/g, '');
                domain = fromStr.includes('@') ? fromStr.split('@')[1] : fromStr;
              } else {
                // フォールバック: (domain of xxx@example.com ...) から取得
                const domainOfMatch = m.match(/domain of ([^;\s()]+)/i);
                if (domainOfMatch) {
                  const fromStr = domainOfMatch[1];
                  domain = fromStr.includes('@') ? fromStr.split('@')[1] : fromStr;
                }
              }

              // IP: designates ... as permitted sender、または client-ip= から取得
              const ipMatch = m.match(/designates\s+([a-fA-F0-9.:]+)\s+as\s+permitted\s+sender/i) ||
                              m.match(/client-ip=([a-fA-F0-9.:]+)/i);
              if (ipMatch) {
                ip = ipMatch[1];
              }

              if (domain || ip) return { domain, ip };
            }
          }
          return { domain, ip };
        }

        if (type === 'dkim') {
          const domains = new Set();

          for (const h of authHeaders) {
            const methods = h.split(';').slice(1);
            for (const m of methods) {
              if (!/\bdkim\s*=/i.test(m)) continue;

              // header.d= と header.i= を両方抽出
              const domainRegex = /header\.(?:d|i)=([^;\s()]+)/ig;
              let match;
              while ((match = domainRegex.exec(m)) !== null) {
                let dkimDomain = match[1];
                if (dkimDomain.includes('@')) {
                  dkimDomain = dkimDomain.split('@')[1];
                }
                if (dkimDomain) domains.add(dkimDomain);
              }
            }
          }

          return { domains: Array.from(domains) };
        }

        if (type === 'dmarc') {
          let domain = "";
          let policy = "";

          for (const h of authHeaders) {
            const methods = h.split(';').slice(1);
            for (const m of methods) {
              if (!/\bdmarc\s*=/i.test(m)) continue;

              const domainMatch = m.match(/header\.from=([^;\s()]+)/i);
              if (domainMatch) domain = domainMatch[1];

              // DMARC ポリシー (p=reject / p=quarantine / p=none) の抽出
              const policyMatch = m.match(/\bp=([a-zA-Z]+)/i);
              if (policyMatch) policy = policyMatch[1].toLowerCase();
            }
          }
          return { domain, policy };
        }

        return {};
      };

      const spfStatus = parseAuthStatus("spf");
      const dkimStatus = parseDkimResults();
      const dmarcStatus = parseAuthStatus("dmarc");

      return {
        spf: { status: spfStatus, detail: extractDetail("spf") },
        dkim: { status: dkimStatus, detail: extractDetail("dkim") },
        dmarc: { status: dmarcStatus, detail: extractDetail("dmarc") }
      };
    };

    // =========================================================
    // 3. parseRoute - 送達経路 (Receivedヘッダ) の解析
    // =========================================================
    const parseRoute = (headers) => {
      // Receivedヘッダは「新しい順(受信側→送信元)」で記録されるため、
      // reverse()を用いて「時系列順(送信元→受信側)」に並び替えて処理する
      const rawReceived = headers["received"] || [];

      return rawReceived.slice().reverse().map(line => {
        const fromMatch = line.match(/\bfrom\s+(.+?)(?=\s+by\s+|;|$)/i);
        const byMatch = line.match(/\bby\s+([^\s;]+)/i);
        const date = parseReceivedDate(line);

        return {
          from: fromMatch ? fromMatch[1].trim() : null,
          by: byMatch ? byMatch[1] : null,
          date: date,
          raw: line
        };
      }).filter(hop => hop.from || hop.by);
    };

    // =========================================================
    // 4. determineSecurityStatus - 総合的なセキュリティ判定
    // =========================================================
    const determineSecurityStatus = (authResults, isDomainAligned, envelopeFrom) => {
      const isSpfOk = authResults.spf.status === "pass";
      const isDkimOk = authResults.dkim.status === "pass";
      // DMARCはポリシー未設定(none)の場合も許容する運用が一般的なため条件に含める
      const isDmarcOk = authResults.dmarc.status === "pass" || authResults.dmarc.status === "none";

      // SPFとDKIMが共にpassであり、かつドメインアライメントが一致している場合を「安全」とみなす
      const isSecure = isSpfOk && isDkimOk && isDomainAligned;

      let badgeClass = "warning";
      let badgeText = "UNVERIFIED";
      let headerDomainHTML = "";

      if (isSecure) {
        badgeClass = "secure";
        badgeText = "✅ AUTH PASS";
      } else if (authResults.spf.status === "fail" || authResults.dkim.status === "fail" || authResults.dmarc.status === "fail") {
        badgeClass = "danger";
        badgeText = "❌ AUTH FAILED";
      } else if ((isSpfOk || isDkimOk) && !isDomainAligned && envelopeFrom !== "Unknown") {
        badgeClass = "warning";
        badgeText = "⚠️ AUTH PASS";
      }

      return {
        isSecure,
        isSpfOk,
        isDkimOk,
        isDmarcOk,
        badgeClass,
        badgeText,
        shouldAutoExpand: badgeClass !== "secure"
      };
    };

    // =========================================================
    // 5. buildUI - UI構築 (HTML/CSS)
    // =========================================================
    const buildUI = (envelope, authResults, routeHops, security) => {

      // --- スタイル定義 ---
      const style = document.createElement('style');
      style.textContent = `
        /* === ライトモード (デフォルト) === */
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

        .maiv-header {
          display: flex; align-items: center;
          cursor: pointer; user-select: none;
          padding: 4px 0; transition: opacity 0.2s;
        }
        .maiv-header:hover { opacity: 0.8; }

        .maiv-badge { font-weight: bold; padding: 6px 10px; border-radius: 4px; margin-right: 8px; color: white; font-size: 14px; letter-spacing: 0.5px; }
        .maiv-badge.secure { background-color: #2e7d32; }
        .maiv-badge.warning { background-color: #ed6c02; }
        .maiv-badge.danger { background-color: #d32f2f; }

        .maiv-header-domain { font-size: 17px; font-weight: bold; color: #222; }
        .maiv-header-mismatch { font-size: 13px; color: #e65100; font-weight: bold; margin-left: 6px; }

        .maiv-toggle-icon { margin-left: 15px; margin-right: 15px; color: #999; font-size: 12px; transition: transform 0.35s cubic-bezier(0.4, 0, 0.2, 1); }
        .maiv-toggle-icon.expanded { transform: rotate(180deg); }
        .maiv-link { color: #666; text-decoration: none; }
        .maiv-link:hover { text-decoration: underline; color: #2196f3; }

        .maiv-body-wrapper {
          display: grid;
          grid-template-rows: 0fr;
          transition: grid-template-rows 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .maiv-body-wrapper.expanded { grid-template-rows: 1fr; }
        .maiv-body-inner { overflow: hidden; }
        .maiv-body-content { padding-top: 12px; }

        .maiv-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 10px; }
        .maiv-card { background: white; border: 1px solid #e0e0e0; border-radius: 4px; padding: 8px; }
        .maiv-card-title { font-weight: bold; color: #555; margin-bottom: 6px; font-size: 11px; text-transform: uppercase; border-bottom: 1px solid #eee; padding-bottom: 4px; }
        .maiv-status-row { display: flex; align-items: center; gap: 6px; }
        .maiv-status-icon { font-size: 14px; }

        .maiv-route-list { background: white; border: 1px solid #e0e0e0; border-radius: 4px; padding: 8px; font-family: monospace; font-size: 11px; overflow-x: auto; }
        .maiv-route-table { width: 100%; border-collapse: collapse; }
        .maiv-route-table td { padding: 4px; border-bottom: 1px solid #eee; vertical-align: middle; }

        .status-pass { color: #2e7d32; font-weight: bold; }
        .status-fail { color: #d32f2f; font-weight: bold; }
        .status-none { color: #757575; }

        .align-ok { color: #2e7d32; font-weight: bold; font-size: 11px; margin-top: 6px; }
        .align-ng { background-color: #ffebee; color: #c62828; font-weight: bold; padding: 6px; border-radius: 4px; font-size: 12px; margin-top: 6px; display: block; }
        .align-warn { background-color: #fff3e0; color: #e65100; font-weight: bold; padding: 6px; border-radius: 4px; font-size: 12px; margin-top: 6px; display: block; }

        .address-row { margin-bottom: 6px; display: flex; align-items: center; }
        .address-label { color: #666; width: 110px; display: inline-block; font-size: 11px; text-transform: uppercase; flex-shrink: 0; }
        .address-highlight {
          font-size: 13px; font-weight: bold; color: #111;
          background-color: #f1f3f4; padding: 4px 8px; border-radius: 3px;
          border: 1px solid #ccc; word-break: break-all;
        }

        .maiv-detail-text { font-size: 11px; color: #666; margin-top: 4px; }
        .maiv-policy-tag {
          display: inline-block; font-size: 10px; font-weight: bold;
          padding: 2px 6px; border-radius: 3px; margin-top: 4px;
        }
        .maiv-policy-reject { background-color: #ffebee; color: #c62828; }
        .maiv-policy-quarantine { background-color: #fff3e0; color: #e65100; }
        .maiv-policy-none { background-color: #f5f5f5; color: #757575; }

        /* === ダークモード === */
        @media (prefers-color-scheme: dark) {
          .maiv-container {
            background-color: #2b2b2b;
            border-bottom-color: #555;
            color: #e0e0e0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
          }
          .maiv-header-domain { color: #e0e0e0; }
          .maiv-header-mismatch { color: #ffb74d; }
          .maiv-toggle-icon { color: #aaa; }
          .maiv-link { color: #aaa; }
          .maiv-link:hover { color: #64b5f6; }

          .maiv-card { background: #3a3a3a; border-color: #555; }
          .maiv-card-title { color: #bbb; border-bottom-color: #555; }

          .maiv-route-list { background: #3a3a3a; border-color: #555; }
          .maiv-route-table td { border-bottom-color: #555; }

          .status-pass { color: #66bb6a; }
          .status-fail { color: #ef5350; }
          .status-none { color: #aaa; }

          .align-ok { color: #66bb6a; }
          .align-ng { background-color: #4a1c1c; color: #ef9a9a; }
          .align-warn { background-color: #4a3000; color: #ffcc80; }

          .address-label { color: #aaa; }
          .address-highlight {
            color: #e0e0e0; background-color: #444;
            border-color: #666;
          }

          .maiv-detail-text { color: #aaa; }
          .maiv-policy-reject { background-color: #4a1c1c; color: #ef9a9a; }
          .maiv-policy-quarantine { background-color: #4a3000; color: #ffcc80; }
          .maiv-policy-none { background-color: #444; color: #aaa; }
        }
      `;
      document.head.appendChild(style);

      // --- コンテナ作成 ---
      const container = document.createElement("div");
      container.className = "maiv-container";

      // --- ヘッダーバッジとドメイン表示 ---
      let headerDomainText = "";
      if (security.isSecure) {
        headerDomainText = escapeHTML(envelope.headerFromDomain);
      } else if (security.badgeClass === "warning" && envelope.envelopeFrom !== "Unknown") {
        headerDomainText = `${escapeHTML(envelope.envelopeFromDomain)} <span class="maiv-header-mismatch">(DOMAIN MISMATCH)</span>`;
      }

      const headerHTML = `
        <div class="maiv-header" id="maiv-header-toggle" title="Click to toggle details">
          <span class="maiv-badge ${security.badgeClass}">${security.badgeText}</span>
          <span class="maiv-header-domain">${headerDomainText}</span>
          <span style="flex-grow:1;"></span>
          <span class="maiv-toggle-icon" id="maiv-toggle-icon">▼</span>
          <a href="https://github.com/shotacure/MailAuthInfoViewer" class="maiv-link" target="_blank"><small>Mail Auth Info Viewer</small></a>
        </div>
      `;

      // --- 認証カード生成ヘルパー ---
      const createAuthCard = (title, tooltip, data, detailHTML) => {
        let icon = "❓";
        let sClass = "status-none";
        const displayStatus = data.status.toUpperCase();

        if (data.status === "pass") { icon = "✅"; sClass = "status-pass"; }
        else if (data.status === "fail") { icon = "❌"; sClass = "status-fail"; }
        else if (data.status === "softfail" || data.status === "none") { icon = "⚠️"; sClass = "status-none"; }

        return `
          <div class="maiv-card">
            <div class="maiv-card-title" title="${escapeHTML(tooltip)}">${escapeHTML(title)}</div>
            <div class="maiv-status-row">
              <span class="maiv-status-icon">${icon}</span>
              <span class="${sClass}">${escapeHTML(displayStatus)}</span>
            </div>
            <div class="maiv-detail-text">${detailHTML}</div>
          </div>
        `;
      };

      // --- 構造化データからHTML詳細を生成 ---
      const spfDetailHTML = (() => {
        const d = authResults.spf.detail;
        const parts = [];
        if (d.domain) parts.push(`domain: ${escapeHTML(d.domain)}`);
        if (d.ip) parts.push(`IP address: ${escapeHTML(d.ip)}`);
        return parts.join("<br>");
      })();

      const dkimDetailHTML = (() => {
        const d = authResults.dkim.detail;
        if (d.domains && d.domains.length > 0) {
          return `domain: ${escapeHTML(d.domains.join(" / "))}`;
        }
        return "";
      })();

      const dmarcDetailHTML = (() => {
        const d = authResults.dmarc.detail;
        const parts = [];
        if (d.domain) parts.push(`domain: ${escapeHTML(d.domain)}`);
        // DMARC ポリシー表示 (p=reject / p=quarantine / p=none)
        if (d.policy) {
          let policyClass = "maiv-policy-none";
          if (d.policy === "reject") policyClass = "maiv-policy-reject";
          else if (d.policy === "quarantine") policyClass = "maiv-policy-quarantine";
          parts.push(`<span class="maiv-policy-tag ${policyClass}">policy: ${escapeHTML(d.policy)}</span>`);
        }
        return parts.join("<br>");
      })();

      // 認証カード (ツールチップ付き)
      const spfCard = createAuthCard(
        "SPF",
        "Sender Policy Framework: Checks if the sending server is authorized by the domain's DNS records.",
        authResults.spf,
        spfDetailHTML
      );
      const dkimCard = createAuthCard(
        "DKIM",
        "DomainKeys Identified Mail: Verifies the email's digital signature to ensure it wasn't altered in transit.",
        authResults.dkim,
        dkimDetailHTML
      );
      const dmarcCard = createAuthCard(
        "DMARC",
        "Domain-based Message Authentication, Reporting & Conformance: Ensures SPF/DKIM align with the From domain and defines the sender's policy.",
        authResults.dmarc,
        dmarcDetailHTML
      );

      // --- アドレス＆アライメント表示 ---
      let alignmentWarningHTML = "";

      if (!envelope.isDomainAligned && envelope.envelopeFrom !== "Unknown") {
        if (security.isSpfOk || security.isDkimOk) {
          alignmentWarningHTML = `<div class="align-warn">⚠️ Domain mismatch between Header From and Envelope</div>`;
        } else {
          alignmentWarningHTML = `<div class="align-ng">⚠️ Domain mismatch between Header From and Envelope</div>`;
        }
      } else if (envelope.isDomainAligned && security.isSecure) {
        alignmentWarningHTML = `<div class="align-ok">✅ Domain aligned (Authenticated)</div>`;
      } else if (envelope.isDomainAligned && !security.isSecure) {
        alignmentWarningHTML = `<div class="align-warn">⚠️ Domain aligned, but sender is not authenticated</div>`;
      }

      const displayNameHTML = envelope.headerFromName
        ? `<span class="address-highlight">${escapeHTML(envelope.headerFromName)}</span>`
        : `<span style="color:#999; font-weight:normal;">(None)</span>`;

      const addressHTML = `
        <div class="maiv-card" style="grid-column: span 2; border-left: 4px solid #2196f3;">
          <div class="maiv-card-title" title="Compares the visible sender address with the actual envelope sender to detect spoofing.">ADDRESS & ALIGNMENT (SENDER IDENTITY)</div>
          <div style="font-size:11px; margin-top: 8px;">
            <div class="address-row">
              <span class="address-label">Display Name:</span>
              ${displayNameHTML}
            </div>
            <div class="address-row">
              <span class="address-label">Header From:</span>
              <span class="address-highlight">${escapeHTML(envelope.headerFromAddress)}</span>
            </div>
            <div class="address-row">
              <span class="address-label">Envelope From:</span>
              <span class="address-highlight">${escapeHTML(envelope.envelopeFrom)}</span>
            </div>
            ${alignmentWarningHTML}
          </div>
        </div>
      `;

      // --- 送達経路テーブル ---
      let routeRows = "";
      let prevDate = null;

      routeHops.forEach((hop, idx) => {
        const isFirst = idx === 0;

        let delayText = "--";
        let delayColor = "#ccc";

        if (hop.date && prevDate) {
          const diffMs = hop.date - prevDate;
          const diffSec = Math.floor(diffMs / 1000);

          if (diffSec < 60) {
            delayText = `+${diffSec}s`;
            delayColor = "#666";
          } else {
            const min = Math.floor(diffSec / 60);
            const sec = diffSec % 60;
            delayText = `+${min}m${sec}s`;
            delayColor = diffSec > 300 ? "#d32f2f" : "#e65100";
          }
        } else if (isFirst) {
          delayText = "ORIGIN";
          delayColor = "#000";
        }
        prevDate = hop.date;

        const hostLabel = hop.from || 'unknown';
        const byLabel = hop.by ? `(by ${hop.by})` : '';
        const rowBg = isFirst ? 'background-color:#f0f8ff;' : '';
        const rowStyle = isFirst ? 'font-weight:bold; color:#000; background-color:#f0f8ff;' : 'color:#555;';
        const timeStr = formatTimestamp(hop.date);

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
          <div class="maiv-card-title" title="Shows the path the email took from sender to your inbox, with time delays between each server hop.">DELIVERY ROUTE (Sender &rarr; Recipient)</div>
          <table class="maiv-route-table">
            ${routeRows}
          </table>
        </div>
      `;

      // --- 最終マークアップの組み立て ---
      const markup = `
        ${headerHTML}
        <div class="maiv-body-wrapper" id="maiv-body-wrapper">
          <div class="maiv-body-inner">
            <div class="maiv-body-content">
              <div class="maiv-grid">
                ${addressHTML}
                ${spfCard}
                ${dkimCard}
                ${dmarcCard}
              </div>
              ${routeHTML}
            </div>
          </div>
        </div>
      `;

      const doc = new DOMParser().parseFromString(markup, "text/html");
      container.replaceChildren(...doc.body.childNodes);

      // 既存のUIを削除して新しいコンテナを挿入
      const existing = document.querySelector(".maiv-container");
      if (existing) existing.remove();
      document.body.insertAdjacentElement("afterbegin", container);

      // --- アコーディオンの開閉インタラクション ---
      const headerToggle = container.querySelector('#maiv-header-toggle');
      const bodyWrapper = container.querySelector('#maiv-body-wrapper');
      const toggleIcon = container.querySelector('#maiv-toggle-icon');

      headerToggle.addEventListener('click', (e) => {
        if (e.target.closest('.maiv-link')) return;
        bodyWrapper.classList.toggle('expanded');
        toggleIcon.classList.toggle('expanded');
      });

      // 「安全」以外の場合はアニメーション付き自動展開
      if (security.shouldAutoExpand) {
        setTimeout(() => {
          bodyWrapper.classList.add('expanded');
          toggleIcon.classList.add('expanded');
        }, 50);
      }
    };

    // =========================================================
    // メイン処理: データ取得 → 解析 → UI構築
    // =========================================================
    const resp = await browser.runtime.sendMessage({ command: "getMessageDetails" });
    if (resp.error || !resp.fullMessage) return;

    const fullMsg = resp.fullMessage;
    const msgHeader = resp.messageHeader || {};
    const headers = fullMsg.headers || {};

    const envelope = parseEnvelope(fullMsg, headers, msgHeader);
    const authResults = parseAuthResults(headers);
    const routeHops = parseRoute(headers);
    const security = determineSecurityStatus(authResults, envelope.isDomainAligned, envelope.envelopeFrom);

    buildUI(envelope, authResults, routeHops, security);

  } catch (e) {
    console.error("MailAuthInfoViewer Error:", e);
  }
})();
