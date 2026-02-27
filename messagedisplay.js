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

    // i18n ヘルパー: browser.i18n.getMessage() のラッパー (キーが見つからない場合はキー自体を返す)
    const msg = (key) => {
      try {
        const translated = browser.i18n.getMessage(key);
        return translated || key;
      } catch (e) {
        return key;
      }
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
    // 1. parseEnvelope - エンベロープ情報・アドレスアライメント・メーリングリスト検知
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

      // ■ 組織ドメイン (Organizational Domain) での比較 — RFC 7489 準拠
      // psl_data.js で定義された getOrganizationalDomain() を使用し、
      // Public Suffix List に基づいて正確な組織ドメインを抽出して比較する。
      // これにより aaa.bbb.google.com と ccc.google.com は共に google.com として一致する。
      const headerOrgDomain = window.getOrganizationalDomain
        ? window.getOrganizationalDomain(headerFromDomain)
        : headerFromDomain;
      const envelopeOrgDomain = window.getOrganizationalDomain
        ? window.getOrganizationalDomain(envelopeFromDomain)
        : envelopeFromDomain;

      const isDomainAligned = (headerOrgDomain === envelopeOrgDomain);

      // ■ メーリングリスト検知
      // List-Id または List-Unsubscribe ヘッダの存在でメーリングリスト経由と判断
      const isMailingList = !!(
        (headers["list-id"] && headers["list-id"].length > 0) ||
        (headers["list-unsubscribe"] && headers["list-unsubscribe"].length > 0)
      );

      return {
        envelopeFrom,
        envelopeTo,
        headerFromName,
        headerFromAddress,
        headerFromDomain,
        envelopeFromDomain,
        headerOrgDomain,
        envelopeOrgDomain,
        isDomainAligned,
        isMailingList
      };
    };

    // =========================================================
    // 2. parseAuthResults - メール認証結果の解析 (authserv-id フィルタリング付き)
    // =========================================================
    const parseAuthResults = (headers) => {
      // ■ authserv-id による信頼フィルタリング
      // 最新の Received ヘッダの by ホスト名と Authentication-Results の authserv-id を比較し、
      // 信頼できるヘッダのみを採用する。攻撃者が注入した偽の認証結果を排除するため。
      // ARC-Authentication-Results は独自のチェイン検証機構を持つため、フィルタリング対象外。

      const getLastReceivedBy = () => {
        const received = headers["received"] || [];
        if (received.length === 0) return "";
        // received[0] が最新（受信MTA自身が追加）
        const byMatch = received[0].match(/\bby\s+([^\s;]+)/i);
        return byMatch ? byMatch[1].toLowerCase() : "";
      };

      const filterByAuthServId = (authResultHeaders, trustedHost) => {
        if (!trustedHost || authResultHeaders.length === 0) return authResultHeaders;

        const trusted = authResultHeaders.filter(h => {
          // authserv-id はヘッダの先頭（最初のセミコロンの前）に記載される
          const authServId = h.split(';')[0].trim().toLowerCase();
          // 完全一致、またはサブドメイン関係を許容
          return authServId === trustedHost ||
                 authServId.endsWith("." + trustedHost) ||
                 trustedHost.endsWith("." + authServId);
        });

        // マッチするものがなければフォールバック（全て信頼）
        return trusted.length > 0 ? trusted : authResultHeaders;
      };

      const lastReceivedBy = getLastReceivedBy();
      const regularAuth = headers["authentication-results"] || [];
      const arcAuth = headers["arc-authentication-results"] || [];

      // 通常の Authentication-Results のみ authserv-id でフィルタリング
      const trustedRegular = filterByAuthServId(regularAuth, lastReceivedBy);
      const authHeaders = [...trustedRegular, ...arcAuth];

      // セミコロンで区切ってメソッド単位に分割し、認証タイプのステータスを抽出
      const parseAuthStatus = (type) => {
        const regex = new RegExp(`\\b${type}\\s*=\\s*([a-zA-Z0-9]+)`, "i");
        for (const h of authHeaders) {
          const methods = h.split(';').slice(1);
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
        const results = [];
        for (const h of authHeaders) {
          const methods = h.split(';').slice(1);
          for (const m of methods) {
            const statusMatch = m.match(/\bdkim\s*=\s*([a-zA-Z0-9]+)/i);
            if (statusMatch) {
              results.push({ status: statusMatch[1].toLowerCase(), segment: m });
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
              if (ipMatch) ip = ipMatch[1];
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
                if (dkimDomain.includes('@')) dkimDomain = dkimDomain.split('@')[1];
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
      let badgeText = msg("badgeUnverified");
      let headerDomainHTML = "";

      if (isSecure) {
        badgeClass = "secure";
        badgeText = msg("badgeAuthPass");
      } else if (authResults.spf.status === "fail" || authResults.dkim.status === "fail" || authResults.dmarc.status === "fail") {
        badgeClass = "danger";
        badgeText = msg("badgeAuthFailed");
      } else if ((isSpfOk || isDkimOk) && !isDomainAligned && envelopeFrom !== "Unknown") {
        badgeClass = "warning";
        badgeText = msg("badgeAuthPassWarning");
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
    // 5. buildUI - UI構築 (HTML/CSS) — i18n・ダークモード完全対応
    // =========================================================
    const buildUI = (envelope, authResults, routeHops, security) => {

      // --- スタイル定義 (CSS変数によるダークモード完全対応) ---
      const style = document.createElement('style');
      style.textContent = `
        /* === CSS カスタムプロパティ (ライトモードデフォルト) === */
        .maiv-container {
          --maiv-bg: #f9f9fa;
          --maiv-border: #ccc;
          --maiv-text: #333;
          --maiv-text-secondary: #555;
          --maiv-text-muted: #666;
          --maiv-text-faint: #999;
          --maiv-text-strong: #222;
          --maiv-text-strongest: #111;
          --maiv-card-bg: white;
          --maiv-card-border: #e0e0e0;
          --maiv-card-title-color: #555;
          --maiv-card-title-border: #eee;
          --maiv-highlight-bg: #f1f3f4;
          --maiv-highlight-border: #ccc;
          --maiv-route-border: #eee;
          --maiv-route-origin-bg: #f0f8ff;
          --maiv-link-color: #666;
          --maiv-link-hover: #2196f3;
          --maiv-shadow: rgba(0,0,0,0.05);
          --maiv-pass: #2e7d32;
          --maiv-fail: #d32f2f;
          --maiv-none: #757575;
          --maiv-delay-normal: #666;
          --maiv-delay-warning: #e65100;
          --maiv-delay-danger: #d32f2f;
          --maiv-align-ok-text: #2e7d32;
          --maiv-align-warn-bg: #fff3e0;
          --maiv-align-warn-text: #e65100;
          --maiv-align-ng-bg: #ffebee;
          --maiv-align-ng-text: #c62828;
          --maiv-policy-reject-bg: #ffebee;
          --maiv-policy-reject-text: #c62828;
          --maiv-policy-quarantine-bg: #fff3e0;
          --maiv-policy-quarantine-text: #e65100;
          --maiv-policy-none-bg: #f5f5f5;
          --maiv-policy-none-text: #757575;
          --maiv-mismatch-color: #e65100;
          --maiv-mailing-list-bg: #e3f2fd;
          --maiv-mailing-list-text: #1565c0;
        }

        /* === ダークモード === */
        @media (prefers-color-scheme: dark) {
          .maiv-container {
            --maiv-bg: #2b2b2b;
            --maiv-border: #555;
            --maiv-text: #e0e0e0;
            --maiv-text-secondary: #ccc;
            --maiv-text-muted: #aaa;
            --maiv-text-faint: #888;
            --maiv-text-strong: #e0e0e0;
            --maiv-text-strongest: #f0f0f0;
            --maiv-card-bg: #3a3a3a;
            --maiv-card-border: #555;
            --maiv-card-title-color: #bbb;
            --maiv-card-title-border: #555;
            --maiv-highlight-bg: #444;
            --maiv-highlight-border: #666;
            --maiv-route-border: #555;
            --maiv-route-origin-bg: #1a2a3a;
            --maiv-link-color: #aaa;
            --maiv-link-hover: #64b5f6;
            --maiv-shadow: rgba(0,0,0,0.3);
            --maiv-pass: #66bb6a;
            --maiv-fail: #ef5350;
            --maiv-none: #aaa;
            --maiv-delay-normal: #aaa;
            --maiv-delay-warning: #ffb74d;
            --maiv-delay-danger: #ef5350;
            --maiv-align-ok-text: #66bb6a;
            --maiv-align-warn-bg: #4a3000;
            --maiv-align-warn-text: #ffcc80;
            --maiv-align-ng-bg: #4a1c1c;
            --maiv-align-ng-text: #ef9a9a;
            --maiv-policy-reject-bg: #4a1c1c;
            --maiv-policy-reject-text: #ef9a9a;
            --maiv-policy-quarantine-bg: #4a3000;
            --maiv-policy-quarantine-text: #ffcc80;
            --maiv-policy-none-bg: #444;
            --maiv-policy-none-text: #aaa;
            --maiv-mismatch-color: #ffb74d;
            --maiv-mailing-list-bg: #1a2a3a;
            --maiv-mailing-list-text: #64b5f6;
          }
        }

        /* === コンポーネントスタイル (CSS変数使用) === */
        .maiv-container {
          font-family: "Segoe UI", Meiryo, sans-serif;
          background-color: var(--maiv-bg);
          border-bottom: 1px solid var(--maiv-border);
          padding: 10px 12px;
          margin-bottom: 15px;
          color: var(--maiv-text);
          font-size: 13px;
          box-shadow: 0 2px 4px var(--maiv-shadow);
        }

        .maiv-header {
          display: flex; align-items: center;
          cursor: pointer; user-select: none;
          padding: 4px 0; transition: opacity 0.2s;
        }
        .maiv-header:hover { opacity: 0.8; }

        .maiv-badge { font-weight: bold; padding: 6px 10px; border-radius: 4px; margin-right: 8px; color: white; font-size: 14px; letter-spacing: 0.5px; white-space: nowrap; }
        .maiv-badge.secure { background-color: #2e7d32; }
        .maiv-badge.warning { background-color: #ed6c02; }
        .maiv-badge.danger { background-color: #d32f2f; }

        .maiv-header-domain { font-size: 17px; font-weight: bold; color: var(--maiv-text-strong); }
        .maiv-header-mismatch { font-size: 13px; color: var(--maiv-mismatch-color); font-weight: bold; margin-left: 6px; }
        .maiv-mailing-list-tag {
          font-size: 11px; font-weight: bold;
          padding: 2px 8px; border-radius: 10px; margin-left: 8px;
          background-color: var(--maiv-mailing-list-bg);
          color: var(--maiv-mailing-list-text);
        }

        .maiv-toggle-icon { margin-left: 15px; margin-right: 15px; color: var(--maiv-text-faint); font-size: 12px; transition: transform 0.35s cubic-bezier(0.4, 0, 0.2, 1); }
        .maiv-toggle-icon.expanded { transform: rotate(180deg); }
        .maiv-link { color: var(--maiv-link-color); text-decoration: none; }
        .maiv-link:hover { text-decoration: underline; color: var(--maiv-link-hover); }

        .maiv-body-wrapper {
          display: grid;
          grid-template-rows: 0fr;
          transition: grid-template-rows 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .maiv-body-wrapper.expanded { grid-template-rows: 1fr; }
        .maiv-body-inner { overflow: hidden; }
        .maiv-body-content { padding-top: 12px; }

        .maiv-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 10px; }
        .maiv-card { background: var(--maiv-card-bg); border: 1px solid var(--maiv-card-border); border-radius: 4px; padding: 8px; }
        .maiv-card-title { font-weight: bold; color: var(--maiv-card-title-color); margin-bottom: 6px; font-size: 11px; text-transform: uppercase; border-bottom: 1px solid var(--maiv-card-title-border); padding-bottom: 4px; }
        .maiv-status-row { display: flex; align-items: center; gap: 6px; }
        .maiv-status-icon { font-size: 14px; }

        .maiv-route-list { background: var(--maiv-card-bg); border: 1px solid var(--maiv-card-border); border-radius: 4px; padding: 8px; font-family: monospace; font-size: 11px; overflow-x: auto; }
        .maiv-route-table { width: 100%; border-collapse: collapse; }
        .maiv-route-table td { padding: 4px; border-bottom: 1px solid var(--maiv-route-border); vertical-align: middle; }

        /* 送達経路テーブルの行スタイル (ダークモード完全対応) */
        .maiv-route-origin { background-color: var(--maiv-route-origin-bg); font-weight: bold; color: var(--maiv-text-strongest); border-left: 3px solid #2196f3; }
        .maiv-route-hop { color: var(--maiv-text-secondary); }
        .maiv-route-by { color: var(--maiv-text-faint); font-size: 0.9em; font-weight: normal; }
        .maiv-route-time { text-align: right; color: var(--maiv-text-faint); white-space: nowrap; }
        .maiv-route-delay { width: 60px; text-align: right; font-weight: bold; font-size: 0.9em; }
        .maiv-delay-none { color: var(--maiv-border); }
        .maiv-delay-origin { color: var(--maiv-text-strongest); }
        .maiv-delay-normal { color: var(--maiv-delay-normal); }
        .maiv-delay-warning { color: var(--maiv-delay-warning); }
        .maiv-delay-danger { color: var(--maiv-delay-danger); }

        .status-pass { color: var(--maiv-pass); font-weight: bold; }
        .status-fail { color: var(--maiv-fail); font-weight: bold; }
        .status-none { color: var(--maiv-none); }

        .align-ok { color: var(--maiv-align-ok-text); font-weight: bold; font-size: 11px; margin-top: 6px; }
        .align-ng { background-color: var(--maiv-align-ng-bg); color: var(--maiv-align-ng-text); font-weight: bold; padding: 6px; border-radius: 4px; font-size: 12px; margin-top: 6px; display: block; }
        .align-warn { background-color: var(--maiv-align-warn-bg); color: var(--maiv-align-warn-text); font-weight: bold; padding: 6px; border-radius: 4px; font-size: 12px; margin-top: 6px; display: block; }

        .address-row { margin-bottom: 6px; display: flex; align-items: center; }
        .address-label { color: var(--maiv-text-muted); width: 110px; display: inline-block; font-size: 11px; text-transform: uppercase; flex-shrink: 0; }
        .address-highlight {
          font-size: 13px; font-weight: bold; color: var(--maiv-text-strongest);
          background-color: var(--maiv-highlight-bg); padding: 4px 8px; border-radius: 3px;
          border: 1px solid var(--maiv-highlight-border); word-break: break-all;
          direction: ltr; unicode-bidi: embed;
        }

        .maiv-detail-text { font-size: 11px; color: var(--maiv-text-muted); margin-top: 4px; }
        .maiv-policy-tag {
          display: inline-block; font-size: 10px; font-weight: bold;
          padding: 2px 6px; border-radius: 3px; margin-top: 4px;
        }
        .maiv-policy-reject { background-color: var(--maiv-policy-reject-bg); color: var(--maiv-policy-reject-text); }
        .maiv-policy-quarantine { background-color: var(--maiv-policy-quarantine-bg); color: var(--maiv-policy-quarantine-text); }
        .maiv-policy-none { background-color: var(--maiv-policy-none-bg); color: var(--maiv-policy-none-text); }
      `;
      document.head.appendChild(style);

      // --- コンテナ作成 ---
      const container = document.createElement("div");
      container.className = "maiv-container";

      // --- ヘッダーバッジとドメイン表示 ---
      let headerDomainText = "";
      let mailingListTag = "";

      if (security.isSecure) {
        headerDomainText = escapeHTML(envelope.headerFromDomain);
      } else if (!envelope.isDomainAligned && (security.isSpfOk || security.isDkimOk) && envelope.envelopeFrom !== "Unknown") {
        // 認証は通っているがドメイン不一致の場合のみ DOMAIN MISMATCH を表示
        // UNVERIFIED（認証情報なし）の場合は表示しない
        headerDomainText = `${escapeHTML(envelope.envelopeFromDomain)} <span class="maiv-header-mismatch">${escapeHTML(msg("domainMismatch"))}</span>`;
      }

      // メーリングリスト経由の場合、ヘッダにタグを追加
      if (envelope.isMailingList) {
        mailingListTag = `<span class="maiv-mailing-list-tag">📋 ${escapeHTML(msg("mailingListVia"))}</span>`;
      }

      const headerHTML = `
        <div class="maiv-header" id="maiv-header-toggle" title="${escapeHTML(msg("toggleDetails"))}">
          <span class="maiv-badge ${security.badgeClass}">${security.badgeText}</span>
          <span class="maiv-header-domain">${headerDomainText}</span>
          ${mailingListTag}
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
        if (d.domain) parts.push(`${escapeHTML(msg("labelDomain"))} ${escapeHTML(d.domain)}`);
        if (d.ip) parts.push(`${escapeHTML(msg("labelIpAddress"))} ${escapeHTML(d.ip)}`);
        return parts.join("<br>");
      })();

      const dkimDetailHTML = (() => {
        const d = authResults.dkim.detail;
        if (d.domains && d.domains.length > 0) {
          return `${escapeHTML(msg("labelDomain"))} ${escapeHTML(d.domains.join(" / "))}`;
        }
        return "";
      })();

      const dmarcDetailHTML = (() => {
        const d = authResults.dmarc.detail;
        const parts = [];
        if (d.domain) parts.push(`${escapeHTML(msg("labelDomain"))} ${escapeHTML(d.domain)}`);
        if (d.policy) {
          let policyClass = "maiv-policy-none";
          if (d.policy === "reject") policyClass = "maiv-policy-reject";
          else if (d.policy === "quarantine") policyClass = "maiv-policy-quarantine";
          parts.push(`<span class="maiv-policy-tag ${policyClass}">${escapeHTML(msg("labelPolicy"))} ${escapeHTML(d.policy)}</span>`);
        }
        return parts.join("<br>");
      })();

      // 認証カード
      const spfCard = createAuthCard(msg("cardTitleSpf"), msg("tooltipSpf"), authResults.spf, spfDetailHTML);
      const dkimCard = createAuthCard(msg("cardTitleDkim"), msg("tooltipDkim"), authResults.dkim, dkimDetailHTML);
      const dmarcCard = createAuthCard(msg("cardTitleDmarc"), msg("tooltipDmarc"), authResults.dmarc, dmarcDetailHTML);

      // --- アドレス＆アライメント表示 ---
      let alignmentWarningHTML = "";

      if (!envelope.isDomainAligned && envelope.envelopeFrom !== "Unknown") {
        if (envelope.isMailingList) {
          // メーリングリスト経由: 不一致の原因が転送である可能性を明示
          alignmentWarningHTML = `<div class="align-warn">📋 ${escapeHTML(msg("mailingListNote"))}</div>`;
        } else if (security.isSpfOk || security.isDkimOk) {
          alignmentWarningHTML = `<div class="align-warn">${escapeHTML(msg("alignMismatch"))}</div>`;
        } else {
          alignmentWarningHTML = `<div class="align-ng">${escapeHTML(msg("alignMismatch"))}</div>`;
        }
      } else if (envelope.isDomainAligned && security.isSecure) {
        alignmentWarningHTML = `<div class="align-ok">${escapeHTML(msg("alignOk"))}</div>`;
      } else if (envelope.isDomainAligned && !security.isSecure) {
        alignmentWarningHTML = `<div class="align-warn">${escapeHTML(msg("alignNotAuth"))}</div>`;
      }

      const displayNameHTML = envelope.headerFromName
        ? `<span class="address-highlight">${escapeHTML(envelope.headerFromName)}</span>`
        : `<span style="color:var(--maiv-text-faint); font-weight:normal;">${escapeHTML(msg("labelNone"))}</span>`;

      const addressHTML = `
        <div class="maiv-card" style="grid-column: span 2; border-left: 4px solid #2196f3;">
          <div class="maiv-card-title" title="${escapeHTML(msg("tooltipAddress"))}">${escapeHTML(msg("cardTitleAddress"))}</div>
          <div style="font-size:11px; margin-top: 8px;">
            <div class="address-row">
              <span class="address-label">${escapeHTML(msg("labelDisplayName"))}</span>
              ${displayNameHTML}
            </div>
            <div class="address-row">
              <span class="address-label">${escapeHTML(msg("labelHeaderFrom"))}</span>
              <span class="address-highlight">${escapeHTML(envelope.headerFromAddress)}</span>
            </div>
            <div class="address-row">
              <span class="address-label">${escapeHTML(msg("labelEnvelopeFrom"))}</span>
              <span class="address-highlight">${escapeHTML(envelope.envelopeFrom)}</span>
            </div>
            ${alignmentWarningHTML}
          </div>
        </div>
      `;

      // --- 送達経路テーブル (CSSクラスによるダークモード完全対応) ---
      let routeRows = "";
      let prevDate = null;

      routeHops.forEach((hop, idx) => {
        const isFirst = idx === 0;

        let delayText = "--";
        let delayClass = "maiv-delay-none";

        if (hop.date && prevDate) {
          const diffMs = hop.date - prevDate;
          const diffSec = Math.floor(diffMs / 1000);
          if (diffSec < 60) {
            delayText = `+${diffSec}s`;
            delayClass = "maiv-delay-normal";
          } else {
            const min = Math.floor(diffSec / 60);
            const sec = diffSec % 60;
            delayText = `+${min}m${sec}s`;
            delayClass = diffSec > 300 ? "maiv-delay-danger" : "maiv-delay-warning";
          }
        } else if (isFirst) {
          delayText = msg("labelOrigin");
          delayClass = "maiv-delay-origin";
        }
        prevDate = hop.date;

        const hostLabel = hop.from || 'unknown';
        const byLabel = hop.by ? `(by ${hop.by})` : '';
        const timeStr = formatTimestamp(hop.date);
        const rowClass = isFirst ? "maiv-route-origin" : "maiv-route-hop";

        routeRows += `
          <tr class="${rowClass}">
            <td class="maiv-route-delay ${delayClass}">${delayText}</td>
            <td>
               <div>${escapeHTML(hostLabel)} ${isFirst ? '🚀' : ''}</div>
               <div class="maiv-route-by">${escapeHTML(byLabel)}</div>
            </td>
            <td class="maiv-route-time">${timeStr}</td>
          </tr>
        `;
      });

      const routeHTML = `
        <div class="maiv-route-list">
          <div class="maiv-card-title" title="${escapeHTML(msg("tooltipRoute"))}">${escapeHTML(msg("cardTitleRoute"))}</div>
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
