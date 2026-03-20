// messagedisplay.js
// Mail Auth Info Viewer — メッセージ表示画面に認証情報ダッシュボードを構築
// Copyright (C) 2025 Shota (SHOWTIME)
// License: GPL-3.0

(async () => {
  try {
    // =========================================================
    // i18n ヘルパー: browser.i18n.getMessage のショートハンド
    // =========================================================
    const msg = (id) => browser.i18n.getMessage(id) || id;

    // =========================================================
    // HTML エスケープ: XSS防止のため、ユーザー由来文字列は必ず通す
    // =========================================================
    const escapeHTML = (str) => {
      if (!str) return "";
      return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    };

    // =========================================================
    // 日時パース: Received ヘッダのタイムスタンプを Date オブジェクトに変換
    // =========================================================
    const parseReceivedDate = (line) => {
      const dateMatch = line.match(/;\s*(.+)$/);
      if (dateMatch) {
        const d = new Date(dateMatch[1].trim());
        if (!isNaN(d.getTime())) return d;
      }
      return null;
    };

    // =========================================================
    // IP アドレス判定ヘルパー群
    // =========================================================
    const isIPv4Like = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
    const isIPv6Like = (s) => /^[a-fA-F0-9:]+$/.test(s) && s.includes(':');

    // プライベートIPアドレス判定（内部/外部ネットワーク分類用）
    const isPrivateIP = (ip) => {
      if (!ip) return false;
      if (ip.includes(':')) {
        const lower = ip.toLowerCase();
        return lower === '::1' || lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd');
      }
      const parts = ip.split('.').map(Number);
      if (parts.length !== 4) return false;
      return (parts[0] === 10) ||
             (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
             (parts[0] === 192 && parts[1] === 168) ||
             (parts[0] === 127);
    };

    // Received ヘッダの from 句からIPアドレスを抽出
    const extractIPFromReceived = (line) => {
      if (!line) return null;
      // 角括弧内のIPv4/IPv6 (例: [192.168.1.1])
      const bracketMatch = line.match(/\[([^\]]+)\]/);
      if (bracketMatch && (isIPv4Like(bracketMatch[1]) || isIPv6Like(bracketMatch[1]))) {
        return bracketMatch[1];
      }
      // 括弧内のIPv4 (例: (192.168.1.1))
      const parenMatch = line.match(/\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)/);
      if (parenMatch) return parenMatch[1];
      return null;
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

      // ■ 表示名なりすまし検知
      // 攻撃者が表示名にメールアドレスを埋め込み、受信者を欺く手口を検知する。
      // 例: From: "support@amazon.co.jp" <evil@attacker.com>
      // 表示名内のアドレスのドメインと実際のHeader Fromドメインを組織ドメインレベルで比較し、
      // 不一致の場合はなりすましの疑いとして警告フラグを立てる。
      let isDisplayNameSpoofed = false;
      if (headerFromName) {
        // 表示名から @ を含む文字列（メールアドレス候補）を抽出
        const emailInName = headerFromName.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/);
        if (emailInName) {
          const spoofedDomain = emailInName[0].split('@')[1].toLowerCase();
          const getOrgDomain = window.getOrganizationalDomain || ((d) => d);
          const spoofedOrgDomain = getOrgDomain(spoofedDomain);
          // 表示名内のドメインと実際のHeader Fromドメインが組織ドメインレベルで異なれば警告
          isDisplayNameSpoofed = (spoofedOrgDomain !== headerOrgDomain);
        }
      }

      // ■ Reply-To ドメイン不一致検知
      // Reply-To が Header From と異なる組織ドメインの場合、
      // フィッシングで返信先を攻撃者に誘導する手口の可能性がある
      let isReplyToMismatch = false;
      let replyToAddress = "";
      const replyToRaw = headers["reply-to"]?.[0] || "";
      if (replyToRaw) {
        const replyToMatch = replyToRaw.match(/<([^>]+)>/);
        replyToAddress = replyToMatch ? replyToMatch[1].trim() : replyToRaw.replace(/^<|>$/g, "").trim();
        if (replyToAddress.includes('@')) {
          const replyToDomain = replyToAddress.split('@')[1].toLowerCase();
          const getOrgDomain = window.getOrganizationalDomain || ((d) => d);
          const replyToOrgDomain = getOrgDomain(replyToDomain);
          // Reply-To の組織ドメインが Header From と異なり、
          // かつ Reply-To アドレスが Header From アドレスと完全一致でもない場合に警告
          if (replyToOrgDomain !== headerOrgDomain && replyToAddress.toLowerCase() !== headerFromAddress.toLowerCase()) {
            isReplyToMismatch = true;
          }
        }
      }

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
        isMailingList,
        isDisplayNameSpoofed,
        isReplyToMismatch,
        replyToAddress
      };
    };

    // =========================================================
    // 2. parseAuthResults - メール認証結果の解析 (authserv-id フィルタリング付き)
    // =========================================================
    const parseAuthResults = (headers, envelope) => {
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
      // 全結果を個別に収集し、集約ステータスと署名ごとの結果リストの両方を返す。
      const parseDkimResults = () => {
        const results = [];
        // 重複排除用: "status|domain" の組み合わせを記録
        const seen = new Set();

        for (const h of authHeaders) {
          const methods = h.split(';').slice(1);
          for (const m of methods) {
            const statusMatch = m.match(/\bdkim\s*=\s*([a-zA-Z0-9]+)/i);
            if (statusMatch) {
              // 各DKIM署名の d= ドメインを抽出
              const dMatch = m.match(/header\.d=([^;\s()]+)/i);
              const domain = dMatch ? dMatch[1].replace(/^[@"']|["']$/g, '') : "";
              // DKIM セレクター (header.s=) を抽出: デバッグやDNS確認時に有用
              const sMatch = m.match(/header\.s=([^;\s()]+)/i);
              const selector = sMatch ? sMatch[1].replace(/["']/g, '') : "";
              const status = statusMatch[1].toLowerCase();

              // Authentication-Results と ARC-Authentication-Results に
              // 同じ署名結果が記録されることがあるため、status+domain で重複排除
              const key = `${status}|${domain.toLowerCase()}`;
              if (seen.has(key)) continue;
              seen.add(key);

              results.push({
                status: status,
                domain: domain,
                selector: selector,
                segment: m
              });
            }
          }
        }

        // 集約: 1つでも pass なら pass
        let aggregated = "none";
        if (results.length > 0) {
          if (results.some(r => r.status === "pass")) aggregated = "pass";
          else if (results.some(r => r.status === "fail")) aggregated = "fail";
          else aggregated = results[0].status;
        }

        return { aggregated, results };
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
                // クォートで囲まれた値 (例: smtp.mailfrom="user@domain.com") に対応
                const fromStr = mailfromMatch[1].replace(/^["'<]|["'>]$/g, '');
                domain = fromStr.includes('@') ? fromStr.split('@')[1] : fromStr;
              } else {
                // フォールバック: (domain of xxx@example.com ...) から取得
                const domainOfMatch = m.match(/domain of ([^;\s()]+)/i);
                if (domainOfMatch) {
                  const fromStr = domainOfMatch[1].replace(/^["'<]|["'>]$/g, '');
                  domain = fromStr.includes('@') ? fromStr.split('@')[1] : fromStr;
                }
              }

              // IP: designates ... as permitted sender、client-ip=、または smtp.remote-ip= から取得
              const ipMatch = m.match(/designates\s+([a-fA-F0-9.:]+)\s+as\s+permitted\s+sender/i) ||
                              m.match(/client-ip=([a-fA-F0-9.:]+)/i) ||
                              m.match(/smtp\.remote-ip=([a-fA-F0-9.:]+)/i);
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
                let dkimDomain = match[1].replace(/["']/g, '');
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
              if (domainMatch) domain = domainMatch[1].replace(/["']/g, '');

              // DMARC ポリシー (p=reject / p=quarantine / p=none) の抽出
              // sp= (サブドメインポリシー) や pct= との誤マッチを防ぐため、
              // 先頭または空白の直後に限定する
              const policyMatch = m.match(/(?:^|[\s(])p=([a-zA-Z]+)/i);
              if (policyMatch) policy = policyMatch[1].toLowerCase();
            }
          }
          return { domain, policy };
        }

        return {};
      };

      // ■ SPF/DKIM アライメントの個別評価
      // DMARCはSPFアライメントとDKIMアライメントを別々に評価する（RFC 7489）。
      // SPFドメイン(smtp.mailfrom)とDKIM署名ドメイン(header.d)を
      // それぞれヘッダFromの組織ドメインと比較する。
      const evaluateAlignment = (spfDetail, dkimDetail, headerOrgDomain) => {
        const getOrgDomain = window.getOrganizationalDomain || ((d) => d);

        // SPF アライメント: smtp.mailfrom のドメインと Header From の組織ドメインを比較
        let spfAligned = false;
        if (spfDetail.domain) {
          const spfOrgDomain = getOrgDomain(spfDetail.domain.toLowerCase());
          spfAligned = (spfOrgDomain === headerOrgDomain);
        }

        // DKIM アライメント: いずれかの DKIM 署名ドメインと Header From の組織ドメインが一致すればOK
        let dkimAligned = false;
        const dkimDomains = dkimDetail.domains || [];
        for (const d of dkimDomains) {
          const dkimOrgDomain = getOrgDomain(d.toLowerCase());
          if (dkimOrgDomain === headerOrgDomain) {
            dkimAligned = true;
            break;
          }
        }

        return { spfAligned, dkimAligned };
      };

      let spfStatus = parseAuthStatus("spf");
      const dkimResult = parseDkimResults();
      const dmarcStatus = parseAuthStatus("dmarc");

      let spfDetail = extractDetail("spf");
      const dkimDetail = extractDetail("dkim");
      const dmarcDetail = extractDetail("dmarc");

      // ■ Received-SPF フォールバック
      // Authentication-Results に SPF 結果がない場合（古いMTAなど）、
      // Received-SPF ヘッダから SPF ステータスとドメイン・IPを取得する
      if (spfStatus === "none") {
        const receivedSpf = headers["received-spf"] || [];
        if (receivedSpf.length > 0) {
          const spfLine = receivedSpf[0];
          // ステータス: ヘッダの先頭単語 (例: "pass identity=mailfrom;")
          const statusMatch = spfLine.match(/^\s*(pass|fail|softfail|neutral|temperror|permerror|none)/i);
          if (statusMatch) {
            spfStatus = statusMatch[1].toLowerCase();
            // ドメイン: envelope-from="user@domain.com" から抽出
            const envFromMatch = spfLine.match(/envelope-from=["']?([^"';\s]+)/i);
            let domain = "";
            if (envFromMatch) {
              const fromStr = envFromMatch[1].replace(/["'>]/g, '');
              domain = fromStr.includes('@') ? fromStr.split('@')[1] : fromStr;
            }
            // IP: client-ip=x.x.x.x から抽出
            const ipMatch = spfLine.match(/client-ip=([a-fA-F0-9.:]+)/i);
            const ip = ipMatch ? ipMatch[1] : spfDetail.ip;
            spfDetail = { domain: domain || spfDetail.domain, ip: ip };
          }
        }
      }

      // SPF/DKIM アライメントの個別評価結果
      const alignment = evaluateAlignment(spfDetail, dkimDetail, envelope.headerOrgDomain);

      return {
        spf: { status: spfStatus, detail: spfDetail },
        dkim: { status: dkimResult.aggregated, detail: dkimDetail, signatures: dkimResult.results },
        dmarc: { status: dmarcStatus, detail: dmarcDetail },
        alignment
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

        // from 句からIPアドレスを抽出し、内部/外部ネットワークを判定
        const fromClause = fromMatch ? fromMatch[1] : "";
        const ip = extractIPFromReceived(fromClause);
        const isInternal = isPrivateIP(ip);

        return {
          from: fromMatch ? fromMatch[1].trim() : null,
          by: byMatch ? byMatch[1] : null,
          date: date,
          ip: ip,
          isInternal: isInternal,
          raw: line
        };
      }).filter(hop => hop.from || hop.by);
    };

    // =========================================================
    // 4. parseArcChain - ARC (Authenticated Received Chain) の解析
    // =========================================================
    // メールが転送される際に付与される ARC ヘッダセットを解析し、
    // チェーン番号ごとの検証状態・署名ドメイン・認証サマリーを抽出する。
    // ARC は転送先のMTAがオリジナルの認証結果を保証するための仕組み (RFC 8617)。
    const parseArcChain = (headers) => {
      const arcSeals = headers["arc-seal"] || [];
      const arcAuthResults = headers["arc-authentication-results"] || [];

      if (arcSeals.length === 0 && arcAuthResults.length === 0) return [];

      // ARC-Seal から各チェーンの情報を抽出
      const chains = new Map();
      for (const seal of arcSeals) {
        // チェーン番号 (i=1, i=2, ...)
        const iMatch = seal.match(/\bi=(\d+)/);
        // チェーン検証状態 (cv=none / cv=pass / cv=fail)
        const cvMatch = seal.match(/\bcv=(\w+)/i);
        // 署名ドメイン (d=example.com)
        const dMatch = seal.match(/\bd=([^\s;]+)/i);

        if (iMatch) {
          const chainNum = parseInt(iMatch[1], 10);
          chains.set(chainNum, {
            i: chainNum,
            cv: cvMatch ? cvMatch[1].toLowerCase() : "unknown",
            domain: dMatch ? dMatch[1] : "",
            authSummary: ""
          });
        }
      }

      // ARC-Authentication-Results から各チェーンの認証サマリーを抽出
      for (const aar of arcAuthResults) {
        const iMatch = aar.match(/\bi=(\d+)/);
        if (!iMatch) continue;
        const chainNum = parseInt(iMatch[1], 10);

        // SPF/DKIM/DMARC の結果をコンパクトにまとめる
        const summaryParts = [];
        const spfMatch = aar.match(/\bspf=(\w+)/i);
        const dkimMatch = aar.match(/\bdkim=(\w+)/i);
        const dmarcMatch = aar.match(/\bdmarc=(\w+)/i);
        if (spfMatch) summaryParts.push(`spf=${spfMatch[1].toLowerCase()}`);
        if (dkimMatch) summaryParts.push(`dkim=${dkimMatch[1].toLowerCase()}`);
        if (dmarcMatch) summaryParts.push(`dmarc=${dmarcMatch[1].toLowerCase()}`);

        if (chains.has(chainNum)) {
          chains.get(chainNum).authSummary = summaryParts.join(" ");
        } else {
          // ARC-Seal がなくても ARC-Authentication-Results だけある場合
          chains.set(chainNum, {
            i: chainNum,
            cv: "unknown",
            domain: "",
            authSummary: summaryParts.join(" ")
          });
        }
      }

      // チェーン番号順にソートして返す
      return Array.from(chains.values()).sort((a, b) => a.i - b.i);
    };

    // =========================================================
    // 5. parseMessageBody - MIME構造を走査してHTML本文を取得
    // =========================================================
    // fullMessage.parts のツリーを再帰的に走査し、text/html パーツを優先的に取得する。
    // HTML が見つからない場合は text/plain にフォールバックする。
    const parseMessageBody = (fullMsg) => {
      let htmlBody = "";
      let textBody = "";

      const walkParts = (parts) => {
        if (!parts) return;
        for (const part of parts) {
          const ct = (part.contentType || "").toLowerCase();
          if (ct === "text/html" && part.body && !htmlBody) {
            htmlBody = part.body;
          } else if (ct === "text/plain" && part.body && !textBody) {
            textBody = part.body;
          }
          // multipart/* の子パーツを再帰走査
          if (part.parts) walkParts(part.parts);
        }
      };

      walkParts(fullMsg.parts);
      return htmlBody || textBody || "";
    };

    // =========================================================
    // 6. analyzeLinkSafety - メール本文のリンク安全性分析
    // =========================================================
    // メール本文のHTML/テキストを解析し、フィッシングの特徴を検出する。
    // 検出項目:
    //   [critical] リンクテキスト偽装、javascript:/data: URI、HTMLフォーム埋め込み
    //   [suspicious] IPアドレスリンク、IDNホモグラフ、URLショートナー
    //   [info] リンクドメイン一覧（Header Fromとの一致/不一致）
    //   [info] Reply-To不一致（parseEnvelopeで検出済み、ここでは扱わない）
    const analyzeLinkSafety = (bodyContent, headerOrgDomain) => {
      const findings = [];   // { level: "critical"|"suspicious"|"info", type: string, detail: string }
      const linkDomains = new Map(); // domain → { count, matchesFrom }
      const deceptiveDomains = new Set(); // リンクテキスト偽装の実際のリンク先組織ドメイン

      // フィッシングで多用される URL ショートナーサービスのドメインリスト
      const URL_SHORTENERS = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "bl.ink", "rb.gy", "cutt.ly", "shorturl.at",
        "tiny.cc", "lnkd.in", "surl.li", "rebrand.ly", "v.gd", "qr.ae",
        "bc.vc", "yourls.org"
      ];

      if (!bodyContent) return { findings, linkDomains, deceptiveDomains };

      // DOMParser で本文HTMLをパースし、リンクとフォームを解析する
      const parser = new DOMParser();
      const doc = parser.parseFromString(bodyContent, "text/html");
      const getOrgDomain = window.getOrganizationalDomain || ((d) => d);

      // ■ フォーム検知 (項目3): メール内の <form> 要素は極めて異常
      const forms = doc.querySelectorAll("form");
      if (forms.length > 0) {
        findings.push({
          level: "critical",
          type: "embedded_form",
          detail: msg("linkEmbeddedForm")
        });
      }

      // ■ リンク解析: 全 <a href="..."> を走査
      const anchors = doc.querySelectorAll("a[href]");
      for (const a of anchors) {
        const href = (a.getAttribute("href") || "").trim();
        if (!href || href.startsWith("#") || href.startsWith("mailto:")) continue;

        // --- 項目2: javascript: / data: URI 検知 ---
        const hrefLower = href.toLowerCase().replace(/\s/g, '');
        if (hrefLower.startsWith("javascript:") || hrefLower.startsWith("data:")) {
          findings.push({
            level: "critical",
            type: "dangerous_scheme",
            detail: msg("linkDangerousScheme") + ` (${escapeHTML(href.substring(0, 30))}...)`
          });
          continue;
        }

        // URL からホスト名を抽出
        let linkHost = "";
        try {
          const url = new URL(href, "http://dummy.invalid");
          linkHost = url.hostname.toLowerCase();
        } catch {
          continue; // パース不能なURLはスキップ
        }

        if (!linkHost || linkHost === "dummy.invalid") continue;

        // --- 項目1: リンクテキスト偽装検知 ---
        // 表示テキストがURLの形式を取っており、href先ドメインと異なる場合はほぼ確実にフィッシング
        const linkText = (a.textContent || "").trim();
        const urlInText = linkText.match(/^https?:\/\/([^\/\s?#]+)/i);
        if (urlInText) {
          const displayHost = urlInText[1].toLowerCase();
          const displayOrgDomain = getOrgDomain(displayHost);
          const hrefOrgDomain = getOrgDomain(linkHost);
          if (displayOrgDomain !== hrefOrgDomain) {
            findings.push({
              level: "critical",
              type: "deceptive_text",
              detail: msg("linkDeceptiveText")
            });
            // 偽装リンクの実際のリンク先ドメインを記録し、ドメイン一覧で危険表示に使う
            deceptiveDomains.add(hrefOrgDomain);
          }
        }

        // --- 項目4: IPアドレス直指定リンク検知 ---
        if (isIPv4Like(linkHost) || isIPv6Like(linkHost) || linkHost.startsWith("[")) {
          findings.push({
            level: "suspicious",
            type: "ip_address_link",
            detail: msg("linkIpAddress") + ` (${escapeHTML(linkHost)})`
          });
        }

        // --- 項目5: IDNホモグラフ攻撃検知 ---
        // Punycode (xn--) を含むドメインは、見た目が正規ドメインに酷似した
        // Unicode文字を使ったなりすましの可能性がある
        if (linkHost.includes("xn--")) {
          findings.push({
            level: "suspicious",
            type: "idn_homograph",
            detail: msg("linkIdnHomograph") + ` (${escapeHTML(linkHost)})`
          });
        }

        // --- 項目6: URLショートナー検知 ---
        const linkOrgDomain = getOrgDomain(linkHost);
        if (URL_SHORTENERS.some(s => linkHost === s || linkHost.endsWith("." + s))) {
          findings.push({
            level: "suspicious",
            type: "url_shortener",
            detail: msg("linkShortener") + ` (${escapeHTML(linkHost)})`
          });
        }

        // --- 項目7: リンクドメイン一覧収集 ---
        // 全リンクのドメインを組織ドメインレベルで集計し、Header Fromとの一致/不一致を記録
        const matchesFrom = (linkOrgDomain === headerOrgDomain);
        if (linkDomains.has(linkOrgDomain)) {
          linkDomains.get(linkOrgDomain).count++;
        } else {
          linkDomains.set(linkOrgDomain, { count: 1, matchesFrom });
        }
      }

      // findings の重複排除（同じ type + detail は1回だけ）
      const uniqueFindings = [];
      const seenFindings = new Set();
      for (const f of findings) {
        const key = `${f.type}|${f.detail}`;
        if (!seenFindings.has(key)) {
          seenFindings.add(key);
          uniqueFindings.push(f);
        }
      }

      return { findings: uniqueFindings, linkDomains, deceptiveDomains };
    };

    // =========================================================
    // 7. determineSecurityStatus - 総合的なセキュリティ判定
    // =========================================================
    // 認証結果・アライメント・フィッシング指標を総合し、バッジ色と判定理由を決定する。
    // グリーン条件:
    //   SPF pass, DKIM pass, DMARC pass (policy ≠ none),
    //   DMARCアライメント成立, 表示名なりすましなし, フィッシング指標なし
    // エンベロープドメイン不一致: DMARC pass かつアライメント成立時はグリーンを阻害しない
    const determineSecurityStatus = (authResults, isDomainAligned, envelopeFrom, isDisplayNameSpoofed, linkSafety) => {
      const isSpfOk = authResults.spf.status === "pass";
      const isDkimOk = authResults.dkim.status === "pass";
      // DMARC は pass のみを合格とする。
      // status=none（DMARCレコード未設定）は管理者がレコードを追加すれば解決できるため、
      // 「設定不備」として警告対象にする。
      const isDmarcOk = authResults.dmarc.status === "pass";

      // ■ DMARCポリシーの厳格性チェック
      // p=none は「DMARCレコードはあるが認証失敗でも何もしない」という設定。
      // 管理者が p=quarantine または p=reject に変更すれば解決できる不備のため、
      // グリーン判定の条件から除外する。
      const dmarcPolicy = authResults.dmarc.detail?.policy || "";
      const isDmarcPolicyStrict = isDmarcOk && dmarcPolicy !== "" && dmarcPolicy !== "none";

      // ■ DMARCアライメント判定 (RFC 7489)
      // SPFドメイン(smtp.mailfrom)またはDKIM署名ドメイン(header.d)の
      // 少なくとも一方がHeader Fromの組織ドメインと一致する必要がある。
      // 両方とも不一致の場合、認証が通っていても信頼性が低い。
      const al = authResults.alignment || {};
      const isDmarcAligned = !!(al.spfAligned || al.dkimAligned);

      // ■ フィッシング指標の集約
      const hasCriticalPhishing = linkSafety?.findings?.some(f => f.level === "critical") || false;
      const hasSuspiciousPhishing = linkSafety?.findings?.some(f => f.level === "suspicious") || false;

      // ■ 判定理由の収集: なぜグリーンにならないか / なぜレッドなのかを記録
      const verdictReasons = [];

      // ■ 総合判定
      // DMARCがpassかつアライメント成立していれば、エンベロープドメイン不一致はグリーンを阻害しない
      // （SendGrid等の正当な外部配信サービス利用パターンに対応）
      const domainCheckOk = isDmarcOk && isDmarcAligned ? true : isDomainAligned;

      const isSecure = isSpfOk && isDkimOk && isDmarcPolicyStrict &&
                       domainCheckOk && isDmarcAligned &&
                       !isDisplayNameSpoofed && !hasCriticalPhishing && !hasSuspiciousPhishing;

      // 判定理由を記録
      if (!isSpfOk) verdictReasons.push("spf_not_pass");
      if (!isDkimOk) verdictReasons.push("dkim_not_pass");
      if (!isDmarcOk) verdictReasons.push("dmarc_not_pass");
      if (isDmarcOk && !isDmarcPolicyStrict) verdictReasons.push("dmarc_policy_none");
      if (!isDmarcAligned) verdictReasons.push("dmarc_not_aligned");
      if (!domainCheckOk) verdictReasons.push("domain_not_aligned");
      if (isDisplayNameSpoofed) verdictReasons.push("display_name_spoofed");
      if (hasCriticalPhishing) verdictReasons.push("phishing_critical");
      if (hasSuspiciousPhishing) verdictReasons.push("phishing_suspicious");

      let badgeClass = "warning";
      let badgeText = msg("badgeUnverified");

      if (hasCriticalPhishing) {
        // フィッシングの確度が極めて高い指標が検出された場合は、認証結果に関わらずレッド
        badgeClass = "danger";
        badgeText = msg("badgeAuthFailed");
      } else if (isSecure) {
        badgeClass = "secure";
        badgeText = msg("badgeAuthPass");
      } else if (authResults.spf.status === "fail" || authResults.dkim.status === "fail" || authResults.dmarc.status === "fail") {
        badgeClass = "danger";
        badgeText = msg("badgeAuthFailed");
      } else if ((isSpfOk || isDkimOk) && envelopeFrom !== "Unknown") {
        // 認証は通っているがグリーン条件を満たさない
        badgeClass = "warning";
        badgeText = msg("badgeAuthPassWarning");
      }

      return {
        isSecure,
        isSpfOk,
        isDkimOk,
        isDmarcOk,
        isDmarcAligned,
        isDmarcPolicyStrict,
        hasCriticalPhishing,
        hasSuspiciousPhishing,
        verdictReasons,
        badgeClass,
        badgeText,
        shouldAutoExpand: badgeClass !== "secure"
      };
    };

    // =========================================================
    // 8. buildUI - UI構築 (HTML/CSS) — Shadow DOM・i18n・ダークモード完全対応
    // =========================================================
    const buildUI = (envelope, authResults, routeHops, security, arcChain, linkSafety) => {

      // --- スタイル定義 (CSS変数によるダークモード完全対応) ---
      const style = document.createElement('style');
      style.textContent = `
        /* === Shadow DOM ホスト要素のリセット === */
        /* HTMLメールのCSSがアドオンUIに影響しないよう、:host で全スタイルを初期化する */
        :host {
          all: initial;
          display: block;
        }

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
        /* 判定理由サマリー: バッジ横に表示する小さなタグ */
        .maiv-verdict-reason {
          font-size: 10px; font-weight: bold; margin-left: 8px;
          padding: 2px 8px; border-radius: 10px;
          white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 350px;
        }
        .maiv-verdict-reason.reason-warning {
          background-color: var(--maiv-align-warn-bg); color: var(--maiv-align-warn-text);
        }
        .maiv-verdict-reason.reason-danger {
          background-color: var(--maiv-align-ng-bg); color: var(--maiv-align-ng-text);
        }

        .maiv-toggle-icon { margin-left: 15px; margin-right: 15px; color: var(--maiv-text-faint); transition: transform 0.3s; display: inline-block; }
        .maiv-toggle-icon.expanded { transform: rotate(180deg); }

        .maiv-link { text-decoration: none; color: var(--maiv-link-color); transition: color 0.2s; }
        .maiv-link:hover { color: var(--maiv-link-hover); }

        .maiv-body-wrapper { max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out; }
        .maiv-body-wrapper.expanded { max-height: 3000px; transition: max-height 0.5s ease-in; }
        .maiv-body-inner { padding-top: 10px; }
        .maiv-body-content { display: flex; flex-direction: column; gap: 10px; }

        /* 上段: アドレス(2) / SPF(1) / DKIM(1) / DMARC(1) */
        .maiv-grid { display: grid; grid-template-columns: 2fr 1fr 1fr 1fr; gap: 10px; }
        /* 下段: 送達経路(2) / ARCチェーン(2) / リンク安全性(1) */
        .maiv-grid-bottom { display: grid; grid-template-columns: 2fr 2fr 1fr; gap: 10px; }
        /* データなしカードの空状態表示 */
        .maiv-empty-state { color: var(--maiv-text-faint); font-size: 11px; font-style: italic; padding: 8px 0; }
        .maiv-card {
          background-color: var(--maiv-card-bg);
          border: 1px solid var(--maiv-card-border);
          border-radius: 6px; padding: 10px;
        }
        .maiv-card-title { font-size: 11px; font-weight: bold; color: var(--maiv-card-title-color); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; padding-bottom: 4px; border-bottom: 1px solid var(--maiv-card-title-border); }
        .maiv-status-row { display: flex; align-items: center; gap: 6px; margin-bottom: 2px; }
        .maiv-status-icon { font-size: 16px; }

        .maiv-route-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 4px; }
        .maiv-route-table td { padding: 4px 6px; border-bottom: 1px solid var(--maiv-route-border); vertical-align: top; }
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

        .address-row { margin-bottom: 4px; display: flex; align-items: center; }
        .address-label { color: var(--maiv-text-muted); width: 85px; display: inline-block; font-size: 10px; text-transform: uppercase; flex-shrink: 0; }
        .address-highlight {
          font-size: 11px; font-weight: bold; color: var(--maiv-text-strongest);
          background-color: var(--maiv-highlight-bg); padding: 3px 6px; border-radius: 3px;
          border: 1px solid var(--maiv-highlight-border); word-break: break-all;
          direction: ltr; unicode-bidi: embed; min-width: 0;
        }

        .maiv-detail-text { font-size: 11px; color: var(--maiv-text-muted); margin-top: 4px; }
        .maiv-policy-tag {
          display: inline-block; font-size: 10px; font-weight: bold;
          padding: 2px 6px; border-radius: 3px; margin-top: 4px;
        }
        .maiv-policy-reject { background-color: var(--maiv-policy-reject-bg); color: var(--maiv-policy-reject-text); }
        .maiv-policy-quarantine { background-color: var(--maiv-policy-quarantine-bg); color: var(--maiv-policy-quarantine-text); }
        .maiv-policy-none { background-color: var(--maiv-policy-none-bg); color: var(--maiv-policy-none-text); }

        /* ARC チェーン表示 */
        .maiv-arc-table { width: 100%; border-collapse: collapse; font-size: 11px; }
        .maiv-arc-table td { padding: 3px 6px; border-bottom: 1px solid var(--maiv-route-border); }
        .maiv-arc-chain-num { font-weight: bold; color: var(--maiv-text-strong); width: 30px; text-align: center; }
        .maiv-arc-domain { color: var(--maiv-text-secondary); }
        .maiv-arc-summary { color: var(--maiv-text-muted); font-family: monospace; font-size: 10px; }

        /* IPタイプ表示: 送達経路上の内部/外部ネットワーク判定 */
        .maiv-ip-tag { font-size: 10px; margin-left: 4px; }

        /* LINK SAFETY カード: フィッシング検知結果表示 */
        .maiv-finding-critical {
          background-color: var(--maiv-align-ng-bg); color: var(--maiv-align-ng-text);
          font-weight: bold; padding: 5px 8px; border-radius: 4px; font-size: 11px;
          margin-bottom: 4px;
        }
        .maiv-finding-suspicious {
          background-color: var(--maiv-align-warn-bg); color: var(--maiv-align-warn-text);
          font-weight: bold; padding: 5px 8px; border-radius: 4px; font-size: 11px;
          margin-bottom: 4px;
        }
        .maiv-link-domain-list { font-size: 11px; margin-top: 6px; }
        .maiv-link-domain-item { padding: 2px 0; display: flex; align-items: center; gap: 6px; }
        .maiv-link-domain-match { color: var(--maiv-pass); }
        .maiv-link-domain-mismatch { color: var(--maiv-align-warn-text); }
        /* リンクテキスト偽装の実際のリンク先ドメイン: 赤色太字で危険性を強調 */
        .maiv-link-domain-danger { color: var(--maiv-fail); font-weight: bold; }

      `;

      // --- コンテナ作成 ---
      const container = document.createElement("div");
      container.className = "maiv-container";

      // --- ヘッダーバッジとドメイン表示 ---
      let headerDomainText = "";
      let mailingListTag = "";

      if (security.isSecure) {
        // グリーン判定時はドメイン名のみ表示
        headerDomainText = escapeHTML(envelope.headerFromDomain);
      } else if (!envelope.isDomainAligned && (security.isSpfOk || security.isDkimOk) && envelope.envelopeFrom !== "Unknown") {
        // ドメイン不一致時もドメイン名のみ表示（詳細はアドレスカード内の警告で確認可能）
        headerDomainText = escapeHTML(envelope.envelopeFromDomain);
      }

      // メーリングリスト経由の場合、ヘッダにタグを追加
      if (envelope.isMailingList) {
        mailingListTag = `<span class="maiv-mailing-list-tag">📋 ${escapeHTML(msg("mailingListVia"))}</span>`;
      }

      // --- 判定理由サマリー: バッジの横に1行で「なぜこの判定か」を表示 ---
      let verdictReasonText = "";
      if (!security.isSecure && security.verdictReasons.length > 0) {
        // 最も重要な理由を1つ選んで表示する（優先順位順）
        const reasonMap = {
          "phishing_critical": msg("verdictReasonPhishing"),
          "dmarc_not_pass": msg("verdictReasonDmarcFail"),
          "dmarc_policy_none": msg("verdictReasonPolicyNone"),
          "spf_not_pass": msg("verdictReasonSpfFail"),
          "dkim_not_pass": msg("verdictReasonDkimFail"),
          "dmarc_not_aligned": msg("verdictReasonAlignment"),
          "domain_not_aligned": msg("verdictReasonDomainMismatch"),
          "display_name_spoofed": msg("verdictReasonSpoofing"),
          "phishing_suspicious": msg("verdictReasonSuspicious")
        };
        const priorityOrder = [
          "phishing_critical", "dmarc_not_pass", "dmarc_policy_none",
          "spf_not_pass", "dkim_not_pass", "dmarc_not_aligned",
          "domain_not_aligned", "display_name_spoofed", "phishing_suspicious"
        ];
        for (const key of priorityOrder) {
          if (security.verdictReasons.includes(key) && reasonMap[key]) {
            verdictReasonText = reasonMap[key];
            break;
          }
        }
      }
      const verdictReasonHTML = (() => {
        if (!verdictReasonText) return "";
        const reasonClass = security.badgeClass === "danger" ? "reason-danger" : "reason-warning";
        return `<span class="maiv-verdict-reason ${reasonClass}">${escapeHTML(verdictReasonText)}</span>`;
      })();

      const headerHTML = `
        <div class="maiv-header" id="maiv-header-toggle" title="${escapeHTML(msg("toggleDetails"))}"
             aria-expanded="${security.shouldAutoExpand}" aria-controls="maiv-body-wrapper">
          <span class="maiv-badge ${security.badgeClass}">${security.badgeText}</span>
          <span class="maiv-header-domain">${headerDomainText}</span>
          ${mailingListTag}
          ${verdictReasonHTML}
          <span style="flex-grow:1;"></span>
          <span class="maiv-toggle-icon" id="maiv-toggle-icon" aria-hidden="true">▼</span>
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
        else if (data.status === "softfail" || data.status === "neutral" || data.status === "none") { icon = "⚠️"; sClass = "status-none"; }
        else if (data.status === "temperror" || data.status === "permerror") { icon = "❌"; sClass = "status-fail"; }

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
      // SPF カード詳細: ドメイン・IP・アライメント結果を表示
      const spfDetailHTML = (() => {
        const d = authResults.spf.detail;
        const al = authResults.alignment;
        const parts = [];
        if (d.domain) parts.push(`${escapeHTML(msg("labelDomain"))} ${escapeHTML(d.domain)}`);
        if (d.ip) parts.push(`${escapeHTML(msg("labelIpAddress"))} ${escapeHTML(d.ip)}`);
        // SPF アライメント: smtp.mailfrom ドメインが Header From の組織ドメインと一致するか
        if (al) {
          const icon = al.spfAligned ? "✅" : "❌";
          const cls = al.spfAligned ? "maiv-align-pass" : "maiv-align-fail";
          const label = al.spfAligned ? msg("alignedLabel") : msg("notAlignedLabel");
          parts.push(`<div class="maiv-align-item" style="margin-top:4px;">${icon} <span class="${cls}">${escapeHTML(msg("labelSpfAlign"))} ${escapeHTML(label)}</span></div>`);
        }
        return parts.join("<br>");
      })();

      // DKIM カード詳細: 集約ドメイン・個別署名結果・アライメントを表示
      const dkimDetailHTML = (() => {
        const d = authResults.dkim.detail;
        const sigs = authResults.dkim.signatures || [];
        const al = authResults.alignment;
        const parts = [];
        const sigsWithDomain = sigs.filter(s => s.domain);

        // 集約ドメイン表示
        if (d.domains && d.domains.length > 0) {
          parts.push(`${escapeHTML(msg("labelDomain"))} ${escapeHTML(d.domains.join(" / "))}`);
        }

        // 署名が1つでセレクターが判明している場合はドメイン行の下にセレクターを表示
        if (sigsWithDomain.length === 1 && sigsWithDomain[0].selector) {
          parts.push(`<span style="color:var(--maiv-text-faint);">selector: ${escapeHTML(sigsWithDomain[0].selector)}</span>`);
        }

        // 複数署名がある場合、ドメインが判明している署名のみ個別にリスト表示する
        if (sigsWithDomain.length > 1) {
          let listHTML = '<div class="maiv-dkim-list">';
          for (const sig of sigsWithDomain) {
            const icon = sig.status === "pass" ? "✅" : (sig.status === "fail" ? "❌" : "⚠️");
            const statusClass = sig.status === "pass" ? "status-pass" : (sig.status === "fail" ? "status-fail" : "status-none");
            // セレクターが判明している場合は (s=selector) を併記
            const selectorLabel = sig.selector ? ` <span style="color:var(--maiv-text-faint);">(s=${escapeHTML(sig.selector)})</span>` : '';
            listHTML += `<div class="maiv-dkim-item">${icon} <span class="${statusClass}">${escapeHTML(sig.status.toUpperCase())}</span> ${escapeHTML(sig.domain)}${selectorLabel}</div>`;
          }
          listHTML += '</div>';
          parts.push(listHTML);
        }

        // DKIM アライメント: いずれかの署名ドメインが Header From の組織ドメインと一致するか
        if (al) {
          const icon = al.dkimAligned ? "✅" : "❌";
          const cls = al.dkimAligned ? "maiv-align-pass" : "maiv-align-fail";
          const label = al.dkimAligned ? msg("alignedLabel") : msg("notAlignedLabel");
          parts.push(`<div class="maiv-align-item" style="margin-top:4px;">${icon} <span class="${cls}">${escapeHTML(msg("labelDkimAlign"))} ${escapeHTML(label)}</span></div>`);
        }

        return parts.join("<br>");
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

      // 表示名なりすまし警告: 表示名に別ドメインのアドレスが埋め込まれている場合
      if (envelope.isDisplayNameSpoofed) {
        alignmentWarningHTML += `<div class="align-ng">${escapeHTML(msg("displayNameSpoofWarning"))}</div>`;
      }

      if (!envelope.isDomainAligned && envelope.envelopeFrom !== "Unknown") {
        if (envelope.isMailingList) {
          // メーリングリスト経由: 不一致の原因が転送である可能性を明示
          alignmentWarningHTML += `<div class="align-warn">📋 ${escapeHTML(msg("mailingListNote"))}</div>`;
        } else if (security.isSpfOk || security.isDkimOk) {
          // 認証は通っている: DMARCアライメント成立時は情報提供レベル、非成立時は警告
          alignmentWarningHTML += `<div class="align-warn">${escapeHTML(msg("alignMismatch"))}</div>`;
        } else {
          alignmentWarningHTML += `<div class="align-ng">${escapeHTML(msg("alignMismatch"))}</div>`;
        }
      } else if (envelope.isDomainAligned && security.isSecure) {
        alignmentWarningHTML += `<div class="align-ok">${escapeHTML(msg("alignOk"))}</div>`;
      } else if (envelope.isDomainAligned && !security.isSecure) {
        alignmentWarningHTML += `<div class="align-warn">${escapeHTML(msg("alignNotAuth"))}</div>`;
      }

      // Reply-To 不一致警告: フィッシングで返信先を攻撃者に誘導する手口の可能性
      if (envelope.isReplyToMismatch) {
        alignmentWarningHTML += `<div class="align-warn">${escapeHTML(msg("replyToMismatch"))} (${escapeHTML(envelope.replyToAddress)})</div>`;
      }

      const displayNameHTML = envelope.headerFromName
        ? `<div class="address-row"><span class="address-label">${escapeHTML(msg("labelDisplayName"))}</span><span class="address-highlight">${escapeHTML(envelope.headerFromName)}</span></div>`
        : "";
      // エンベロープTo: 取得できない場合 (Unknown) は非表示
      const envelopeToHTML = envelope.envelopeTo && envelope.envelopeTo !== "Unknown"
        ? `<div class="address-row"><span class="address-label">${escapeHTML(msg("labelEnvelopeTo"))}</span><span class="address-highlight">${escapeHTML(envelope.envelopeTo)}</span></div>`
        : "";
      const addressHTML = `
        <div class="maiv-card">
          <div class="maiv-card-title" title="${escapeHTML(msg("tooltipAddress"))}">${escapeHTML(msg("cardTitleAddress"))}</div>
          ${displayNameHTML}
          <div class="address-row"><span class="address-label">${escapeHTML(msg("labelHeaderFrom"))}</span><span class="address-highlight">${escapeHTML(envelope.headerFromAddress)}</span></div>
          <div class="address-row"><span class="address-label">${escapeHTML(msg("labelEnvelopeFrom"))}</span><span class="address-highlight">${escapeHTML(envelope.envelopeFrom)}</span></div>
          ${envelopeToHTML}
          ${alignmentWarningHTML}
        </div>
      `;

      // --- 送達経路表示（常時カード表示、データなし時は空状態） ---
      let routeContentHTML = "";
      if (routeHops.length > 0) {
        let routeRows = "";
        for (let i = 0; i < routeHops.length; i++) {
          const hop = routeHops[i];
          const isFirst = (i === 0);

          // 前ホップとの時間差を計算して遅延を表示
          let delayStr = "";
          let delayClass = "maiv-delay-none";
          if (isFirst) {
            delayStr = "🚀";
            delayClass = "maiv-delay-origin";
          } else if (hop.date && routeHops[i - 1].date) {
            const diffMs = hop.date - routeHops[i - 1].date;
            const diffSec = Math.round(diffMs / 1000);
            if (diffSec < 0) { delayStr = `${diffSec}s`; delayClass = "maiv-delay-warning"; }
            else if (diffSec < 5) { delayStr = `${diffSec}s`; delayClass = "maiv-delay-normal"; }
            else if (diffSec < 30) { delayStr = `${diffSec}s`; delayClass = "maiv-delay-warning"; }
            else { delayStr = `${diffSec}s`; delayClass = "maiv-delay-danger"; }
          }

          // from/by のホスト名を表示用に整形
          const fromDisplay = hop.from || "";
          const byDisplay = hop.by ? ` <span class="maiv-route-by">→ ${escapeHTML(hop.by)}</span>` : "";

          // IPアドレスタイプ (内部/外部) をアイコンとツールチップで表示
          let ipTag = "";
          if (hop.ip) {
            const ipIcon = hop.isInternal ? "🏠" : "🌐";
            ipTag = `<span class="maiv-ip-tag" title="${escapeHTML(hop.ip)}">${ipIcon}</span>`;
          }

          const rowClass = isFirst ? "maiv-route-origin" : "maiv-route-hop";
          const timeDisplay = hop.date ? hop.date.toLocaleTimeString() : "";
          const label = isFirst ? `${msg("labelOrigin")} 🚀` : `#${i + 1}`;

          routeRows += `
            <tr class="${rowClass}">
              <td class="maiv-route-delay"><span class="${delayClass}">${delayStr}</span></td>
              <td>${escapeHTML(label)} ${ipTag}${byDisplay}</td>
              <td class="maiv-route-time">${escapeHTML(timeDisplay)}</td>
            </tr>
          `;
        }

        // Envelope-To を末尾行に追加（取得できない場合は省略）
        if (envelope.envelopeTo && envelope.envelopeTo !== "Unknown") {
          routeRows += `
            <tr class="maiv-route-hop">
              <td class="maiv-route-delay"><span class="maiv-delay-none">📬</span></td>
              <td>${escapeHTML(msg("labelEnvelopeTo"))}: ${escapeHTML(envelope.envelopeTo)}</td>
              <td class="maiv-route-time"></td>
            </tr>
          `;
        }
        routeContentHTML = `<table class="maiv-route-table">${routeRows}</table>`;
      } else {
        routeContentHTML = `<div class="maiv-empty-state">${escapeHTML(msg("labelNone"))}</div>`;
      }
      const routeHTML = `
        <div class="maiv-card">
          <div class="maiv-card-title" title="${escapeHTML(msg("tooltipRoute"))}">${escapeHTML(msg("cardTitleRoute"))}</div>
          ${routeContentHTML}
        </div>
      `;

      // --- ARC チェーン表示（常時カード表示、データなし時は空状態） ---
      let arcContentHTML = "";
      if (arcChain.length > 0) {
        let arcRows = "";
        for (const chain of arcChain) {
          const cvIcon = (chain.cv === "pass" || chain.cv === "none") ? "✅" : (chain.cv === "fail" ? "❌" : "⚠️");
          const cvClass = (chain.cv === "pass" || chain.cv === "none") ? "status-pass" : (chain.cv === "fail" ? "status-fail" : "status-none");
          arcRows += `
            <tr>
              <td class="maiv-arc-chain-num">#${chain.i}</td>
              <td>${cvIcon} <span class="${cvClass}">${escapeHTML(chain.cv.toUpperCase())}</span></td>
              <td class="maiv-arc-domain">${escapeHTML(chain.domain)}</td>
              <td class="maiv-arc-summary">${escapeHTML(chain.authSummary)}</td>
            </tr>
          `;
        }
        arcContentHTML = `<table class="maiv-arc-table">${arcRows}</table>`;
      } else {
        arcContentHTML = `<div class="maiv-empty-state">${escapeHTML(msg("labelNone"))}</div>`;
      }
      const arcHTML = `
        <div class="maiv-card">
          <div class="maiv-card-title" title="${escapeHTML(msg("tooltipArc"))}">${escapeHTML(msg("cardTitleArc"))}</div>
          ${arcContentHTML}
        </div>
      `;

      // --- LINK SAFETY カード: フィッシング検知結果とリンクドメイン一覧（常時表示） ---
      const hasFindings = linkSafety && linkSafety.findings && linkSafety.findings.length > 0;
      const hasLinkDomains = linkSafety && linkSafety.linkDomains && linkSafety.linkDomains.size > 0;

      let linkSafetyContentHTML = "";
      if (hasFindings || hasLinkDomains) {
        let findingsHTML = "";
        if (hasFindings) {
          for (const f of linkSafety.findings) {
            const cls = f.level === "critical" ? "maiv-finding-critical" : "maiv-finding-suspicious";
            const icon = f.level === "critical" ? "🚨" : "⚠️";
            findingsHTML += `<div class="${cls}">${icon} ${escapeHTML(f.detail)}</div>`;
          }
        }

        // リンクドメイン一覧: Header Fromとの一致/不一致/偽装先を色分け表示
        let domainListHTML = "";
        if (hasLinkDomains) {
          let domainItems = "";
          const deceptive = linkSafety.deceptiveDomains || new Set();
          // 偽装先ドメインを最上位、不一致を中間、一致を末尾に並べる
          const sorted = Array.from(linkSafety.linkDomains.entries())
            .sort((a, b) => {
              const aDeceptive = deceptive.has(a[0]) ? 2 : 0;
              const bDeceptive = deceptive.has(b[0]) ? 2 : 0;
              const aMatch = a[1].matchesFrom ? 0 : 1;
              const bMatch = b[1].matchesFrom ? 0 : 1;
              return (bDeceptive + bMatch) - (aDeceptive + aMatch);
            });
          for (const [domain, info] of sorted) {
            let icon, cls;
            if (deceptive.has(domain)) {
              // リンクテキスト偽装の実際のリンク先: 赤色太字で危険性を強調
              icon = "💀";
              cls = "maiv-link-domain-danger";
            } else if (info.matchesFrom) {
              icon = "✅";
              cls = "maiv-link-domain-match";
            } else {
              icon = "⚠️";
              cls = "maiv-link-domain-mismatch";
            }
            domainItems += `<div class="maiv-link-domain-item">${icon} <span class="${cls}">${escapeHTML(domain)}</span> <span style="color:var(--maiv-text-faint);">(×${info.count})</span></div>`;
          }
          domainListHTML = `
            <div class="maiv-link-domain-list">
              <div style="font-weight:bold; margin-bottom:4px; color:var(--maiv-text-secondary);">${escapeHTML(msg("linkDomainListTitle"))}</div>
              ${domainItems}
            </div>
          `;
        }
        linkSafetyContentHTML = findingsHTML + domainListHTML;
      } else {
        // リンクなし または テキストメールの場合の空状態
        linkSafetyContentHTML = `<div class="maiv-empty-state">${escapeHTML(msg("labelNone"))}</div>`;
      }

      const linkSafetyHTML = `
        <div class="maiv-card">
          <div class="maiv-card-title" title="${escapeHTML(msg("tooltipLinkSafety"))}">${escapeHTML(msg("cardTitleLinkSafety"))}</div>
          ${linkSafetyContentHTML}
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
              <div class="maiv-grid-bottom">
                ${routeHTML}
                ${arcHTML}
                ${linkSafetyHTML}
              </div>
            </div>
          </div>
        </div>
      `;

      const doc = new DOMParser().parseFromString(markup, "text/html");
      container.replaceChildren(...doc.body.childNodes);

      // ■ Shadow DOM によるCSS隔離
      // HTMLメール側のCSS (例: * { font-size: 20px !important; }) がアドオンUIに
      // 影響しないよう、Shadow DOM でカプセル化する。
      // mode: "closed" により外部からの shadow root への参照も遮断する。
      const hostId = "maiv-shadow-host";
      let host = document.getElementById(hostId);
      if (host) host.remove();
      host = document.createElement("div");
      host.id = hostId;
      document.body.insertAdjacentElement("afterbegin", host);

      const shadow = host.attachShadow({ mode: "closed" });
      shadow.appendChild(style);
      shadow.appendChild(container);

      // --- アコーディオンの開閉インタラクション ---
      const headerToggle = container.querySelector('#maiv-header-toggle');
      const bodyWrapper = container.querySelector('#maiv-body-wrapper');
      const toggleIcon = container.querySelector('#maiv-toggle-icon');

      // 開閉状態を切り替え、aria-expanded 属性も同期させる共通関数
      const togglePanel = () => {
        const isExpanded = bodyWrapper.classList.toggle('expanded');
        toggleIcon.classList.toggle('expanded');
        headerToggle.setAttribute('aria-expanded', isExpanded);
      };

      // マウスクリックによる開閉（リンクをクリックした場合は除外）
      headerToggle.addEventListener('click', (e) => {
        if (e.target.closest('.maiv-link')) return;
        togglePanel();
      });

      // 「安全」以外の場合はアニメーション付き自動展開
      if (security.shouldAutoExpand) {
        setTimeout(() => {
          bodyWrapper.classList.add('expanded');
          toggleIcon.classList.add('expanded');
          headerToggle.setAttribute('aria-expanded', 'true');
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
    const authResults = parseAuthResults(headers, envelope);
    const routeHops = parseRoute(headers);
    const arcChain = parseArcChain(headers);
    const bodyContent = parseMessageBody(fullMsg);
    const linkSafety = analyzeLinkSafety(bodyContent, envelope.headerOrgDomain);
    const security = determineSecurityStatus(authResults, envelope.isDomainAligned, envelope.envelopeFrom, envelope.isDisplayNameSpoofed, linkSafety);

    buildUI(envelope, authResults, routeHops, security, arcChain, linkSafety);

  } catch (e) {
    console.error("MailAuthInfoViewer Error:", e);
  }
})();
