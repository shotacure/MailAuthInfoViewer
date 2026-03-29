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
              // 各DKIM署名の d= ドメインを抽出。なければ i= から取得
              const dMatch = m.match(/header\.d=([^;\s()]+)/i);
              let domain = dMatch ? dMatch[1].replace(/^[@"']|["']$/g, '') : "";
              if (!domain) {
                // header.i=@domain or header.i=user@domain からドメイン部分を取得
                const iMatch = m.match(/header\.i=([^;\s()]+)/i);
                if (iMatch) {
                  let ival = iMatch[1].replace(/["']/g, '');
                  domain = ival.includes('@') ? ival.split('@').pop() : ival;
                }
              }
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
          let rawSegment = "";

          for (const h of authHeaders) {
            const methods = h.split(';').slice(1);
            for (const m of methods) {
              if (!/\bspf\s*=/i.test(m)) continue;
              rawSegment = m.trim();

              // smtp.mailfrom
              const mailfromMatch = m.match(/smtp\.mailfrom=([^;\s()]+)/i);
              if (mailfromMatch) {
                const fromStr = mailfromMatch[1].replace(/^["'<]|["'>]$/g, '');
                domain = fromStr.includes('@') ? fromStr.split('@')[1] : fromStr;
              } else {
                const domainOfMatch = m.match(/domain of ([^;\s()]+)/i);
                if (domainOfMatch) {
                  const fromStr = domainOfMatch[1].replace(/^["'<]|["'>]$/g, '');
                  domain = fromStr.includes('@') ? fromStr.split('@')[1] : fromStr;
                }
              }

              // IP
              const ipMatch = m.match(/designates\s+([a-fA-F0-9.:]+)\s+as\s+permitted\s+sender/i) ||
                              m.match(/client-ip=([a-fA-F0-9.:]+)/i) ||
                              m.match(/smtp\.remote-ip=([a-fA-F0-9.:]+)/i);
              if (ipMatch) ip = ipMatch[1];

              if (domain || ip) return { domain, ip, rawSegment };
            }
          }
          return { domain, ip, rawSegment };
        }

        if (type === 'dkim') {
          const domains = new Set();

          for (const h of authHeaders) {
            const methods = h.split(';').slice(1);
            for (const m of methods) {
              if (!/\bdkim\s*=/i.test(m)) continue;

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
          let rawSegment = "";

          for (const h of authHeaders) {
            const methods = h.split(';').slice(1);
            for (const m of methods) {
              if (!/\bdmarc\s*=/i.test(m)) continue;
              rawSegment = m.trim();

              const domainMatch = m.match(/header\.from=([^;\s()]+)/i);
              if (domainMatch) domain = domainMatch[1].replace(/["']/g, '');

              // p= (ポリシー) - sp= / pct= との誤マッチ防止
              const policyMatch = m.match(/(?:^|[\s(])p=([a-zA-Z]+)/i);
              if (policyMatch) policy = policyMatch[1].toLowerCase();
            }
          }
          return { domain, policy, rawSegment };
        }

        return {};
      };

      // ■ SPF/DKIM アライメントの個別評価
      // DMARCはSPFアライメントとDKIMアライメントを別々に評価する（RFC 7489）。
      // SPFドメイン(smtp.mailfrom)とDKIM署名ドメイン(header.d)を
      // それぞれヘッダFromの組織ドメインと比較する。
      const evaluateAlignment = (spfDetail, dkimSignatures, headerOrgDomain, spfStatus, dkimStatus) => {
        const getOrgDomain = window.getOrganizationalDomain || ((d) => d);

        // SPF アライメント: smtp.mailfrom のドメインと Header From の組織ドメインを比較
        // SPF が pass でない場合、ドメインが一致していてもアライメント成立とはみなさない
        let spfAligned = false;
        if (spfStatus === "pass" && spfDetail.domain) {
          const spfOrgDomain = getOrgDomain(spfDetail.domain.toLowerCase());
          spfAligned = (spfOrgDomain === headerOrgDomain);
        }

        // DKIM アライメント: pass した署名のドメインのみを対象に評価する。
        // fail した署名のドメインが Header From と一致していてもアライメント成立とはみなさない。
        // （例: pass=trusted.com, fail=attacker.com の場合、attacker.com は無視する）
        let dkimAligned = false;
        if (dkimStatus === "pass") {
          const passedDomains = (dkimSignatures || [])
            .filter(sig => sig.status === "pass" && sig.domain)
            .map(sig => sig.domain);
          for (const d of passedDomains) {
            const dkimOrgDomain = getOrgDomain(d.toLowerCase());
            if (dkimOrgDomain === headerOrgDomain) {
              dkimAligned = true;
              break;
            }
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

      // SPF/DKIM アライメントの個別評価結果（pass した署名のドメインのみで判定）
      const alignment = evaluateAlignment(spfDetail, dkimResult.results, envelope.headerOrgDomain, spfStatus, dkimResult.aggregated);

      return {
        authServId: trustedRegular.length > 0
          ? trustedRegular[0].split(';')[0].trim()
          : lastReceivedBy,
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
    //   [suspicious] 唯一のリンクが外部ドメイン、最大CTAが外部ドメイン、トラッキングピクセル
    //   [info] リンクドメイン一覧、リソースドメイン一覧
    const analyzeLinkSafety = (bodyContent, headerOrgDomain, trustedDomains) => {
      const findings = [];   // { level: "critical"|"suspicious"|"info", type: string, detail: string }
      const linkDomains = new Map(); // domain → { count, matchesFrom }
      const resourceDomains = new Map(); // domain → { count, matchesFrom } (画像等の外部リソース)
      const deceptiveDomains = new Set(); // リンクテキスト偽装の実際のリンク先組織ドメイン

      // フィッシングで多用される URL ショートナーサービスのドメインリスト
      const URL_SHORTENERS = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "bl.ink", "rb.gy", "cutt.ly", "shorturl.at",
        "tiny.cc", "lnkd.in", "surl.li", "rebrand.ly", "v.gd", "qr.ae",
        "bc.vc", "yourls.org"
      ];

      if (!bodyContent) return { findings, linkDomains, resourceDomains, deceptiveDomains, trackingPixelDomains: new Set() };

      // DOMParser で本文HTMLをパースし、リンク・フォーム・画像を解析する
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
      // 各リンクの推定表示面積も記録し、最大CTAの判定に使う
      const anchors = doc.querySelectorAll("a[href]");
      const linkInfos = []; // { orgDomain, matchesFrom, estimatedArea }

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
          continue;
        }

        if (!linkHost || linkHost === "dummy.invalid") continue;

        // --- 項目1: リンクテキスト偽装検知 ---
        const linkText = (a.textContent || "").trim();
        const urlInText = linkText.match(/^https?:\/\/([^\/\s?#]+)/i);
        if (urlInText) {
          const displayHost = urlInText[1].toLowerCase();
          const displayOrgDomain = getOrgDomain(displayHost);
          const hrefOrgDomain = getOrgDomain(linkHost);
          if (displayOrgDomain !== hrefOrgDomain) {
            // 信頼済みドメインならスキップ
            if (trustedDomains && trustedDomains.has(hrefOrgDomain)) {
              // スキップ（ドメイン一覧には引き続き記録）
            } else {
              findings.push({
                level: "critical",
                type: "deceptive_text",
                detail: msg("linkDeceptiveText"),
                targetDomain: hrefOrgDomain
              });
              deceptiveDomains.add(hrefOrgDomain);
            }
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
        const matchesFrom = (linkOrgDomain === headerOrgDomain);
        if (linkDomains.has(linkOrgDomain)) {
          linkDomains.get(linkOrgDomain).count++;
        } else {
          linkDomains.set(linkOrgDomain, { count: 1, matchesFrom });
        }

        // --- CTA推定面積の計算 ---
        // <a> 内に <img> がある場合はその画像サイズ、なければテキスト長で推定
        let estimatedArea = linkText.length * 16; // テキストリンクのデフォルト推定
        const innerImg = a.querySelector("img");
        if (innerImg) {
          const w = parseInt(innerImg.getAttribute("width")) || 0;
          const h = parseInt(innerImg.getAttribute("height")) || 0;
          if (w > 0 && h > 0) estimatedArea = w * h;
          else estimatedArea = 10000; // サイズ不明の画像リンクは大きめに推定
        }
        // ボタン風スタイルの検出: padding や display:block があれば面積を加算
        const style = a.getAttribute("style") || "";
        if (/padding/i.test(style) || /display\s*:\s*block/i.test(style)) {
          estimatedArea = Math.max(estimatedArea, 5000);
        }

        linkInfos.push({ orgDomain: linkOrgDomain, matchesFrom, estimatedArea });
      }

      // ■ テキスト状態のURL検出
      const textContent = doc.body ? doc.body.textContent : "";
      const textUrlRegex = /https?:\/\/([^\s"'<>)\]]+)/gi;
      const textUrls = []; // テキスト中のURL一覧（唯一のURL判定に使用）
      let textUrlMatch;
      while ((textUrlMatch = textUrlRegex.exec(textContent)) !== null) {
        try {
          const url = new URL(textUrlMatch[0]);
          const host = url.hostname.toLowerCase();
          if (!host) continue;
          const orgDomain = getOrgDomain(host);
          const matchesFrom = (orgDomain === headerOrgDomain);
          textUrls.push({ orgDomain, matchesFrom });
          if (!linkDomains.has(orgDomain)) {
            linkDomains.set(orgDomain, { count: 1, matchesFrom });
          }
        } catch {
          // パース不能なURLはスキップ
        }
      }

      // ■ すべてのリンクが外部ドメイン → フィッシング疑い
      // HTMLメール: 全 <a> リンクのドメインがHeader Fromと無関係（信頼済みドメインは除外）
      // テキストメール: 全URLのドメインがHeader Fromと無関係（信頼済みドメインは除外）
      const isHtml = /<[a-z][\s\S]*>/i.test(bodyContent);
      const isSafeLink = (l) => l.matchesFrom || (trustedDomains && trustedDomains.has(l.orgDomain));
      let hasAllExternalWarning = false;
      if (isHtml && linkInfos.length > 0 && !linkInfos.some(isSafeLink)) {
        findings.push({ level: "suspicious", type: "all_links_external", detail: msg("linkAllExternal") });
        hasAllExternalWarning = true;
      } else if (!isHtml && textUrls.length > 0 && !textUrls.some(isSafeLink)) {
        findings.push({ level: "suspicious", type: "all_links_external", detail: msg("linkAllExternal") });
        hasAllExternalWarning = true;
      }

      // ■ 最大CTAリンクが外部ドメイン → フィッシング疑い
      // メール内で最も目立つクリック領域（推定面積最大）のリンク先が送信者ドメインと異なる場合
      // 全リンク外部警告が出ている場合は冗長なので省略
      if (!hasAllExternalWarning && linkInfos.length > 0) {
        const largestCta = linkInfos.reduce((max, cur) => cur.estimatedArea > max.estimatedArea ? cur : max);
        if (!isSafeLink(largestCta)) {
          findings.push({ level: "suspicious", type: "cta_external", detail: msg("linkCtaExternal") });
        }
      }

      // ■ 画像・外部リソース解析
      const images = doc.querySelectorAll("img[src]");
      let trackingPixelCount = 0;
      const trackingPixelDomains = new Set(); // トラッキングピクセルの配信元ドメイン
      for (const img of images) {
        const src = (img.getAttribute("src") || "").trim();
        if (!src || src.startsWith("data:") || src.startsWith("cid:")) continue;

        let imgHost = "";
        try {
          const url = new URL(src, "http://dummy.invalid");
          imgHost = url.hostname.toLowerCase();
        } catch {
          continue;
        }
        if (!imgHost || imgHost === "dummy.invalid") continue;

        const imgOrgDomain = getOrgDomain(imgHost);
        const matchesFrom = (imgOrgDomain === headerOrgDomain);

        // トラッキングピクセル検知: 1x1 や 0x0 の非表示画像
        const w = parseInt(img.getAttribute("width")) || -1;
        const h = parseInt(img.getAttribute("height")) || -1;
        const style = img.getAttribute("style") || "";
        const isPixel = (w >= 0 && w <= 2 && h >= 0 && h <= 2) ||
                        /width\s*:\s*[01]px/i.test(style) ||
                        /height\s*:\s*[01]px/i.test(style) ||
                        /display\s*:\s*none/i.test(style) ||
                        /visibility\s*:\s*hidden/i.test(style);
        if (isPixel) {
          trackingPixelCount++;
          trackingPixelDomains.add(imgOrgDomain);
        }

        // リソースドメイン一覧に追加（トラッキングピクセルも含める）
        if (resourceDomains.has(imgOrgDomain)) {
          resourceDomains.get(imgOrgDomain).count++;
        } else {
          resourceDomains.set(imgOrgDomain, { count: 1, matchesFrom });
        }
      }

      // トラッキングピクセルが検出された場合は警告
      if (trackingPixelCount > 0) {
        findings.push({
          level: "suspicious",
          type: "tracking_pixel",
          detail: msg("linkTrackingPixel") + ` (×${trackingPixelCount})`
        });
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

      return { findings: uniqueFindings, linkDomains, resourceDomains, deceptiveDomains, trackingPixelDomains };
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

      // ■ DMARCポリシーの情報表示
      // p=none は「DMARCレコードはあるが認証失敗でも何もしない」という設定。
      // DMARCカード内でポリシーを赤色表示して管理者に改善を促すが、
      // 認証自体は成功しているためグリーン判定は阻害しない。
      // （一般ユーザーにはp=noneで自動展開しないことで情報過多を防ぐ）

      // ■ DMARCアライメント判定 (RFC 7489)
      // SPFドメイン(smtp.mailfrom)またはDKIM署名ドメイン(header.d)の
      // 少なくとも一方がHeader Fromの組織ドメインと一致する必要がある。
      // 両方とも不一致の場合、認証が通っていても信頼性が低い。
      const al = authResults.alignment || {};
      const isDmarcAligned = !!(al.spfAligned || al.dkimAligned);

      // ■ フィッシング指標の集約
      const hasCriticalPhishing = linkSafety?.findings?.some(f => f.level === "critical") || false;
      // トラッキングピクセルはグリーン判定を阻害しない（情報提供のみ）
      // 正規の企業メールにほぼ必ず含まれるため、阻害すると常態化してオオカミ少年になる
      const hasSuspiciousLink = linkSafety?.findings?.some(f => f.level === "suspicious" && f.type !== "tracking_pixel") || false;

      // ■ 判定理由の収集: グリーンでない全理由を記録
      // 認証系は実ステータスを含め、アライメントはpassかつ不成立の場合のみ記録
      const verdictReasons = [];

      // ■ 総合判定
      // DMARCがpassかつアライメント成立していれば、エンベロープドメイン不一致はグリーンを阻害しない
      // （SendGrid等の正当な外部配信サービス利用パターンに対応）
      const domainCheckOk = isDmarcOk && isDmarcAligned ? true : isDomainAligned;

      const isSecure = isSpfOk && isDkimOk && isDmarcOk &&
                       domainCheckOk && isDmarcAligned &&
                       !isDisplayNameSpoofed && !hasCriticalPhishing && !hasSuspiciousLink;

      // 認証系: pass 以外なら実際のステータスを記録 (例: "SPF: softfail")
      if (!isSpfOk) verdictReasons.push(`SPF: ${authResults.spf.status}`);
      if (!isDkimOk) verdictReasons.push(`DKIM: ${authResults.dkim.status}`);
      if (!isDmarcOk) verdictReasons.push(`DMARC: ${authResults.dmarc.status}`);
      // アライメント: 認証が pass しているのにアライメント不成立の場合のみ表示
      if (isSpfOk && !al.spfAligned) verdictReasons.push("spf_align_fail");
      if (isDkimOk && !al.dkimAligned) verdictReasons.push("dkim_align_fail");
      if (!domainCheckOk) verdictReasons.push("domain_not_aligned");
      if (isDisplayNameSpoofed) verdictReasons.push("display_name_spoofed");
      // phishing_critical はバッジ自体が「💀 フィッシング検出」になるため判定理由には含めない
      // トラッキングピクセルは判定理由タグに出さない（リンク安全性カード内で情報提供）
      if (hasSuspiciousLink) verdictReasons.push("phishing_suspicious");

      let badgeClass = "warning";
      let badgeText = msg("badgeUnverified");

      if (hasCriticalPhishing) {
        // フィッシング確定: リンク偽装等の確度が極めて高い指標 → 専用バッジ（レッドより重い）
        badgeClass = "phishing";
        badgeText = msg("badgePhishing");
      } else if (isSecure) {
        badgeClass = "secure";
        badgeText = msg("badgeAuthPass");
      } else if (authResults.spf.status === "fail" || authResults.dkim.status === "fail" || authResults.dmarc.status === "fail") {
        badgeClass = "danger";
        badgeText = msg("badgeAuthFailed");
      } else if ((isSpfOk || isDkimOk) && isDmarcOk && envelopeFrom !== "Unknown") {
        // SPF/DKIM・DMARC全て通っているが他の条件（アライメント・なりすまし等）で不合格
        badgeClass = "warning";
        badgeText = msg("badgeAuthPassWarning");
      } else if ((isSpfOk || isDkimOk) && envelopeFrom !== "Unknown") {
        // SPF/DKIMの一部は通っているがDMARCがpassでない → 「認証成功」とは言わない
        badgeClass = "warning";
        badgeText = msg("badgeAuthPartial");
      }

      return {
        isSecure,
        isSpfOk,
        isDkimOk,
        isDmarcOk,
        isDmarcAligned,
        hasCriticalPhishing,
        hasSuspiciousLink,
        verdictReasons,
        badgeClass,
        badgeText,
        shouldAutoExpand: false
      };
    };

    // =========================================================
    // 8. buildUI - UI構築 (HTML/CSS) — Shadow DOM・i18n・ダークモード完全対応
    // =========================================================
    const buildUI = (envelope, authResults, routeHops, security, arcChain, linkSafety, trustedDomains) => {

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
          --maiv-policy-reject-bg: #e3f2fd;
          --maiv-policy-reject-text: #1565c0;
          --maiv-policy-quarantine-bg: #fff3e0;
          --maiv-policy-quarantine-text: #e65100;
          --maiv-policy-none-bg: #ffebee;
          --maiv-policy-none-text: #c62828;
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
            --maiv-policy-reject-bg: #1a2a3a;
            --maiv-policy-reject-text: #64b5f6;
            --maiv-policy-quarantine-bg: #4a3000;
            --maiv-policy-quarantine-text: #ffcc80;
            --maiv-policy-none-bg: #4a1c1c;
            --maiv-policy-none-text: #ef9a9a;
            --maiv-mismatch-color: #ffb74d;
            --maiv-mailing-list-bg: #1a2a3a;
            --maiv-mailing-list-text: #64b5f6;
          }
        }

        /* ダークモードでのフィッシングバッジ */
        @media (prefers-color-scheme: dark) {
          .maiv-badge.phishing {
            background-color: #2a0000;
            color: #ff5252;
            border-color: #ff5252;
          }
          @keyframes maiv-phishing-pulse {
            0%, 100% { background-color: #2a0000; color: #ff5252; }
            50% { background-color: #ff5252; color: #1a0000; }
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
        .maiv-badge.phishing {
          background-color: #fff;
          color: #b71c1c;
          border: 2px solid #d32f2f;
          animation: maiv-phishing-pulse 0.8s ease-in-out 5;
        }
        @keyframes maiv-phishing-pulse {
          0%, 100% { background-color: #fff; color: #b71c1c; }
          50% { background-color: #d32f2f; color: #fff; }
        }

        .maiv-header-domain { font-size: 17px; font-weight: bold; color: var(--maiv-text-strong); }
        .maiv-header-mismatch { font-size: 13px; color: var(--maiv-mismatch-color); font-weight: bold; margin-left: 6px; }
        .maiv-mailing-list-tag {
          font-size: 11px; font-weight: bold;
          padding: 2px 8px; border-radius: 10px; margin-left: 8px;
          background-color: var(--maiv-mailing-list-bg);
          color: var(--maiv-mailing-list-text);
        }
        /* 判定理由タグ: 全理由をピルタグで横並び（折り返し可） */
        .maiv-verdict-reasons-wrap {
          display: inline-flex; flex-wrap: wrap; gap: 4px; margin-left: 8px; align-items: center;
        }
        .maiv-verdict-reason {
          font-size: 10px; font-weight: bold;
          padding: 2px 8px; border-radius: 10px;
          white-space: nowrap;
        }
        .maiv-verdict-reason.reason-warning {
          background-color: var(--maiv-align-warn-bg); color: var(--maiv-align-warn-text);
        }
        .maiv-verdict-reason.reason-danger {
          background-color: var(--maiv-align-ng-bg); color: var(--maiv-align-ng-text);
        }

        .maiv-toggle-icon { margin-left: 15px; margin-right: 15px; color: var(--maiv-text-faint); transition: transform 0.3s; display: inline-block; }
        .maiv-toggle-icon.expanded { transform: rotate(180deg); }

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

        /* 折りたたみ可能なカード */
        .maiv-card-title.maiv-collapsible {
          cursor: pointer; user-select: none; display: flex; align-items: center; gap: 4px;
        }
        .maiv-card-title.maiv-collapsible:hover { opacity: 0.7; }
        .maiv-card-title.maiv-collapsible::before {
          content: "▶"; font-size: 8px; transition: transform 0.2s; display: inline-block; flex-shrink: 0;
        }
        .maiv-card-title.maiv-collapsible.maiv-expanded::before {
          transform: rotate(90deg);
        }
        .maiv-collapsible-body {
          max-height: 0; overflow: hidden; transition: max-height 0.3s ease;
        }
        .maiv-collapsible-body.maiv-expanded {
          max-height: 2000px;
        }
        /* 認証カードの最小高さ（折りたたみ時もステータス行を維持） */
        .maiv-auth-card { min-height: 70px; }
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

        /* SPF/DKIMカード内のアライメントラベル色分け */
        .maiv-align-pass { color: var(--maiv-pass); }
        .maiv-align-fail { color: var(--maiv-fail); }

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
        .maiv-expanded-detail { font-size: 10px; color: var(--maiv-text-muted); margin-top: 6px; padding-top: 6px; border-top: 1px dashed var(--maiv-card-title-border); }
        .maiv-prop-row { display: flex; gap: 6px; padding: 1px 0; }
        .maiv-prop-key { color: var(--maiv-text-faint); min-width: 80px; flex-shrink: 0; font-family: monospace; font-size: 10px; }
        .maiv-prop-val { color: var(--maiv-text-secondary); word-break: break-all; font-family: monospace; font-size: 10px; }
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
        .maiv-trust-btn {
          font-size: 10px; padding: 2px 8px; margin-left: 8px; border: 1px solid currentColor;
          border-radius: 3px; background: transparent; color: inherit; cursor: pointer;
          font-weight: normal; opacity: 0.8; vertical-align: middle;
        }
        .maiv-trust-btn:hover { opacity: 1; background: rgba(255,255,255,0.2); }

        /* カスタム確認ダイアログ */
        .maiv-confirm-overlay {
          position: fixed; top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(0,0,0,0.5); z-index: 99999;
          display: flex; align-items: center; justify-content: center;
        }
        .maiv-confirm-box {
          background: var(--maiv-card-bg); border: 1px solid var(--maiv-card-border);
          border-radius: 8px; padding: 20px; max-width: 360px; width: 90%;
          box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }
        .maiv-confirm-text { font-size: 13px; color: var(--maiv-text-strongest); margin-bottom: 16px; line-height: 1.5; }
        .maiv-confirm-domain { font-weight: bold; color: #2196f3; }
        .maiv-confirm-buttons { display: flex; gap: 8px; justify-content: flex-end; }
        .maiv-confirm-buttons button {
          padding: 6px 16px; border-radius: 4px; font-size: 12px; cursor: pointer; border: 1px solid var(--maiv-card-border);
        }
        .maiv-confirm-cancel { background: transparent; color: var(--maiv-text-secondary); }
        .maiv-confirm-ok { background: #2196f3; color: #fff; border-color: #2196f3; }
        .maiv-link-domain-list { font-size: 11px; margin-top: 6px; }
        .maiv-link-domain-item { padding: 2px 0; display: flex; align-items: center; gap: 6px; }
        .maiv-link-domain-match { color: var(--maiv-pass); }
        .maiv-link-domain-mismatch { color: var(--maiv-align-warn-text); }
        .maiv-link-domain-trusted { color: #2196f3; }
        /* リンクテキスト偽装の実際のリンク先ドメイン: 赤色太字で危険性を強調 */
        .maiv-link-domain-danger { color: var(--maiv-fail); font-weight: bold; }

      `;

      // --- コンテナ作成 ---
      const container = document.createElement("div");
      container.className = "maiv-container";

      // --- ヘッダーバッジとドメイン表示 ---
      // バッジ横のドメイン表示: 常にヘッダFromドメインを表示
      // 認証成功時は「このドメインが認証済み」の意味、
      // それ以外は「このドメインを名乗っているメール」と人間が判断する材料
      const headerDomainText = escapeHTML(envelope.headerFromDomain);
      let mailingListTag = "";

      // メーリングリスト経由の場合、ヘッダにタグを追加
      if (envelope.isMailingList) {
        mailingListTag = `<span class="maiv-mailing-list-tag">📋 ${escapeHTML(msg("mailingListVia"))}</span>`;
      }

      // --- 判定理由サマリー: バッジの横に該当する全理由をピルタグで表示 ---
      let verdictReasonHTML = "";
      if (!security.isSecure && security.verdictReasons.length > 0) {
        // 認証系 ("SPF: softfail" 等) はそのまま表示、その他はローカライズ
        const reasonLabelMap = {
          "spf_align_fail": msg("verdictReasonSpfAlign"),
          "dkim_align_fail": msg("verdictReasonDkimAlign"),
          "domain_not_aligned": msg("verdictReasonDomainMismatch"),
          "display_name_spoofed": msg("verdictReasonSpoofing"),
          "phishing_suspicious": msg("verdictReasonSuspicious")
        };
        const defaultReasonClass = (security.badgeClass === "danger" || security.badgeClass === "phishing") ? "reason-danger" : "reason-warning";
        // 認証ステータスの深刻度別色分け
        const softStatuses = new Set(["none", "softfail", "neutral"]);
        const tags = security.verdictReasons.map(r => {
          // 認証系は "SPF: softfail" のようにコロンを含む → そのまま表示
          const label = r.includes(":") ? r : (reasonLabelMap[r] || r);
          let tagClass = defaultReasonClass;
          if (r.includes(":")) {
            // 認証系タグ: ステータスに応じて色を変える
            const status = r.split(":")[1].trim().toLowerCase();
            tagClass = softStatuses.has(status) ? "reason-warning" : "reason-danger";
          }
          return `<span class="maiv-verdict-reason ${tagClass}">${escapeHTML(label)}</span>`;
        }).join("");
        verdictReasonHTML = `<span class="maiv-verdict-reasons-wrap">${tags}</span>`;
      }

      const headerHTML = `
        <div class="maiv-header" id="maiv-header-toggle" title="${escapeHTML(msg("toggleDetails"))}"
             aria-expanded="${security.shouldAutoExpand}" aria-controls="maiv-body-wrapper">
          <span class="maiv-badge ${security.badgeClass}">${security.badgeText}</span>
          <span class="maiv-header-domain">${headerDomainText}</span>
          ${mailingListTag}
          ${verdictReasonHTML}
          <span style="flex-grow:1;"></span>
          <span class="maiv-toggle-icon" id="maiv-toggle-icon" aria-hidden="true">▼</span>
        </div>
      `;

      // --- 認証カード生成ヘルパー ---
      const createAuthCard = (title, tooltip, data, detailHTML, expandedHTML, cardId) => {
        let icon = "❓";
        let sClass = "status-none";
        const displayStatus = data.status.toUpperCase();

        if (data.status === "pass") { icon = "✅"; sClass = "status-pass"; }
        else if (data.status === "fail") { icon = "❌"; sClass = "status-fail"; }
        else if (data.status === "softfail" || data.status === "neutral" || data.status === "none") { icon = "⚠️"; sClass = "status-none"; }
        else if (data.status === "temperror" || data.status === "permerror") { icon = "❌"; sClass = "status-fail"; }

        // authserv-id: ジャッジしたサーバのドメイン
        const authServLabel = authResults.authServId
          ? `<span style="color:var(--maiv-text-faint); font-size:10px; margin-left:4px;">(${escapeHTML(authResults.authServId)})</span>`
          : "";

        const hasExpanded = expandedHTML && expandedHTML.trim();
        return `
          <div class="maiv-card maiv-auth-card">
            <div class="maiv-card-title${hasExpanded ? ' maiv-collapsible' : ''}"${hasExpanded ? ` data-toggle="${cardId}"` : ''}
                 title="${escapeHTML(tooltip)}">${escapeHTML(title)}</div>
            <div class="maiv-status-row">
              <span class="maiv-status-icon">${icon}</span>
              <span class="${sClass}">${escapeHTML(displayStatus)}</span>
              ${authServLabel}
            </div>
            <div class="maiv-detail-text">${detailHTML}</div>
            ${hasExpanded ? `<div class="maiv-collapsible-body" id="${cardId}"><div class="maiv-expanded-detail">${expandedHTML}</div></div>` : ''}
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
        // SPF アライメント: SPF が pass の場合のみ表示
        // pass 以外のとき「不一致」を出すのは誤解を招くため非表示にする
        if (al && authResults.spf.status === "pass") {
          const icon = al.spfAligned ? "✅" : "❌";
          const cls = al.spfAligned ? "maiv-align-pass" : "maiv-align-fail";
          const label = al.spfAligned ? msg("alignedLabel") : msg("notAlignedLabel");
          parts.push(`<div class="maiv-align-item" style="margin-top:4px;">${icon} <span class="${cls}">${escapeHTML(msg("labelSpfAlign"))} ${escapeHTML(label)}</span></div>`);
        }
        return parts.join("<br>");
      })();

      // DKIM カード詳細: 集約ドメイン・個別署名結果・アライメントを表示
      const dkimDetailHTML = (() => {
        const sigs = authResults.dkim.signatures || [];
        const getOrgDomain = window.getOrganizationalDomain || ((d) => d);
        const headerOrgDomain = envelope.headerOrgDomain;
        const authServLabel = authResults.authServId
          ? `<span style="color:var(--maiv-text-faint); font-size:10px; margin-left:4px;">(${escapeHTML(authResults.authServId)})</span>`
          : "";

        if (sigs.length === 0 || !sigs.some(s => s.domain)) {
          const st = authResults.dkim.status;
          const emptyIcon = (st === "fail" || st === "permerror" || st === "temperror") ? "❌" : "⚠️";
          const emptyCls = (st === "fail" || st === "permerror" || st === "temperror") ? "status-fail" : "status-none";
          return `
            <div class="maiv-status-row">
              <span class="maiv-status-icon">${emptyIcon}</span>
              <span class="${emptyCls}">${escapeHTML(st.toUpperCase())}</span>
              ${authServLabel}
            </div>
          `;
        }

        let html = "";
        for (let i = 0; i < sigs.length; i++) {
          const sig = sigs[i];
          if (!sig.domain) continue;
          if (i > 0) html += `<div style="border-top:1px dashed var(--maiv-card-title-border); margin:6px 0;"></div>`;

          const icon = sig.status === "pass" ? "✅" : (sig.status === "fail" ? "❌" : "⚠️");
          const sClass = sig.status === "pass" ? "status-pass" : (sig.status === "fail" ? "status-fail" : "status-none");

          // ステータス行（SPFと同じ maiv-status-row）
          html += `<div class="maiv-status-row"><span class="maiv-status-icon">${icon}</span><span class="${sClass}">${escapeHTML(sig.status.toUpperCase())}</span>${authServLabel}</div>`;
          // ドメイン・セレクタ・アライメントをSPFと同じ maiv-detail-text 内に配置
          const parts = [];
          parts.push(`${escapeHTML(msg("labelDomain"))} ${escapeHTML(sig.domain)}`);
          if (sig.selector) {
            parts.push(`${escapeHTML(msg("labelSelector"))} ${escapeHTML(sig.selector)}`);
          }
          // アライメント（passした署名のみ）— SPFと同じくparts内に含めてmaiv-detail-textの11pxを適用
          if (sig.status === "pass") {
            const sigOrgDomain = getOrgDomain(sig.domain.toLowerCase());
            const aligned = (sigOrgDomain === headerOrgDomain);
            const alIcon = aligned ? "✅" : "❌";
            const alCls = aligned ? "maiv-align-pass" : "maiv-align-fail";
            const alLabel = aligned ? msg("alignedLabel") : msg("notAlignedLabel");
            parts.push(`<div class="maiv-align-item" style="margin-top:4px;">${alIcon} <span class="${alCls}">${escapeHTML(msg("labelDkimAlign"))} ${escapeHTML(alLabel)}</span></div>`);
          }
          html += `<div class="maiv-detail-text">${parts.join("<br>")}</div>`;
        }
        return html;
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
      // --- 展開時の全プロパティHTML生成 ---
      // Authentication-Results 生セグメントから全 key=value ペアを抽出して表示
      const renderPropRow = (key, val) => {
        if (!val && val !== 0) return "";
        return `<div class="maiv-prop-row"><span class="maiv-prop-key">${escapeHTML(key)}</span><span class="maiv-prop-val">${escapeHTML(String(val))}</span></div>`;
      };

      // 生セグメントから全プロパティを抽出するジェネリックパーサー
      // "spf=pass (reason text) smtp.mailfrom=x smtp.helo=y" → [{key, val}, ...]
      const parseSegmentProps = (segment) => {
        if (!segment) return [];
        const props = [];
        // 括弧内のテキストを reason として先に抽出
        const reasonMatch = segment.match(/\(([^)]+)\)/);
        if (reasonMatch) props.push({ key: "reason", val: reasonMatch[1] });
        // 括弧部分を除去してから key=value を抽出（括弧内の = による誤マッチを防止）
        const cleaned = segment.replace(/\([^)]*\)/g, '');
        // クォート値対応: key="value with = signs" or key=unquoted_value
        const propRegex = /([a-zA-Z][a-zA-Z0-9._-]*)="([^"]*)"|([a-zA-Z][a-zA-Z0-9._-]*)=([^;\s"]+)/g;
        let m;
        while ((m = propRegex.exec(cleaned)) !== null) {
          const key = m[1] || m[3];
          const val = m[2] !== undefined ? m[2] : m[4];
          if (/^(spf|dkim|dmarc|arc|bimi)$/i.test(key)) continue;
          props.push({ key, val });
        }
        return props;
      };

      // SPF 展開: 生セグメントから全プロパティ
      const spfExpandedHTML = (() => {
        const props = parseSegmentProps(authResults.spf.detail.rawSegment);
        return props.map(p => renderPropRow(p.key, p.val)).join("");
      })();

      // DKIM 展開: 各署名の生セグメントから全プロパティ（常にドメイン見出し付き）
      const dkimExpandedHTML = (() => {
        const sigs = authResults.dkim.signatures || [];
        if (sigs.length === 0 || !sigs.some(s => s.domain)) return "";
        let html = "";
        for (const sig of sigs) {
          html += `<div style="font-weight:bold; margin-top:4px; margin-bottom:2px; font-size:10px;">${escapeHTML(sig.domain || "unknown")} (${escapeHTML(sig.status)})</div>`;
          const props = parseSegmentProps(sig.segment);
          html += props.map(p => renderPropRow(p.key, p.val)).join("");
        }
        return html;
      })();

      // DMARC 展開: 括弧内のポリシーパラメータを個別抽出
      const dmarcExpandedHTML = (() => {
        const seg = authResults.dmarc.detail.rawSegment;
        if (!seg) return "";
        let html = "";
        // 括弧内からポリシーパラメータを個別抽出
        const parenMatch = seg.match(/\(([^)]+)\)/);
        if (parenMatch) {
          const inner = parenMatch[1];
          const pMatch = inner.match(/(?:^|[\s])p=([^\s)]+)/i);
          const spMatch = inner.match(/\bsp=([^\s)]+)/i);
          const disMatch = inner.match(/\bdis=([^\s)]+)/i);
          const pctMatch = inner.match(/\bpct=([^\s)]+)/i);
          if (pMatch) html += renderPropRow("p", pMatch[1]);
          if (spMatch) html += renderPropRow("sp", spMatch[1]);
          if (disMatch) html += renderPropRow("dis", disMatch[1]);
          if (pctMatch) html += renderPropRow("pct", pctMatch[1]);
        }
        // 括弧外の key=value（header.from 等）
        const cleaned = seg.replace(/\([^)]*\)/g, '');
        const propRegex = /([a-zA-Z][a-zA-Z0-9._-]*)="([^"]*)"|([a-zA-Z][a-zA-Z0-9._-]*)=([^;\s"]+)/g;
        let m;
        while ((m = propRegex.exec(cleaned)) !== null) {
          const key = m[1] || m[3];
          const val = m[2] !== undefined ? m[2] : m[4];
          if (/^(dmarc)$/i.test(key)) continue;
          html += renderPropRow(key, val);
        }
        return html;
      })();

      const spfCard = createAuthCard(msg("cardTitleSpf"), msg("tooltipSpf"), authResults.spf, spfDetailHTML, spfExpandedHTML, "maiv-spf-detail");

      // DKIM カード: 署名ごとにステータス・ドメイン・セレクタ・アライメントを表示（集約行なし）
      const dkimCard = (() => {
        const hasExpanded = dkimExpandedHTML && dkimExpandedHTML.trim();
        return `
          <div class="maiv-card maiv-auth-card">
            <div class="maiv-card-title${hasExpanded ? ' maiv-collapsible' : ''}"${hasExpanded ? ' data-toggle="maiv-dkim-detail"' : ''}
                 title="${escapeHTML(msg("tooltipDkim"))}">${escapeHTML(msg("cardTitleDkim"))}</div>
            ${dkimDetailHTML}
            ${hasExpanded ? `<div class="maiv-collapsible-body" id="maiv-dkim-detail"><div class="maiv-expanded-detail">${dkimExpandedHTML}</div></div>` : ''}
          </div>
        `;
      })();

      const dmarcCard = createAuthCard(msg("cardTitleDmarc"), msg("tooltipDmarc"), authResults.dmarc, dmarcDetailHTML, dmarcExpandedHTML, "maiv-dmarc-detail");

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
      } else if (envelope.isDomainAligned && (security.isSpfOk || security.isDkimOk)) {
        // ドメイン一致かつ認証も通っている場合はグリーン表示
        // （p=none等で総合判定がグリーンでなくても、認証自体は成功している）
        alignmentWarningHTML += `<div class="align-ok">${escapeHTML(msg("alignOk"))}</div>`;
      } else if (envelope.isDomainAligned) {
        // ドメインは一致しているが認証が通っていない
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

          // by ホスト名を表示用に整形
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

      // --- LINK SAFETY カード: フィッシング検知結果・リンクドメイン・リソースドメイン一覧（常時表示） ---
      const hasFindings = linkSafety && linkSafety.findings && linkSafety.findings.length > 0;
      const hasLinkDomains = linkSafety && linkSafety.linkDomains && linkSafety.linkDomains.size > 0;
      const hasResourceDomains = linkSafety && linkSafety.resourceDomains && linkSafety.resourceDomains.size > 0;

      let linkSafetyContentHTML = "";
      if (hasFindings || hasLinkDomains || hasResourceDomains) {
        let findingsHTML = "";
        if (hasFindings) {
          for (const f of linkSafety.findings) {
            const cls = f.level === "critical" ? "maiv-finding-critical" : "maiv-finding-suspicious";
            const icon = f.level === "critical" ? "🚨" : "⚠️";
            findingsHTML += `<div class="${cls}">${icon} ${escapeHTML(f.detail)}</div>`;
          }
        }

        // ドメイン一覧のレンダリングヘルパー
        // showTrust: trueの場合、リンク先相違検出時に限り不一致ドメインに「信頼」ボタンを表示
        const renderDomainList = (title, domains, deceptive, trackers, showTrust) => {
          if (!domains || domains.size === 0) return "";
          let items = "";
          const sorted = Array.from(domains.entries())
            .sort((a, b) => {
              const aD = deceptive && deceptive.has(a[0]) ? 2 : 0;
              const bD = deceptive && deceptive.has(b[0]) ? 2 : 0;
              const aM = a[1].matchesFrom ? 0 : 1;
              const bM = b[1].matchesFrom ? 0 : 1;
              return (bD + bM) - (aD + aM);
            });
          for (const [domain, info] of sorted) {
            let icon, cls;
            const isTrusted = trustedDomains && trustedDomains.has(domain);
            if (deceptive && deceptive.has(domain)) {
              icon = "💀"; cls = "maiv-link-domain-danger";
            } else if (info.matchesFrom) {
              icon = "✅"; cls = "maiv-link-domain-match";
            } else if (isTrusted) {
              icon = "🛡️"; cls = "maiv-link-domain-trusted";
            } else {
              icon = "⚠️"; cls = "maiv-link-domain-mismatch";
            }
            const trackerMark = trackers && trackers.has(domain) ? " 🕵️" : "";
            // 「信頼」ボタン: リンク先相違(💀)検出時のみ、未信頼かつ不一致ドメインに表示
            const trustBtn = (showTrust && hasFindings && !info.matchesFrom && !isTrusted)
              ? ` <button class="maiv-trust-btn" data-domain="${escapeHTML(domain)}">${escapeHTML(msg("trustDomainButton"))}</button>`
              : "";
            items += `<div class="maiv-link-domain-item">${icon} <span class="${cls}">${escapeHTML(domain)}</span>${trackerMark} <span style="color:var(--maiv-text-faint);">(×${info.count})</span>${trustBtn}</div>`;
          }
          return `
            <div class="maiv-link-domain-list">
              <div style="font-weight:bold; margin-bottom:4px; color:var(--maiv-text-secondary);">${escapeHTML(title)}</div>
              ${items}
            </div>
          `;
        };

        const deceptive = linkSafety.deceptiveDomains || new Set();
        const trackers = linkSafety.trackingPixelDomains || new Set();
        const linkListHTML = renderDomainList(msg("linkDomainListTitle"), linkSafety.linkDomains, deceptive, null, true);
        const resourceListHTML = renderDomainList(msg("resourceDomainListTitle"), linkSafety.resourceDomains, null, trackers, false);
        const domainListsHTML = linkListHTML + resourceListHTML;
        const hasDomainLists = domainListsHTML.trim().length > 0;

        // findings（critical/suspicious）があればドメイン一覧もデフォルト展開
        const expandDomains = hasFindings;
        const expandedCls = expandDomains ? " maiv-expanded" : "";

        linkSafetyContentHTML = findingsHTML +
          (hasDomainLists ? `<div class="maiv-collapsible-body${expandedCls}" id="maiv-link-safety-detail">${domainListsHTML}</div>` : "");
      } else {
        linkSafetyContentHTML = `<div class="maiv-empty-state">${escapeHTML(msg("labelNone"))}</div>`;
      }

      // ドメイン一覧がある場合はタイトルをトグル化、critical時はデフォルト展開
      const hasExpandableLinkSafety = (hasLinkDomains || hasResourceDomains);
      const linkSafetyExpandedCls = (hasExpandableLinkSafety && hasFindings) ? " maiv-expanded" : "";
      const linkSafetyHTML = `
        <div class="maiv-card">
          <div class="maiv-card-title${hasExpandableLinkSafety ? ' maiv-collapsible' + linkSafetyExpandedCls : ''}"${hasExpandableLinkSafety ? ' data-toggle="maiv-link-safety-detail"' : ''} title="${escapeHTML(msg("tooltipLinkSafety"))}">${escapeHTML(msg("cardTitleLinkSafety"))}</div>
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

      // マウスクリックによる開閉
      headerToggle.addEventListener('click', () => {
        togglePanel();
      });

      // --- カード内折りたたみセクションの開閉 ---
      // data-toggle 属性を持つ要素をクリックすると、対応するIDの折りたたみボディを開閉する
      container.addEventListener('click', (e) => {
        const toggler = e.target.closest('[data-toggle]');
        if (!toggler) return;
        // メインヘッダのクリックイベントと衝突しないよう、ヘッダ内のトグルは除外
        if (toggler.closest('#maiv-header-toggle')) return;
        const targetId = toggler.getAttribute('data-toggle');
        const target = container.querySelector('#' + targetId);
        if (!target) return;
        toggler.classList.toggle('maiv-expanded');
        target.classList.toggle('maiv-expanded');
      });

      // --- 「信頼」ボタン ---
      container.addEventListener('click', async (e) => {
        const btn = e.target.closest('.maiv-trust-btn');
        if (!btn) return;
        e.stopPropagation();
        const domain = btn.getAttribute('data-domain');
        if (!domain) return;

        // Shadow DOM内カスタム確認ダイアログ（DOM APIで構築）
        const confirmText = msg("trustDomainConfirm").replace("{domain}", domain);
        const overlay = document.createElement("div");
        overlay.className = "maiv-confirm-overlay";

        const box = document.createElement("div");
        box.className = "maiv-confirm-box";

        const textEl = document.createElement("div");
        textEl.className = "maiv-confirm-text";
        textEl.textContent = confirmText;

        const buttons = document.createElement("div");
        buttons.className = "maiv-confirm-buttons";

        const cancelBtn = document.createElement("button");
        cancelBtn.className = "maiv-confirm-cancel";
        cancelBtn.textContent = "Cancel";

        const okBtn = document.createElement("button");
        okBtn.className = "maiv-confirm-ok";
        okBtn.textContent = "OK";

        buttons.appendChild(cancelBtn);
        buttons.appendChild(okBtn);
        box.appendChild(textEl);
        box.appendChild(buttons);
        overlay.appendChild(box);
        container.appendChild(overlay);

        const result = await new Promise(resolve => {
          okBtn.addEventListener('click', () => resolve(true));
          cancelBtn.addEventListener('click', () => resolve(false));
          overlay.addEventListener('click', (ev) => { if (ev.target === overlay) resolve(false); });
        });
        overlay.remove();
        if (!result) return;

        try {
          const stored = await browser.storage.local.get("trustedDomains");
          const list = stored.trustedDomains || [];
          if (!list.includes(domain)) {
            list.push(domain);
            await browser.storage.local.set({ trustedDomains: list });
          }
          btn.textContent = msg("trustDomainAdded");
          btn.disabled = true;
          btn.style.opacity = "0.5";
        } catch (err) {
          console.error("MailAuthInfoViewer: Failed to save trusted domain", err);
        }
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

    // ■ 信頼済みドメインのホワイトリスト読み込み
    let trustedDomains = new Set();
    try {
      const stored = await browser.storage.local.get("trustedDomains");
      if (stored.trustedDomains && Array.isArray(stored.trustedDomains)) {
        trustedDomains = new Set(stored.trustedDomains);
      }
    } catch { /* storage未対応環境ではスキップ */ }

    const envelope = parseEnvelope(fullMsg, headers, msgHeader);
    const authResults = parseAuthResults(headers, envelope);
    const routeHops = parseRoute(headers);
    const arcChain = parseArcChain(headers);
    const bodyContent = parseMessageBody(fullMsg);
    const linkSafety = analyzeLinkSafety(bodyContent, envelope.headerOrgDomain, trustedDomains);
    const security = determineSecurityStatus(authResults, envelope.isDomainAligned, envelope.envelopeFrom, envelope.isDisplayNameSpoofed, linkSafety);

    buildUI(envelope, authResults, routeHops, security, arcChain, linkSafety, trustedDomains);

  } catch (e) {
    console.error("MailAuthInfoViewer Error:", e);
  }
})();
