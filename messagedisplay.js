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
    // 既知の電子メール匿名化・転送（リレー）サービスのドメイン
    // =========================================================
    // これらのサービスはユーザーの実アドレスを隠蔽するため、
    // 元送信者の身元を「表示名」に保持しつつ、別ドメインの匿名アドレスから配信する。
    // 例: From: "original@sender.com [via Relay]" <random@mozmail.com>
    // 表示名と実アドレスのドメインが意図的に異なるため、なりすまし検知の対象外とする。
    const EMAIL_RELAY_DOMAINS = new Set([
      "mozmail.com",              // Firefox Relay
      "relay.firefox.com",        // Firefox Relay (legacy)
      "duck.com",                 // DuckDuckGo Email Protection
      "privaterelay.appleid.com", // Apple Hide My Email
      "simplelogin.com",          // SimpleLogin
      "simplelogin.fr",
      "simplelogin.co",
      "slmail.me",
      "aleeas.com",
      "anonaddy.com",             // AnonAddy / addy.io
      "anonaddy.me",
      "addy.io",
      "forwardemail.net",         // Forward Email
      "33mail.com",               // 33Mail
      "spamgourmet.com",          // SpamGourmet
    ]);

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

      // "Display Name <user@domain.com>" の形式をパース（末尾の <...> を採用）
      // 複数の角括弧がある場合は最後のものが正規アドレスと判断する
      const matches = Array.from(headerFromRaw.matchAll(/<([^>]+)>/g));
      if (matches.length > 0) {
        const lastMatch = matches[matches.length - 1];
        headerFromAddress = lastMatch[1].trim();
        headerFromName = headerFromRaw.substring(0, lastMatch.index).trim().replace(/"/g, '').trim();
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

      // ■ メール匿名化/転送サービス経由かを判定
      // Firefox Relay 等のリレーサービスは、元送信者の身元を表示名に残しつつ、
      // 配信は別ドメインの匿名アドレスから行う。表示名と実アドレスの
      // ドメイン不一致が「正規の挙動」となるため、なりすまし検知を抑制する必要がある。
      const isEmailRelay = EMAIL_RELAY_DOMAINS.has(headerOrgDomain);

      // ■ 表示名なりすまし検知
      // 攻撃者が表示名にメールアドレスを埋め込み、受信者を欺く手口を検知する。
      // 例: From: "support@amazon.co.jp" <evil@attacker.com>
      // 表示名内のアドレスのドメインと実際のHeader Fromドメインを組織ドメインレベルで比較し、
      // 不一致の場合はなりすましの疑いとして警告フラグを立てる。
      // 実アドレスが既知のメールリレーサービスのドメインの場合は、転送パターンとして警告対象外。
      let isDisplayNameSpoofed = false;
      if (headerFromName && !isEmailRelay) {
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
      // ※ メールリレーサービス経由の場合、Reply-To に元送信者を設定するのが通常のため除外
      let isReplyToMismatch = false;
      let replyToAddress = "";
      const replyToRaw = headers["reply-to"]?.[0] || "";
      if (replyToRaw && !isEmailRelay) {
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

      // ■ コメント括弧を考慮したセミコロン分割ヘルパー
      // RFC 8601 では Authentication-Results 中の "(...)" はコメントであり、
      // 括弧内に含まれるセミコロンは構文上のセパレータではない。
      // 例: dkim=pass (2048-bit key; unprotected) header.d=example.com
      //   このようなコメント付き結果を素朴に ';' で分割すると、
      //   "dkim=pass (2048-bit key" と " unprotected) header.d=..." に
      //   分断され、header.d 等の属性が後続セグメントに紛れ込んで
      //   ドメイン抽出やアライメント評価が誤った結果になる。
      // そのため括弧の対応をネストで追いつつトップレベルのセミコロンだけで
      // 分割する専用関数を用いる。
      const splitOnTopLevelSemicolons = (str) => {
        if (!str) return [];
        const result = [];
        let depth = 0;
        let current = "";
        for (let i = 0; i < str.length; i++) {
          const ch = str[i];
          if (ch === '(') {
            depth++;
            current += ch;
          } else if (ch === ')') {
            if (depth > 0) depth--;
            current += ch;
          } else if (ch === ';' && depth === 0) {
            result.push(current);
            current = "";
          } else {
            current += ch;
          }
        }
        // 最後のセグメント（末尾セミコロンがない場合の残り）も含める
        result.push(current);
        return result;
      };

      const getLastReceivedBy = () => {
        const received = headers["received"] || [];
        if (received.length === 0) return "";

        // authserv-id 照合に使う「信頼する受信ホスト」を求める。
        // 単純に received[0] の by を採るだけでは、受信プロバイダの構成によって
        // 「最終配送ホップ ≠ 認証（Authentication-Results 付与）ホスト」となり、
        // 正規の A-R が authserv-id 不一致で破棄されてしまう。代表的な2パターン:
        //   - Gmail / Google Workspace: 最上段に内部ハンドオフ
        //       Received: by 2002:<IPv6> with SMTP id ...
        //     を積む（by が IP リテラルで authserv-id になり得ない）。
        //   - Fastmail (messagingengine.com): Cyrus LMTP の内部ホスト
        //       Received: ... by slotpiXXmYY (Cyrus ...) with LMTPA
        //     が最終配送だが、認証は phl-mx-NN.messagingengine.com が実施し
        //     A-R を付与する。間に *.internal / localhost の内部ホップが挟まる。
        // そこで以下の優先順で境界 MTA（=authserv 発行ホスト）を特定する。

        const extractBy = (line) => {
          const m = line.match(/\bby\s+([^\s;]+)/i);
          return m ? m[1].toLowerCase().replace(/^\[|\]$/g, "") : "";
        };
        const isIpLiteral = (h) => isIPv4Like(h) || isIPv6Like(h);
        // 公開到達可能な実 FQDN か（ドットを含み、IP リテラルでも内部/予約
        // ホスト名でもない）。.internal/.local 等や単一ラベル名・localhost を除外する。
        const isPublicFqdn = (h) =>
          !!h && h.includes(".") && !isIpLiteral(h) && h !== "localhost" &&
          !/\.(internal|local|lan|intranet|localdomain|home\.arpa)$/.test(h);

        // 優先1: 外部（公開 IP）から受信した最初のホップ＝境界 MTA。その by を採用。
        // 内部配送ホップ（private IP / localhost / from 無し）はこの段で自然に飛ぶ。
        // 単一ラベル名の受信ホストでも、公開 IP から受信していれば正しく採用される。
        for (const line of received) {
          const fromMatch = line.match(/\bfrom\s+(.+?)(?=\s+by\s+|;|$)/i);
          const fromIP = extractIPFromReceived(fromMatch ? fromMatch[1] : "");
          if (fromIP && !isPrivateIP(fromIP)) {
            const by = extractBy(line);
            if (by && !isIpLiteral(by)) return by;
            break; // 境界は見つかったが by が使えない → 後段へ
          }
        }

        // 優先2: 公開 IP からの受信ホップが無い場合（自己送信や全内部経路）。
        // 先頭から最初の実 FQDN の by を採用する。Fastmail の自己送信のように
        // slotpiXX（単一ラベル）・*.internal・localhost ばかりの経路でも、
        // 認証ホスト phl-mx-NN.messagingengine.com に正しく当てられる。
        for (const line of received) {
          const by = extractBy(line);
          if (isPublicFqdn(by)) return by;
        }

        // 優先3: いずれも該当しなければ従来どおり received[0] の by を返す。
        return extractBy(received[0]);
      };

      const filterByAuthServId = (authResultHeaders, trustedHost) => {
        if (!trustedHost || authResultHeaders.length === 0) return authResultHeaders;

        const trusted = authResultHeaders.filter(h => {
          // authserv-id はヘッダの先頭（最初のセミコロンの前）に記載される
          // コメント括弧内のセミコロンを誤って境界と認識しないようヘルパーを利用する
          const authServId = splitOnTopLevelSemicolons(h)[0].trim().toLowerCase();
          // 完全一致、またはサブドメイン関係を許容
          return authServId === trustedHost ||
                 authServId.endsWith("." + trustedHost) ||
                 trustedHost.endsWith("." + authServId);
        });

        // マッチするものがなければ空配列を返す（判定に使わない）
        // 不一致時にすべてのA-Rを信頼するのはセキュリティ上の危険
        return trusted;
      };

      const lastReceivedBy = getLastReceivedBy();
      const regularAuth = headers["authentication-results"] || [];

      // 通常の Authentication-Results のみ authserv-id でフィルタリング
      // ARC-Authentication-Results は暗号学的検証なしでは偽造可能なため、
      // 本判定からは除外し、ARC カード表示（parseArcChain）のみで利用する
      const trustedRegular = filterByAuthServId(regularAuth, lastReceivedBy);
      const authHeaders = trustedRegular;

      // セミコロンで区切ってメソッド単位に分割し、認証タイプのステータスを抽出
      // 分割は splitOnTopLevelSemicolons を用い、コメント括弧内のセミコロンを保護する。
      // 任意のヘッダ群を対象に取れるよう汎用化し、信頼済み A-R 以外
      // （authserv-id 不一致で除外したものや ARC-AR）の報告値抽出にも再利用する。
      const statusFromHeaderList = (headerList, type) => {
        const regex = new RegExp(`\\b${type}\\s*=\\s*([a-zA-Z0-9]+)`, "i");
        for (const h of headerList) {
          const methods = splitOnTopLevelSemicolons(h).slice(1);
          for (const m of methods) {
            const match = m.match(regex);
            if (match) return match[1].toLowerCase();
          }
        }
        return "none";
      };
      const parseAuthStatus = (type) => statusFromHeaderList(authHeaders, type);

      // ■ 複数 DKIM 署名への対応
      // メールによっては複数の DKIM 署名があり、一部は pass・一部は fail のことがある。
      // 全結果を個別に収集し、集約ステータスと署名ごとの結果リストの両方を返す。
      const parseDkimResults = () => {
        const results = [];
        // 重複排除用: "status|domain" の組み合わせを記録
        const seen = new Set();

        for (const h of authHeaders) {
          // コメント括弧 "(2048-bit key; unprotected)" 等に含まれるセミコロンを
          // 境界として扱わないため splitOnTopLevelSemicolons を使う。
          // これにより header.d= 等の属性がセグメントから漏れない。
          const methods = splitOnTopLevelSemicolons(h).slice(1);
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
            const methods = splitOnTopLevelSemicolons(h).slice(1);
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
            const methods = splitOnTopLevelSemicolons(h).slice(1);
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
            const methods = splitOnTopLevelSemicolons(h).slice(1);
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

      // ■ 認証強度の弱さ検出
      // 認証が pass していても、送信側の努力で解決できる設定上の弱さがあれば
      // 警告対象とする（設計思想: グリーン＝何もしなくて安全）。
      // ただしバッジ判定には影響させず、各カード内の警告表示のみに使う
      // （DMARC p=none の赤色表示と同じ位置づけ）。
      const detectStrengthWarnings = () => {
        const dkimWarnings = [];
        const dmarcWarnings = [];

        // --- DKIM-Signature ヘッダの署名タグ検査 ---
        // a=rsa-sha1: 衝突攻撃が現実的な非推奨アルゴリズム（RFC 8301 で禁止）
        // l= タグ:    本文の先頭 N バイトのみ署名するため、署名検証を保ったまま
        //             本文末尾へのコンテンツ追記を許してしまう既知の弱点
        const dkimSigHeaders = headers["dkim-signature"] || [];
        const seenWeakAlgo = new Set();
        const seenLimitedScope = new Set();
        for (const sigHeader of dkimSigHeaders) {
          const dMatch = sigHeader.match(/(?:^|[;\s])d=([^;\s]+)/i);
          const sigDomain = dMatch ? dMatch[1].trim() : "";

          const aMatch = sigHeader.match(/(?:^|[;\s])a=([a-zA-Z0-9-]+)/i);
          if (aMatch && aMatch[1].toLowerCase() === "rsa-sha1" && !seenWeakAlgo.has(sigDomain)) {
            seenWeakAlgo.add(sigDomain);
            dkimWarnings.push({ type: "weak_algorithm", domain: sigDomain, value: "rsa-sha1" });
          }

          const lMatch = sigHeader.match(/(?:^|[;\s])l=(\d+)/i);
          if (lMatch && !seenLimitedScope.has(sigDomain)) {
            seenLimitedScope.add(sigDomain);
            dkimWarnings.push({ type: "limited_scope", domain: sigDomain, value: `l=${lMatch[1]}` });
          }
        }

        // --- DKIM 鍵長検査 ---
        // 鍵長は DKIM-Signature には現れないが、受信側 MTA が
        // Authentication-Results のコメントに "(1024-bit key; ...)" の形で
        // 記録することがある（Gmail 等）。記録がある場合のみ判定する。
        // 注意: Ed25519 署名（RFC 8463）は 256 ビットでも安全なため、
        // 512 ビット未満の表記や ed25519 の言及がある場合は RSA とみなさず警告しない
        const seenWeakKey = new Set();
        for (const sig of dkimResult.results) {
          const segment = sig.segment || "";
          if (/ed25519/i.test(segment)) continue;
          const bitsMatch = segment.match(/(\d{3,5})-bit/i);
          if (bitsMatch) {
            const bits = parseInt(bitsMatch[1], 10);
            if (bits >= 512 && bits < 2048 && !seenWeakKey.has(sig.domain)) {
              seenWeakKey.add(sig.domain);
              dkimWarnings.push({ type: "weak_key", domain: sig.domain, value: `${bits}-bit` });
            }
          }
        }

        // --- DMARC ポリシーパラメータ検査 ---
        // sp= / pct= は DNS 由来の値だが、受信側 MTA が A-R のコメントに
        // "(p=REJECT sp=NONE dis=NONE)" の形で記録した場合のみ判定可能。
        const dmarcSegment = dmarcDetail.rawSegment || "";
        // sp=none: 本ドメインのポリシーが強くてもサブドメインが無防備になる穴。
        // p=none の場合は既存のポリシー赤色表示が同じ問題を示すため重複警告しない
        const spMatch = dmarcSegment.match(/\bsp=([a-zA-Z]+)/i);
        if (spMatch && spMatch[1].toLowerCase() === "none" && dmarcDetail.policy && dmarcDetail.policy !== "none") {
          dmarcWarnings.push({ type: "weak_sp", value: "sp=none" });
        }
        // pct<100: ポリシーが一部のメールにしか適用されない部分施行状態
        const pctMatch = dmarcSegment.match(/\bpct=(\d+)/i);
        if (pctMatch && parseInt(pctMatch[1], 10) < 100) {
          dmarcWarnings.push({ type: "limited_pct", value: `pct=${pctMatch[1]}` });
        }

        return { dkim: dkimWarnings, dmarc: dmarcWarnings };
      };
      const strength = detectStrengthWarnings();

      // ■ 信頼できないソースからの報告値（判定には一切用いない・断り書き表示用）
      // ある方式の信頼済み判定が none のとき、次の「信頼しないソース」に結果が
      // あれば、それを「受信サーバの報告値（未検証）」として控えめに surface する。
      //   ① authserv-id 不一致で除外した標準 Authentication-Results
      //   ② ARC-Authentication-Results（暗号検証不能・偽造可能なため判定外）
      // 設計思想（グリーン昇格は保守的に）を守るため、これらはバッジ・カード判定に
      // 影響させず、ヘッダのピル＋ツールチップで情報提供するに留める。
      const buildReportedUnverified = () => {
        const result = { spf: null, dkim: null, dmarc: null, fromUnmatchedAR: false, fromArc: false, any: false };
        // authserv-id 不一致で信頼対象から外れた標準 A-R
        const untrustedRegular = regularAuth.filter(h => !trustedRegular.includes(h));
        const arcAuthHeaders = headers["arc-authentication-results"] || [];
        const trustedStatus = { spf: spfStatus, dkim: dkimResult.aggregated, dmarc: dmarcStatus };
        for (const type of ["spf", "dkim", "dmarc"]) {
          // 信頼済み判定で結果が出ている方式は報告不要（重複・矛盾の糊塗を避ける）
          if (trustedStatus[type] && trustedStatus[type] !== "none") continue;
          // ①不一致だった標準 A-R を優先、無ければ②ARC-AR
          let status = statusFromHeaderList(untrustedRegular, type);
          let viaAR = status !== "none";
          if (!viaAR) status = statusFromHeaderList(arcAuthHeaders, type);
          if (status === "none") continue;
          result[type] = status;
          if (viaAR) result.fromUnmatchedAR = true; else result.fromArc = true;
          result.any = true;
        }
        return result;
      };
      const reportedUnverified = buildReportedUnverified();

      return {
        authServId: trustedRegular.length > 0
          ? splitOnTopLevelSemicolons(trustedRegular[0])[0].trim()
          : lastReceivedBy,
        spf: { status: spfStatus, detail: spfDetail },
        dkim: { status: dkimResult.aggregated, detail: dkimDetail, signatures: dkimResult.results },
        dmarc: { status: dmarcStatus, detail: dmarcDetail },
        alignment,
        strength,
        reportedUnverified
      };
    };

    // =========================================================
    // 3. parseRoute - 送達経路 (Receivedヘッダ) の解析
    // =========================================================
    const parseRoute = (headers) => {
      // Receivedヘッダは「新しい順(受信側→送信元)」で記録されるため、
      // reverse()を用いて「時系列順(送信元→受信側)」に並び替えて処理する
      const rawReceived = headers["received"] || [];

      // ■ ホップごとの TLS / 暗号化状態の抽出
      // Received ヘッダの記載は受信側 MTA が書くため改ざんは可能だが、
      // 送達経路自体と同じ信頼レベルの参考情報として可視化する。
      // 対応フォーマット例:
      //   Gmail / Microsoft: "(version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 ...)"
      //   Postfix:           "(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 ...)"
      //   プロトコル名:       "with ESMTPS" / "with ESMTPSA"（TLSあり）、
      //                      "with SMTP" / "with ESMTP"（TLSの記録なし）
      const parseTlsInfo = (line) => {
        // バージョン表記の正規化: "TLS1_3" / "TLSv1.3" / "TLS 1.3" → "TLS 1.3"
        const normalizeVersion = (v) => {
          const m = v.match(/(\d+)[._](\d+)/);
          return m ? `TLS ${m[1]}.${m[2]}` : `TLS ${v}`;
        };

        let version = "";
        const versionMatch = line.match(/\bversion=TLS[v_ ]?([\d._]+)/i) ||
                             line.match(/\busing\s+TLSv?([\d.]+)/i) ||
                             line.match(/\bTLSv?(1[._][0-3])\b/);
        if (versionMatch) version = normalizeVersion(versionMatch[1]);

        let cipher = "";
        const cipherMatch = line.match(/\bcipher[= ]([A-Za-z0-9_-]+)/i);
        if (cipherMatch) cipher = cipherMatch[1];

        // with 句のプロトコル名から暗号化有無を推定
        const withMatch = line.match(/\bwith\s+([A-Za-z]+)/);
        const proto = withMatch ? withMatch[1].toUpperCase() : "";
        const tlsProto = /^(ESMTPS|ESMTPSA|SMTPS|UTF8SMTPS|UTF8SMTPSA)$/.test(proto);
        const plainProto = /^(SMTP|ESMTP|ESMTPA|UTF8SMTP|UTF8SMTPA)$/.test(proto);

        // encrypted: true=TLS記録あり / false=平文プロトコル表記でTLS記録なし /
        //            null=判定材料なし（内部配送・with句なし等）
        let encrypted = null;
        if (version || tlsProto) encrypted = true;
        else if (plainProto) encrypted = false;

        return { encrypted, version, cipher };
      };

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
          tls: parseTlsInfo(line),
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
    // メール本文のHTML/テキストを解析し、フィッシングの特徴や未信頼ドメイン、
    // プライバシー上の注意点を検出する。
    // findings の level は深刻度と解決手段で4段階に分類される:
    //   [critical]  リンクテキスト偽装、javascript:/data: URI、HTMLフォーム埋め込み
    //               → 明確なフィッシングの兆候。ホワイトリスト対象外。
    //   [suspicious] IPアドレスリンク、IDNホモグラフ、URLショートナー
    //               → リンク先そのものが怪しい書式。ホワイトリスト対象外。
    //   [untrusted]  全リンク外部ドメイン、最大CTAが外部ドメイン
    //               → ドメインが未知なだけ。信頼リスト追加で解消する。
    //   [privacy]    トラッキングピクセル
    //               → プライバシー上の注意喚起。フィッシングではない。
    //   [info]       リンクドメイン一覧、リソースドメイン一覧
    const analyzeLinkSafety = (bodyContent, headerOrgDomain, trustedDomains) => {
      const findings = [];   // { level: "critical"|"suspicious"|"untrusted"|"privacy"|"info", type, detail }
      const linkDomains = new Map(); // domain → { count, matchesFrom }
      const resourceDomains = new Map(); // domain → { count, matchesFrom } (画像等の外部リソース)
      const deceptiveDomains = new Set(); // リンクテキスト偽装の実際のリンク先組織ドメイン
      // untrusted レベルの findings から参照される、未信頼かつ Header From と不一致の外部リンクドメイン集合
      // findings 行からワンクリック信頼を行う際の対象ドメイン解決に使用する
      const externalLinkDomains = new Set();

      // フィッシングで多用される URL ショートナーサービスのドメインリスト
      const URL_SHORTENERS = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "bl.ink", "rb.gy", "cutt.ly", "shorturl.at",
        "tiny.cc", "lnkd.in", "surl.li", "rebrand.ly", "v.gd", "qr.ae",
        "bc.vc", "yourls.org"
      ];

      if (!bodyContent) return { findings, linkDomains, resourceDomains, deceptiveDomains, trackingPixelDomains: new Set(), externalLinkDomains };

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

      // 重複の集約用: 同じ type のドメイン/IPを集めてから1つの finding にまとめる
      // これにより同種の警告が大量に並ぶ肥大化を防ぐ
      const ipAddressLinks = new Set();
      const idnHomographLinks = new Set();
      const urlShortenerLinks = new Set();

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
            // リンクテキスト偽装（critical）は信頼リスト対象外
            // ドメイン信頼性とは無関係に、表示テキストと実リンク先が異なる場合は必ず警告
            findings.push({
              level: "critical",
              type: "deceptive_text",
              detail: msg("linkDeceptiveText"),
              targetDomain: hrefOrgDomain
            });
            deceptiveDomains.add(hrefOrgDomain);
          }
        }

        // --- 項目4: IPアドレス直指定リンク検知 ---
        // 同一ホストの重複は集約する
        if (isIPv4Like(linkHost) || isIPv6Like(linkHost) || linkHost.startsWith("[")) {
          ipAddressLinks.add(linkHost);
        }

        // --- 項目5: IDNホモグラフ攻撃検知 ---
        if (linkHost.includes("xn--")) {
          idnHomographLinks.add(linkHost);
        }

        // --- 項目6: URLショートナー検知 ---
        const linkOrgDomain = getOrgDomain(linkHost);
        if (URL_SHORTENERS.some(s => linkHost === s || linkHost.endsWith("." + s))) {
          urlShortenerLinks.add(linkHost);
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

      // 重複集約された ip/idn/shortener の findings を生成
      // 同種が複数ある場合は detail 末尾に "(host1, host2, +N more)" 形式で集約表示する
      // 表示上の最大件数は 3 までとし、超過分は "+N more" でまとめる
      const formatAggregated = (set) => {
        const arr = Array.from(set);
        if (arr.length === 0) return "";
        const shown = arr.slice(0, 3).map(escapeHTML).join(", ");
        const extra = arr.length > 3 ? `, +${arr.length - 3} more` : "";
        return `(${shown}${extra})`;
      };
      if (ipAddressLinks.size > 0) {
        findings.push({
          level: "suspicious",
          type: "ip_address_link",
          detail: msg("linkIpAddress") + " " + formatAggregated(ipAddressLinks)
        });
      }
      if (idnHomographLinks.size > 0) {
        findings.push({
          level: "suspicious",
          type: "idn_homograph",
          detail: msg("linkIdnHomograph") + " " + formatAggregated(idnHomographLinks)
        });
      }
      if (urlShortenerLinks.size > 0) {
        findings.push({
          level: "suspicious",
          type: "url_shortener",
          detail: msg("linkShortener") + " " + formatAggregated(urlShortenerLinks)
        });
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

      // ■ すべてのリンクが外部ドメイン → 未信頼レベル
      // HTMLメール: 全 <a> リンクのドメインがHeader Fromと無関係（信頼済みドメインは除外）
      // テキストメール: 全URLのドメインがHeader Fromと無関係（信頼済みドメインは除外）
      // untrusted レベルはユーザーが信頼リストに追加すれば解消するため、
      // 攻撃の兆候を示す "suspicious" とは区別して扱う。
      const isHtml = /<[a-z][\s\S]*>/i.test(bodyContent);
      const isSafeLink = (l) => l.matchesFrom || (trustedDomains && trustedDomains.has(l.orgDomain));
      let hasAllExternalWarning = false;
      if (isHtml && linkInfos.length > 0 && !linkInfos.some(isSafeLink)) {
        findings.push({ level: "untrusted", type: "all_links_external", detail: msg("linkAllExternalUntrusted") });
        hasAllExternalWarning = true;
        // 対象の外部ドメインを externalLinkDomains に収集
        for (const l of linkInfos) {
          if (!l.matchesFrom && !(trustedDomains && trustedDomains.has(l.orgDomain))) {
            externalLinkDomains.add(l.orgDomain);
          }
        }
      } else if (!isHtml && textUrls.length > 0 && !textUrls.some(isSafeLink)) {
        findings.push({ level: "untrusted", type: "all_links_external", detail: msg("linkAllExternalUntrusted") });
        hasAllExternalWarning = true;
        for (const l of textUrls) {
          if (!l.matchesFrom && !(trustedDomains && trustedDomains.has(l.orgDomain))) {
            externalLinkDomains.add(l.orgDomain);
          }
        }
      }

      // ■ 最大CTAリンクが外部ドメイン → 未信頼レベル
      // メール内で最も目立つクリック領域（推定面積最大）のリンク先が送信者ドメインと異なる場合
      // 全リンク外部警告が出ている場合は冗長なので省略
      if (!hasAllExternalWarning && linkInfos.length > 0) {
        const largestCta = linkInfos.reduce((max, cur) => cur.estimatedArea > max.estimatedArea ? cur : max);
        if (!isSafeLink(largestCta)) {
          findings.push({ level: "untrusted", type: "cta_external", detail: msg("linkCtaExternalUntrusted") });
          externalLinkDomains.add(largestCta.orgDomain);
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

      // トラッキングピクセルが検出された場合は privacy レベルとして情報提供
      // プライバシー上の注意喚起であり、フィッシング指標ではない。グリーン判定は阻害しない。
      if (trackingPixelCount > 0) {
        findings.push({
          level: "privacy",
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

      return { findings: uniqueFindings, linkDomains, resourceDomains, deceptiveDomains, trackingPixelDomains, externalLinkDomains };
    };

    // =========================================================
    // 7. determineSecurityStatus - 総合的なセキュリティ判定
    // =========================================================
    // 認証結果・アライメント・フィッシング指標を総合し、バッジ色と判定理由を決定する。
    // グリーン条件:
    //   SPF pass, DKIM pass, DMARC pass (policy ≠ none),
    //   DMARCアライメント成立, 表示名なりすましなし,
    //   critical/suspicious/untrusted のいずれのリンク指標もなし
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

      // ■ リンク系指標の集約 (4レベル)
      // critical:   確度の高いフィッシング指標。専用バッジへ昇格。
      // suspicious: ドメインや書式そのものが怪しいが、ホワイトリスト対象外のため
      //             警告として扱う（グリーン阻害）。
      // untrusted:  未信頼外部ドメインなだけで、信頼リスト追加で解消する。
      //             思想に従いユーザーが信頼表明するまでグリーンにはしない（阻害あり）。
      // privacy:    トラッキングピクセル等のプライバシー注意。グリーン阻害なし。
      const hasCriticalPhishing = linkSafety?.findings?.some(f => f.level === "critical") || false;
      const hasSuspiciousLink = linkSafety?.findings?.some(f => f.level === "suspicious") || false;
      const hasUntrustedLink = linkSafety?.findings?.some(f => f.level === "untrusted") || false;
      // privacy レベル（トラッキングピクセル等）は判定に影響しない

      // ■ 判定理由の収集: グリーンでない全理由を記録
      // 認証系は実ステータスを含め、アライメントはpassかつ不成立の場合のみ記録
      const verdictReasons = [];

      // ■ 総合判定
      // DMARCがpassかつアライメント成立していれば、エンベロープドメイン不一致はグリーンを阻害しない
      // （SendGrid等の正当な外部配信サービス利用パターンに対応）
      const domainCheckOk = isDmarcOk && isDmarcAligned ? true : isDomainAligned;

      const isSecure = isSpfOk && isDkimOk && isDmarcOk &&
                       domainCheckOk && isDmarcAligned &&
                       !isDisplayNameSpoofed && !hasCriticalPhishing &&
                       !hasSuspiciousLink && !hasUntrustedLink;

      // 認証系: pass 以外なら実際のステータスを記録 (例: "SPF: softfail")
      if (!isSpfOk) verdictReasons.push(`SPF: ${authResults.spf.status}`);
      if (!isDkimOk) verdictReasons.push(`DKIM: ${authResults.dkim.status}`);
      if (!isDmarcOk) verdictReasons.push(`DMARC: ${authResults.dmarc.status}`);
      // アライメント: 認証が pass しているのにアライメント不成立の場合のみ表示
      // ただし DMARC pass かつ DMARC アライメント成立（SPF/DKIMの片方が成立）の場合は、
      // もう片方の個別アライメント失敗は DMARC 上問題ないため非表示にする。
      // 例: Sailthru等のバルク配信で d=service.com、SPF が brand.com で aligned のケース。
      const dmarcOverallOk = isDmarcOk && isDmarcAligned;
      if (!dmarcOverallOk && isSpfOk && !al.spfAligned) verdictReasons.push("spf_align_fail");
      if (!dmarcOverallOk && isDkimOk && !al.dkimAligned) verdictReasons.push("dkim_align_fail");
      if (!domainCheckOk) verdictReasons.push("domain_not_aligned");
      if (isDisplayNameSpoofed) verdictReasons.push("display_name_spoofed");
      // phishing_critical はバッジ自体が「💀 フィッシング検出」になるため判定理由には含めない
      // privacy（トラッキングピクセル）は判定理由タグに出さず、リンク安全性カード内で情報提供
      if (hasSuspiciousLink) verdictReasons.push("phishing_suspicious");
      if (hasUntrustedLink) verdictReasons.push("link_untrusted");

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
        hasUntrustedLink,
        verdictReasons,
        badgeClass,
        badgeText,
        shouldAutoExpand: false
      };
    };

    // =========================================================
    // 8. buildUI - UI構築 (HTML/CSS) — Shadow DOM・i18n・ダークモード完全対応
    // =========================================================
    const buildUI = (envelope, authResults, routeHops, security, arcChain, linkSafety, trustedDomains, compactMode) => {

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
          /* 未信頼ドメイン（untrusted）: 既存 warn 系を流用 */
          --maiv-untrusted-bg: #fff8e1;
          --maiv-untrusted-text: #b27300;
          /* プライバシー注意（privacy）: 控えめな青灰色系（情報提供ニュアンス） */
          --maiv-privacy-bg: #eceff1;
          --maiv-privacy-text: #455a64;
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
            /* 未信頼・プライバシーのダークモード対応 */
            --maiv-untrusted-bg: #3a2e00;
            --maiv-untrusted-text: #ffd54f;
            --maiv-privacy-bg: #2a3238;
            --maiv-privacy-text: #b0bec5;
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
        /* 未信頼リンクの判定理由タグ: 警告より一段控えめな配色 */
        .maiv-verdict-reason.reason-untrusted {
          background-color: var(--maiv-untrusted-bg); color: var(--maiv-untrusted-text);
        }
        /* 信頼できない報告値ピル: 判定に算入しない情報提供。点線下線とヘルプ
           カーソルで「hover で全文の断り書きが出る」ことを示す。控えめな情報色
           （privacy 系）を流用し、警告色と混同させない。 */
        .maiv-reported-pill {
          font-size: 10px; font-weight: bold;
          padding: 2px 8px; border-radius: 10px; margin-left: 8px;
          background-color: var(--maiv-privacy-bg); color: var(--maiv-privacy-text);
          white-space: nowrap; cursor: help;
          text-decoration: underline dotted; text-underline-offset: 2px;
        }

        /* コンパクト表示モード: options 画面で有効化すると .maiv-container に
           付与される。小さい画面でメール本文の縦スペースを圧迫しないよう、
           常時表示される通知バー（コンテナ余白・ヘッダ余白・バッジ・ドメイン名）の
           縦方向の占有を縮める。配色や判定には一切手を入れず、ダークモードの
           CSS 変数もそのまま継承するため、表示の意味は変わらず高さだけが下がる。 */
        .maiv-container.maiv-compact { padding: 4px 10px; margin-bottom: 8px; }
        .maiv-container.maiv-compact .maiv-header { padding: 1px 0; }
        .maiv-container.maiv-compact .maiv-badge { padding: 3px 7px; font-size: 12px; }
        .maiv-container.maiv-compact .maiv-header-domain { font-size: 14px; }

        .maiv-toggle-icon { margin-left: 15px; margin-right: 15px; color: var(--maiv-text-faint); transition: transform 0.3s; display: inline-block; }
        .maiv-toggle-icon.expanded { transform: rotate(180deg); }

        /* コピーボタン */
        .maiv-copy-btn {
          padding: 4px 8px; font-size: 11px; border-radius: 3px;
          background: transparent; border: 1px solid var(--maiv-text-faint);
          color: var(--maiv-text-secondary); cursor: pointer;
          margin-right: 8px; white-space: nowrap; transition: all 0.2s;
        }
        .maiv-copy-btn:hover {
          background: var(--maiv-highlight-bg); color: var(--maiv-text-strong);
          border-color: var(--maiv-text-secondary);
        }

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
        .maiv-route-delay { width: 60px; text-align: right; font-weight: bold; font-family: monospace; font-size: 0.9em; }
        .maiv-route-tls { text-align: right; white-space: nowrap; padding-left: 6px; }
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

        /* 認証強度警告: 認証 pass でも送信側の設定変更で解決できる弱さの表示
           （DMARC p=none の赤色ポリシー表示と同じ「改善促し」の位置づけ） */
        .maiv-strength-warn { color: var(--maiv-delay-warning); font-size: 10px; margin-top: 4px; }

        /* ARC チェーン表示 */
        .maiv-arc-table { width: 100%; border-collapse: collapse; font-size: 11px; }
        .maiv-arc-table td { padding: 3px 6px; border-bottom: 1px solid var(--maiv-route-border); }
        .maiv-arc-chain-num { font-weight: bold; color: var(--maiv-text-strong); width: 30px; text-align: center; }
        .maiv-arc-domain { color: var(--maiv-text-secondary); }
        .maiv-arc-summary { color: var(--maiv-text-muted); font-family: monospace; font-size: 10px; }

        /* IPタイプ表示: 送達経路上の内部/外部ネットワーク判定 */
        .maiv-ip-tag { font-size: 10px; margin-left: 4px; }

        /* TLS表示: 送達経路上のホップ間暗号化状態（Received ヘッダ記載ベース） */
        .maiv-tls-tag { font-size: 10px; font-family: monospace; white-space: nowrap; }
        .maiv-tls-secure { color: var(--maiv-pass); }
        .maiv-tls-warn { color: var(--maiv-delay-warning); font-weight: bold; }
        .maiv-tls-danger { color: var(--maiv-fail); font-weight: bold; }
        .maiv-tls-unknown { color: var(--maiv-text-faint); }

        /* LINK SAFETY カード: フィッシング検知結果表示（4段階の severity） */
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
        /* 未信頼ドメイン: 警告より一段控えめな配色で、ユーザーが信頼表明すれば解消することを示唆 */
        .maiv-finding-untrusted {
          background-color: var(--maiv-untrusted-bg); color: var(--maiv-untrusted-text);
          font-weight: bold; padding: 5px 8px; border-radius: 4px; font-size: 11px;
          margin-bottom: 4px;
          display: flex; align-items: center; flex-wrap: wrap; gap: 6px;
        }
        /* プライバシー注意: 青灰色系の情報提供ニュアンス */
        .maiv-finding-privacy {
          background-color: var(--maiv-privacy-bg); color: var(--maiv-privacy-text);
          font-weight: normal; padding: 5px 8px; border-radius: 4px; font-size: 11px;
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

      // --- レポートテキスト生成補助関数 ---
      // 画面に表示している解析結果を、チケットシステムやメールに貼り付けやすい
      // プレーンテキストレポートへ整形する。クリップボード経由で外部ツールに
      // 渡ることを想定し、記号は ASCII 主体（警告マークは [!]）とする。
      const generateReportText = () => {
        const lines = [];

        lines.push("=== Mail Auth Info Viewer Report ===");
        lines.push("");

        // 総合判定: バッジ文言と判定理由タグ
        lines.push(`VERDICT: ${security.badgeText}`);
        if (security.verdictReasons.length > 0) {
          lines.push(`Reasons: ${security.verdictReasons.join(", ")}`);
        }
        lines.push("");

        // 認証結果セクション
        lines.push("AUTHENTICATION RESULTS");
        lines.push("----------------------");
        const spfDomain = authResults.spf.detail.domain || "-";
        const spfIp = authResults.spf.detail.ip ? `, ip: ${authResults.spf.detail.ip}` : "";
        lines.push(`SPF:   ${authResults.spf.status.toUpperCase()} (domain: ${spfDomain}${spfIp})`);

        // DKIM: 複数署名がある場合は署名ごとに「ドメイン=結果 (s=セレクタ)」で列挙
        const sigs = authResults.dkim.signatures || [];
        const dkimSummary = sigs.length > 0
          ? sigs.map(sig => `${sig.domain || "?"}=${sig.status}${sig.selector ? ` (s=${sig.selector})` : ""}`).join(", ")
          : "-";
        lines.push(`DKIM:  ${authResults.dkim.status.toUpperCase()} (${dkimSummary})`);

        const dmarcPolicy = authResults.dmarc.detail.policy || "-";
        lines.push(`DMARC: ${authResults.dmarc.status.toUpperCase()} (policy: ${dmarcPolicy})`);
        if (authResults.authServId) {
          lines.push(`Authserv-Id: ${authResults.authServId}`);
        }
        // 信頼できないソース（authserv-id 不一致の標準 A-R / ARC-AR）からの報告値。
        // 判定には算入していない旨を明記して情報提供する。
        const ru = authResults.reportedUnverified;
        if (ru && ru.any) {
          const parts = [];
          if (ru.spf) parts.push(`SPF:${ru.spf}`);
          if (ru.dkim) parts.push(`DKIM:${ru.dkim}`);
          if (ru.dmarc) parts.push(`DMARC:${ru.dmarc}`);
          lines.push(`Reported (unverified, not counted): ${parts.join(" ")}`);
        }
        lines.push("");

        // アライメントセクション
        lines.push("ALIGNMENT");
        lines.push("---------");
        const al = authResults.alignment || {};
        lines.push(`SPF aligned:  ${al.spfAligned ? "yes" : "no"}`);
        lines.push(`DKIM aligned: ${al.dkimAligned ? "yes" : "no"}`);
        lines.push("");

        // 認証強度の弱さ（検出時のみセクションを出力）
        const strength = authResults.strength || { dkim: [], dmarc: [] };
        if (strength.dkim.length > 0 || strength.dmarc.length > 0) {
          lines.push("STRENGTH WARNINGS");
          lines.push("-----------------");
          for (const w of strength.dkim) {
            lines.push(`[!] DKIM ${w.type}: ${w.value}${w.domain ? ` (${w.domain})` : ""}`);
          }
          for (const w of strength.dmarc) {
            lines.push(`[!] DMARC ${w.type}: ${w.value}`);
          }
          lines.push("");
        }

        // 送信者情報セクション
        lines.push("SENDER IDENTITY");
        lines.push("---------------");
        if (envelope.headerFromName) {
          lines.push(`Display Name:  ${envelope.headerFromName}`);
        }
        lines.push(`Header From:   ${envelope.headerFromAddress}`);
        lines.push(`Envelope From: ${envelope.envelopeFrom}`);
        if (envelope.isDisplayNameSpoofed) {
          lines.push("[!] Display name contains an email address from a different domain");
        }
        if (envelope.isReplyToMismatch) {
          lines.push(`[!] Reply-To differs from sender: ${envelope.replyToAddress}`);
        }
        lines.push("");

        // 送達経路セクション（hop 構造: {from, by, date, ip, isInternal, tls}）
        lines.push("DELIVERY ROUTE");
        lines.push("--------------");
        if (routeHops.length > 0) {
          for (let i = 0; i < routeHops.length; i++) {
            const hop = routeHops[i];
            const label = (i === 0) ? "ORIGIN" : `HOP ${i + 1}`;
            const host = hop.from || hop.by || "(unknown)";
            const ipInfo = hop.ip ? ` [${hop.ip}]` : "";
            lines.push(`${label}: ${host}${ipInfo}`);
            if (hop.by && hop.from) lines.push(`  by:   ${hop.by}`);
            if (hop.date) lines.push(`  time: ${hop.date.toISOString()}`);
            if (hop.tls) {
              if (hop.tls.version) {
                lines.push(`  tls:  ${hop.tls.version}${hop.tls.cipher ? ` (${hop.tls.cipher})` : ""}`);
              } else if (hop.tls.encrypted === true) {
                lines.push("  tls:  encrypted (version unknown)");
              } else if (hop.tls.encrypted === false) {
                lines.push("  tls:  not recorded (plaintext protocol)");
              }
            }
          }
        } else {
          lines.push("(no route information)");
        }
        lines.push("");

        // リンク安全性セクション（findings 構造: {level, type, detail, targetDomain?}）
        lines.push("LINK SAFETY");
        lines.push("-----------");
        const lsFindings = (linkSafety && linkSafety.findings) || [];
        if (lsFindings.length > 0) {
          for (const f of lsFindings) {
            const domainInfo = f.targetDomain ? ` -> ${f.targetDomain}` : "";
            lines.push(`[${f.level.toUpperCase()}] ${f.detail}${domainInfo}`);
          }
        } else {
          lines.push("(no link findings)");
        }
        lines.push("");

        // 生成日時（ISO 8601 — タイムゾーン差異による誤読を防ぐ）
        lines.push(`Generated: ${new Date().toISOString()}`);

        return lines.join("\n");
      };

      // --- クリップボード書き込みヘルパー ---
      // メッセージ表示ペインの文書は mailbox:// / imap:// 等の非セキュアコンテキストで
      // 表示されるため、セキュアコンテキスト限定の navigator.clipboard が存在しない。
      // 利用可能ならそちらを使い、不可なら一時 textarea + document.execCommand("copy") に
      // フォールバックする（クリックというユーザー操作起点のため execCommand が許可される）。
      const writeToClipboard = async (text) => {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          try {
            await navigator.clipboard.writeText(text);
            return true;
          } catch { /* 権限拒否などの場合はフォールバックへ */ }
        }
        const helper = document.createElement("textarea");
        helper.value = text;
        // select() を効かせるため display:none は使わず、画面外へ不可視配置する
        helper.style.position = "fixed";
        helper.style.left = "-9999px";
        helper.style.top = "0";
        helper.setAttribute("readonly", "");
        document.body.appendChild(helper);
        helper.focus();
        helper.select();
        let ok = false;
        try { ok = document.execCommand("copy"); } catch { ok = false; }
        helper.remove();
        return ok;
      };

      // --- コンテナ作成 ---
      const container = document.createElement("div");
      container.className = "maiv-container";
      // コンパクト表示が有効なときは縮小用クラスを付与する。
      // 高さ圧縮は CSS 側（.maiv-container.maiv-compact）に集約しており、
      // ここではフラグに応じてクラスを足すだけに留める。
      if (compactMode) container.classList.add("maiv-compact");

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
          "phishing_suspicious": msg("verdictReasonSuspicious"),
          "link_untrusted": msg("verdictReasonUntrusted")
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
          } else if (r === "link_untrusted") {
            // 未信頼リンクタグ: 警告より一段控えめな専用色
            tagClass = "reason-untrusted";
          }
          return `<span class="maiv-verdict-reason ${tagClass}">${escapeHTML(label)}</span>`;
        }).join("");
        verdictReasonHTML = `<span class="maiv-verdict-reasons-wrap">${tags}</span>`;
      }

      // --- 信頼できない報告値ピル ---
      // authserv-id 不一致で除外した標準 A-R / ARC-AR にしか結果が無い方式を、
      // 「受信サーバの報告値（未検証）」としてヘッダのピル列に控えめに表示する。
      // 判定・バッジ・各カードには一切影響しない情報提供。縦の高さを増やさないよう
      // 専用バナーは設けず既存ピル列に同居させ、全文の断り書きはツールチップに逃がす。
      // 先頭の ℹ️ アイコン・点線下線・ヘルプカーソルで「hover で説明が出る」ことを示す。
      let reportedUnverifiedTag = "";
      const ru = authResults.reportedUnverified;
      if (ru && ru.any) {
        const parts = [];
        if (ru.spf) parts.push(`SPF:${ru.spf}`);
        if (ru.dkim) parts.push(`DKIM:${ru.dkim}`);
        if (ru.dmarc) parts.push(`DMARC:${ru.dmarc}`);
        reportedUnverifiedTag =
          `<span class="maiv-reported-pill" title="${escapeHTML(msg("reportedUnverifiedNotice"))}">` +
          `ℹ️ ${escapeHTML(msg("reportedUnverifiedLabel"))} ${escapeHTML(parts.join(" "))}</span>`;
      }

      const headerHTML = `
        <div class="maiv-header" id="maiv-header-toggle" title="${escapeHTML(msg("toggleDetails"))}"
             aria-expanded="${security.shouldAutoExpand}" aria-controls="maiv-body-wrapper">
          <span class="maiv-badge ${security.badgeClass}">${security.badgeText}</span>
          <span class="maiv-header-domain">${headerDomainText}</span>
          ${mailingListTag}
          ${verdictReasonHTML}
          ${reportedUnverifiedTag}
          <span style="flex-grow:1;"></span>
          <button class="maiv-copy-btn" id="maiv-copy-btn" title="${escapeHTML(msg("copyButton"))}" type="button">📋 ${escapeHTML(msg("copyButton"))}</button>
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

        // 認証強度の弱さ警告（鍵長・アルゴリズム・署名範囲）。
        // 署名結果の有無に関わらず DKIM-Signature ヘッダから検出されるため、
        // 早期 return 経路を含むすべての表示パスの末尾に付加する
        const strengthTypeMsg = {
          "weak_key": msg("dkimWeakKeyLength"),
          "weak_algorithm": msg("dkimWeakAlgorithm"),
          "limited_scope": msg("dkimLimitedScope")
        };
        let strengthHTML = "";
        for (const w of (authResults.strength ? authResults.strength.dkim : [])) {
          const label = strengthTypeMsg[w.type] || w.type;
          const domainInfo = w.domain ? ` — ${w.domain}` : "";
          strengthHTML += `<div class="maiv-strength-warn">⚠️ ${escapeHTML(label)} (${escapeHTML(w.value)}${escapeHTML(domainInfo)})</div>`;
        }

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
            ${strengthHTML}
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
        return html + strengthHTML;
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
        // 認証強度の弱さ警告（sp=none / pct<100）。
        // ポリシー本体が強くても部分的にしか効いていない状態を管理者に示す
        const dmarcStrengthMsg = {
          "weak_sp": msg("dmarcWeakSubpolicy"),
          "limited_pct": msg("dmarcLimitedPct")
        };
        for (const w of (authResults.strength ? authResults.strength.dmarc : [])) {
          const label = dmarcStrengthMsg[w.type] || w.type;
          parts.push(`<div class="maiv-strength-warn">⚠️ ${escapeHTML(label)} (${escapeHTML(w.value)})</div>`);
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

          // TLS / 暗号化状態セル（このホップの Received ヘッダ記載に基づく）
          // ・バージョン記載あり → 🔒 + バージョン番号（TLS 1.0/1.1 は ⚠️ で旧版警告）
          // ・ESMTPS 等のプロトコル名のみ → 🔒（バージョン不明）
          // ・SMTP/ESMTP 等の平文プロトコル表記 → 🔓（暗号化の記録なし）
          // ・with 句なし（ローカル配送等） → 無印（判定材料がないだけで警告ではない）
          let tlsCell = "";
          const tls = hop.tls;
          if (tls && tls.version) {
            const verNum = tls.version.replace(/^TLS\s*/i, "");
            const isLegacy = /^1\.[01]$/.test(verNum);
            const tlsCls = isLegacy ? "maiv-tls-warn" : "maiv-tls-secure";
            const tlsIcon = isLegacy ? "⚠️" : "🔒";
            const tipParts = [tls.version];
            if (tls.cipher) tipParts.push(tls.cipher);
            tlsCell = `<span class="maiv-tls-tag ${tlsCls}" title="${escapeHTML(tipParts.join(" / "))}">${tlsIcon} ${escapeHTML(verNum)}</span>`;
          } else if (tls && tls.encrypted === true) {
            tlsCell = `<span class="maiv-tls-tag maiv-tls-secure" title="TLS">🔒</span>`;
          } else if (tls && tls.encrypted === false) {
            tlsCell = `<span class="maiv-tls-tag maiv-tls-danger" title="${escapeHTML(msg("tlsUnencrypted"))}">🔓</span>`;
          } else {
            tlsCell = `<span class="maiv-tls-tag maiv-tls-unknown" title="${escapeHTML(msg("tlsUnknown"))}">−</span>`;
          }

          const rowClass = isFirst ? "maiv-route-origin" : "maiv-route-hop";
          const timeDisplay = hop.date ? hop.date.toLocaleTimeString() : "";
          const label = isFirst ? `${msg("labelOrigin")} 🚀` : `#${i + 1}`;

          routeRows += `
            <tr class="${rowClass}">
              <td class="maiv-route-delay"><span class="${delayClass}">${delayStr}</span></td>
              <td>${escapeHTML(label)} ${ipTag}${byDisplay}</td>
              <td class="maiv-route-tls">${tlsCell}</td>
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
              <td class="maiv-route-tls"></td>
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
          // レベル別のCSSクラスとアイコン
          // critical=🚨(赤) / suspicious=⚠️(橙) / untrusted=⚠️(黄/控えめ) / privacy=🕵️(青灰)
          const levelCls = {
            "critical": "maiv-finding-critical",
            "suspicious": "maiv-finding-suspicious",
            "untrusted": "maiv-finding-untrusted",
            "privacy": "maiv-finding-privacy"
          };
          const levelIcon = {
            "critical": "🚨",
            "suspicious": "⚠️",
            "untrusted": "⚠️",
            "privacy": "🕵️"
          };
          // 未信頼な外部リンクドメインが1つだけの場合、その findings 行から直接Trustできるようにする。
          // 複数ある場合はユーザーが意図せず一括信頼するリスクがあるため、下のドメイン一覧から個別操作を促す。
          const externalSet = linkSafety.externalLinkDomains || new Set();
          const untrustedSingleDomain = (externalSet.size === 1) ? Array.from(externalSet)[0] : null;
          for (const f of linkSafety.findings) {
            const cls = levelCls[f.level] || "maiv-finding-suspicious";
            const icon = levelIcon[f.level] || "⚠️";
            // untrusted レベルの行に、対象が1ドメインに特定できる場合のみワンクリック Trust ボタンを添える
            let inlineTrust = "";
            if (f.level === "untrusted" && untrustedSingleDomain &&
                !(trustedDomains && trustedDomains.has(untrustedSingleDomain))) {
              inlineTrust = ` <button class="maiv-trust-btn" data-domain="${escapeHTML(untrustedSingleDomain)}">${escapeHTML(msg("trustDomainButton"))} ${escapeHTML(untrustedSingleDomain)}</button>`;
            }
            findingsHTML += `<div class="${cls}">${icon} ${escapeHTML(f.detail)}${inlineTrust}</div>`;
          }
        }

        // ドメイン一覧のレンダリングヘルパー
        // showTrust: trueの場合、未信頼かつHeader From不一致のドメインに「信頼」ボタンを表示
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
            // 「信頼」ボタン: 任意のリンク警告(critical/suspicious/untrusted)検出時、未信頼かつ不一致ドメインに表示
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

        // findings があればドメイン一覧もデフォルト展開
        const expandDomains = hasFindings;
        const expandedCls = expandDomains ? " maiv-expanded" : "";

        linkSafetyContentHTML = findingsHTML +
          (hasDomainLists ? `<div class="maiv-collapsible-body${expandedCls}" id="maiv-link-safety-detail">${domainListsHTML}</div>` : "");
      } else {
        linkSafetyContentHTML = `<div class="maiv-empty-state">${escapeHTML(msg("labelNone"))}</div>`;
      }

      // ドメイン一覧がある場合はタイトルをトグル化、findings時はデフォルト展開
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

      // マウスクリックによる開閉（コピーボタンクリックは除外）
      headerToggle.addEventListener('click', (e) => {
        if (e.target.closest('.maiv-copy-btn')) return;
        togglePanel();
      });

      // --- コピーボタンハンドラー ---
      const copyBtn = container.querySelector('#maiv-copy-btn');
      if (copyBtn) {
        copyBtn.addEventListener('click', async (e) => {
          e.stopPropagation();
          let ok = false;
          try {
            const reportText = generateReportText();
            ok = await writeToClipboard(reportText);
          } catch (err) {
            console.error("MailAuthInfoViewer: Failed to copy to clipboard", err);
            ok = false;
          }
          // 成否をボタン上で2秒間フィードバックして元の表記に戻す
          copyBtn.textContent = ok ? `✅ ${msg("copiedSuccess")}` : `❌ ${msg("copiedFailed")}`;
          setTimeout(() => {
            copyBtn.textContent = `📋 ${msg("copyButton")}`;
          }, 2000);
        });
      }

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
      // findings 行のインラインTrust、ドメイン一覧内のTrust、どちらも同じハンドラで処理する
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

    // ■ コンパクト表示設定の読み込み（options 画面で切り替え）
    //    通知バーの高さを抑えたいユーザー向けの表示オプション。判定には影響せず、
    //    未設定／storage 未対応環境では既定の通常表示にフォールバックする。
    let compactMode = false;
    try {
      const stored = await browser.storage.local.get("compactMode");
      compactMode = stored.compactMode === true;
    } catch { /* storage未対応環境では通常表示 */ }

    const envelope = parseEnvelope(fullMsg, headers, msgHeader);
    const authResults = parseAuthResults(headers, envelope);
    const routeHops = parseRoute(headers);
    const arcChain = parseArcChain(headers);
    const bodyContent = parseMessageBody(fullMsg);
    const linkSafety = analyzeLinkSafety(bodyContent, envelope.headerOrgDomain, trustedDomains);
    const security = determineSecurityStatus(authResults, envelope.isDomainAligned, envelope.envelopeFrom, envelope.isDisplayNameSpoofed, linkSafety);

    buildUI(envelope, authResults, routeHops, security, arcChain, linkSafety, trustedDomains, compactMode);

  } catch (e) {
    console.error("MailAuthInfoViewer Error:", e);
  }
})();