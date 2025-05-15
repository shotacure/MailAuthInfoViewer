// messagedisplay.js

browser.runtime.sendMessage({ command: "getMessageDetails" }).then(resp => {
  if (resp.error) return;
  const headers = resp.fullMessage.headers;

  // ■ Envelope 情報取得（SMTPエンベロープ優先、なければヘッダ由来）
  const envelopeFrom =
    resp.fullMessage.envelope?.from ||
    headers["return-path"]?.[0]?.replace(/^<|>$/g, "") ||
    resp.fullMessage.author ||
    "";
  const envelopeTo =
    (headers["delivered-to"] || []).map(s => s.trim()).join(", ") ||
    resp.fullMessage.envelope?.to?.join(", ") ||
    (resp.fullMessage.recipients || []).join(", ");

  // 送達経路を1行で要約
  const recs = headers["received"] || [];
  const hosts = [];
  recs.forEach(line => {
    const m = line.match(/\bfrom\s+([^\s;]+)/i) || line.match(/\bby\s+([^\s;]+)/i);
    if (m?.[1] && !hosts.includes(m[1])) hosts.push(m[1]);
  });
  const route = hosts.join(" → ");

  // Authentication-Results 全体を分割
  const arRaw = headers["authentication-results"]?.join(" ") || "";
  const arParts = arRaw.split(/;|\r?\n/).map(s => s.trim()).filter(Boolean);

  // SPF／DKIM／DMARC のみを抽出して詳細理由付きでフォーマット
  function fmtARPart(part) {
    const lower = part.toLowerCase();

    // SPF
    if (lower.startsWith("spf=")) {
      const m = part.match(/spf=(\w+)/i);
      const status = m?.[1]?.toLowerCase() || "";
      const mf = part.match(/smtp\.mailfrom=([^ ]+)/i)?.[1] || "";
      const mail = mf.includes("@") ? mf.split("@")[1] : mf;
      const ipMatch = part.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
      const ip = ipMatch ? ipMatch[1] : "";
      if (status === "pass") {
        return `<div style="color:green;">✅ SPF: 有効 — ドメイン ${mail} が IP ${ip} を許可</div>`;
      }
      if (status === "fail") {
        return `<div style="color:red;">❌ SPF: 無効 — ドメイン ${mail} が IP ${ip} を許可せず</div>`;
      }
      if (status === "softfail") {
        return `<div style="color:orange;">⚠ SPF: softfail — ドメイン ${mail} が IP ${ip} を許可せず</div>`;
      }
      if (status === "none") {
        return `<div style="color:orange;">⚠ SPF: none — ドメイン ${mail} に SPF レコードなし</div>`;
      }
      return `<div>${part}</div>`;
    }

    // DKIM
    if (lower.startsWith("dkim=")) {
      const m = part.match(/dkim=(\w+)/i);
      const status = m?.[1]?.toLowerCase() || "";
      if (status === "pass") {
        const d = (part.match(/header\.d=([^ ]+)/i)?.[1] || "").trim();
        const s = (part.match(/header\.s=([^ ]+)/i)?.[1] || "").trim();
        return `<div style="color:green;">✅ DKIM: 有効 — ドメイン ${d}、セレクタ ${s}</div>`;
      }
      if (status === "fail") {
        return `<div style="color:red;">❌ DKIM: 無効 — 署名検証失敗</div>`;
      }
      if (status === "none") {
        return `<div style="color:orange;">⚠ DKIM: none — 署名なし</div>`;
      }
      return `<div>${part}</div>`;
    }

    // DMARC
    if (lower.startsWith("dmarc=")) {
      const m = part.match(/dmarc=(\w+)/i);
      const status = m?.[1]?.toLowerCase() || "";
      const domain = (part.match(/header\.from=([^ ]+)/i)?.[1] || "").trim();
      if (status === "pass") {
        return `<div style="color:green;">✅ DMARC: 有効 — ドメイン ${domain} で認証成功</div>`;
      }
      if (status === "none") {
        return `<div style="color:orange;">⚠ DMARC: none — ドメイン ${domain} でポリシー未設定</div>`;
      }
      if (status === "fail") {
        return `<div style="color:red;">❌ DMARC: 無効 — ドメイン ${domain} で認証失敗</div>`;
      }
      return `<div>${part}</div>`;
    }

    return null;
  }

  // DL要素を作成
  const dl = document.createElement("dl");
  dl.style.display = "grid";
  dl.style.gridTemplateColumns = "auto 1fr";
  dl.style.gridColumnGap = "0.5em";
  dl.style.margin = "0";
  dl.style.fontSize = "small";
  dl.style.lineHeight = "1.2em";

  // エンベロープFrom
  if (envelopeFrom) {
    const dt = document.createElement("dt");
    dt.textContent = "エンベロープFrom";
    dt.style.fontWeight = "bold";
    const dd = document.createElement("dd");
    dd.style.margin = "0 0 5px 0";
    dd.textContent = envelopeFrom;
    dl.append(dt, dd);
  }

  // エンベロープTo
  if (envelopeTo) {
    const dt = document.createElement("dt");
    dt.textContent = "エンベロープTo";
    dt.style.fontWeight = "bold";
    const dd = document.createElement("dd");
    dd.style.margin = "0 0 5px 0";
    dd.textContent = envelopeTo;
    dl.append(dt, dd);
  }

  // 送達経路
  if (route) {
    const dt = document.createElement("dt");
    dt.textContent = "送達経路";
    dt.style.fontWeight = "bold";
    const dd = document.createElement("dd");
    dd.style.margin = "0 0 5px 0";
    dd.textContent = route;
    dl.append(dt, dd);
  }

  // 認証結果
  if (arParts.length) {
    const dt = document.createElement("dt");
    dt.textContent = "認証結果";
    dt.style.fontWeight = "bold";
    const dd = document.createElement("dd");
    dd.style.margin = "0 0 5px 0";

    // サーバ情報
    const serverDiv = document.createElement("div");
    serverDiv.textContent = arParts[0];
    dd.appendChild(serverDiv);

    // SPF, DKIM, DMARC のみ
    arParts.slice(1).forEach(part => {
      const html = fmtARPart(part);
      if (html) {
        const div = document.createElement("div");
        div.style.marginLeft = "1em";
        div.innerHTML = html;
        dd.appendChild(div);
      }
    });

    dl.append(dt, dd);
  }

  // グレーのボックスを作成して挿入
  const box = document.createElement("div");
  box.style.backgroundColor = "#e0e0e0";
  box.style.border = "1px solid #999";
  box.style.padding = "5px";
  box.style.marginBottom = "10px";
  box.style.fontSize = "small";

  box.appendChild(dl);
  document.body.insertAdjacentElement("afterbegin", box);
}).catch(() => {});
