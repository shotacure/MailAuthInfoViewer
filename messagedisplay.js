// messagedisplay.js

browser.runtime.sendMessage({ command: "getMessageDetails" }).then(resp => {
  if (resp.error) return;
  const headers = resp.fullMessage.headers;

  // 送達経路を1行で要約
  const recs = headers["received"] || [];
  const hosts = [];
  recs.forEach(line => {
    const m = line.match(/\bfrom\s+([^\s;]+)/i) || line.match(/\bby\s+([^\s;]+)/i);
    if (m?.[1] && !hosts.includes(m[1])) hosts.push(m[1]);
  });
  const route = hosts.join(" → ");

  // Authentication‑Results ヘッダをすべて連結
  const arLines = (headers["authentication-results"] || [])
    .join(" ")
    .split(/;|\r?\n/)
    .map(s => s.trim())
    .filter(Boolean);

  // 各行をアイコン＋色＋日本語理由でフォーマット
  function fmtARPart(part) {
    const lower = part.toLowerCase();
    if (lower.startsWith("dkim=")) {
      const m = part.match(/dkim=(\w+)/i);
      const status = m?.[1]?.toLowerCase() || "";
      const i = (part.match(/header\.i=@([^ ]+)/i)?.[1] || "").trim();
      const d = (part.match(/header\.d=([^ ]+)/i)?.[1] || "").trim();
      const s = (part.match(/header\.s=([^ ]+)/i)?.[1] || "").trim();
      const dkim = s+"._domainkey."+i+d;
      if (status === "pass")      return `<div style="color:green;">✅ DKIM: pass (署名検証成功 ${dkim})</div>`;
      if (status === "fail")      return `<div style="color:red;">❌ DKIM: fail (署名検証失敗)</div>`;
      if (status === "none")      return `<div style="color:orange;">⚠ DKIM: none (署名なし)</div>`;
      return `<div>${part}</div>`;
    }
    if (lower.startsWith("spf=")) {
      const m = part.match(/spf=(\w+)/i);
      const status = m?.[1]?.toLowerCase() || "";
      const mf = part.match(/smtp\.mailfrom=([^ ]+)/i)?.[1] || "";
      const ipMatch = part.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
      const ip = ipMatch ? ipMatch[1] : "";
      if (status === "pass")      return `<div style="color:green;">✅ SPF: pass (送信者 ${mf} のドメインは ${ip} を許可しています)</div>`;
      if (status === "fail")      return `<div style="color:red;">❌ SPF: fail (送信者 ${mf} のドメインは ${ip} を許可していません(拒絶設定))</div>`;
      if (status === "softfail")  return `<div style="color:orange;">⚠ SPF: softfail (送信者 ${mf} のドメインは ${ip} を許可していません)</div>`;
      if (status === "none")      return `<div style="color:orange;">⚠ SPF: none (送信者 ${mf} のドメインにSPFレコードが見つかりません)</div>`;
      return `<div>${part}</div>`;
    }
    if (lower.startsWith("dmarc=")) {
      const m = part.match(/dmarc=(\w+)/i);
      const status = m?.[1]?.toLowerCase() || "";
      const d = (part.match(/header\.from=([^ ]+)/i)?.[1] || "").trim();
      if (status === "pass")      return `<div style="color:green;">✅ DMARC: pass (送信者アドレスのドメイン ${d} で認証成功)</div>`;
      if (status === "none")      return `<div style="color:orange;">⚠ DMARC: none (送信者アドレスのドメイン ${d} でポリシー未設定)</div>`;
      if (status === "fail")      return `<div style="color:red;">❌ DMARC: fail (送信者アドレスのドメイン ${d} で認証失敗)</div>`;
      return `<div>${part}</div>`;
    }
    return null;
  }

  // DL 要素を作成
  const dl = document.createElement("dl");
  dl.style.display = "grid";
  dl.style.gridTemplateColumns = "auto 1fr";
  dl.style.gridColumnGap = "0.5em";
  dl.style.margin = "0";
  dl.style.fontSize = "small";
  dl.style.lineHeight = "1.2em";

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
  if (arLines.length) {
    const dt = document.createElement("dt");
    dt.textContent = "認証結果";
    dt.style.fontWeight = "bold";
    const dd = document.createElement("dd");
    dd.style.margin = "0 0 5px 0";

    // サーバ情報
    const serverDiv = document.createElement("div");
    serverDiv.textContent = arLines[0];
    dd.appendChild(serverDiv);

    // SPF/DKIM/DMARC のみ
    arLines.slice(1).forEach(part => {
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

  // グレーボックスを作成して挿入
  const box = document.createElement("div");
  box.style.backgroundColor = "#e0e0e0";
  box.style.border = "1px solid #999";
  box.style.padding = "5px";
  box.style.marginBottom = "10px";
  box.style.fontSize = "small";

  box.appendChild(dl);
  document.body.insertAdjacentElement("afterbegin", box);
}).catch(() => {});
