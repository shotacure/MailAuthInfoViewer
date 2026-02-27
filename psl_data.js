// psl_data.js
// Public Suffix List (curated) and Organizational Domain extraction
// Based on https://publicsuffix.org/ — covers major TLDs used in email worldwide.
//
// Algorithm: RFC 7489 Section 3.2 "Organizational Domain"
// The organizational domain is the public suffix plus one additional label.
// e.g. "mail.sub.example.co.uk" → suffix="co.uk", org domain="example.co.uk"
//
// This curated set covers 60+ countries and handles the vast majority of
// real-world email traffic. For unknown multi-part TLDs, the fallback
// assumes a single-level TLD (correct for .com, .net, .org, .de, .fr, etc.).

(() => {
  "use strict";

  // -------------------------------------------------------------------
  // Multi-level public suffixes (sorted alphabetically by TLD)
  // Single-level TLDs (.com, .net, .org, .de, .fr, etc.) are handled
  // by the default fallback and do NOT need entries here.
  // -------------------------------------------------------------------
  const PSL_ENTRIES = [
    // .ae — United Arab Emirates
    "co.ae", "net.ae", "org.ae", "ac.ae", "gov.ae", "mil.ae", "sch.ae",
    // .ar — Argentina
    "com.ar", "edu.ar", "gob.ar", "gov.ar", "int.ar", "mil.ar", "net.ar", "org.ar", "tur.ar",
    // .au — Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    // .bd — Bangladesh
    "com.bd", "net.bd", "org.bd", "edu.bd", "gov.bd", "ac.bd", "mil.bd",
    // .bn — Brunei
    "com.bn", "edu.bn", "gov.bn", "net.bn", "org.bn",
    // .bo — Bolivia
    "com.bo", "edu.bo", "gob.bo", "gov.bo", "mil.bo", "net.bo", "org.bo",
    // .br — Brazil
    "com.br", "net.br", "org.br", "edu.br", "gov.br", "mil.br",
    "art.br", "blog.br", "eco.br", "emp.br", "eng.br", "esp.br",
    "far.br", "flog.br", "fnd.br", "g12.br", "imb.br", "ind.br",
    "inf.br", "jor.br", "log.br", "mus.br", "not.br", "odo.br",
    "ppg.br", "pro.br", "psc.br", "rec.br", "srv.br", "tmp.br",
    "tur.br", "tv.br", "vet.br", "vlog.br", "wiki.br",
    // .cn — China
    "com.cn", "net.cn", "org.cn", "edu.cn", "gov.cn", "ac.cn", "mil.cn",
    "ah.cn", "bj.cn", "cq.cn", "fj.cn", "gd.cn", "gs.cn", "gx.cn",
    "gz.cn", "ha.cn", "hb.cn", "he.cn", "hi.cn", "hk.cn", "hl.cn",
    "hn.cn", "jl.cn", "js.cn", "jx.cn", "ln.cn", "mo.cn", "nm.cn",
    "nx.cn", "qh.cn", "sc.cn", "sd.cn", "sh.cn", "sn.cn", "sx.cn",
    "tj.cn", "tw.cn", "xj.cn", "xz.cn", "yn.cn", "zj.cn",
    // .co — Colombia
    "com.co", "net.co", "org.co", "edu.co", "gov.co", "mil.co", "nom.co",
    // .cr — Costa Rica
    "co.cr", "or.cr", "ac.cr", "ed.cr", "go.cr", "sa.cr",
    // .cy — Cyprus
    "com.cy", "net.cy", "org.cy", "ac.cy", "gov.cy",
    // .do — Dominican Republic
    "com.do", "edu.do", "gob.do", "gov.do", "mil.do", "net.do", "org.do",
    // .ec — Ecuador
    "com.ec", "net.ec", "org.ec", "edu.ec", "gov.ec", "mil.ec",
    // .eg — Egypt
    "com.eg", "edu.eg", "gov.eg", "net.eg", "org.eg", "sci.eg",
    // .et — Ethiopia
    "com.et", "gov.et", "org.et", "edu.et", "net.et",
    // .gh — Ghana
    "com.gh", "edu.gh", "gov.gh", "org.gh", "mil.gh",
    // .gt — Guatemala
    "com.gt", "edu.gt", "gob.gt", "mil.gt", "net.gt", "org.gt",
    // .hk — Hong Kong
    "com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk", "idv.hk",
    // .id — Indonesia
    "co.id", "ac.id", "go.id", "net.id", "or.id", "web.id", "sch.id", "mil.id",
    // .il — Israel
    "co.il", "ac.il", "org.il", "net.il", "gov.il", "muni.il",
    // .in — India
    "co.in", "net.in", "org.in", "ac.in", "edu.in", "gov.in", "mil.in", "res.in",
    // .jm — Jamaica
    "com.jm", "net.jm", "org.jm", "edu.jm", "gov.jm", "mil.jm",
    // .jo — Jordan
    "com.jo", "net.jo", "org.jo", "edu.jo", "gov.jo", "mil.jo",
    // .jp — Japan
    "ac.jp", "ad.jp", "co.jp", "ed.jp", "go.jp", "gr.jp", "lg.jp", "ne.jp", "or.jp",
    // .ke — Kenya
    "co.ke", "ac.ke", "go.ke", "ne.ke", "or.ke", "sc.ke",
    // .kh — Cambodia
    "com.kh", "edu.kh", "gov.kh", "net.kh", "org.kh",
    // .kr — South Korea
    "co.kr", "ne.kr", "or.kr", "ac.kr", "go.kr", "re.kr", "pe.kr", "mil.kr",
    // .kw — Kuwait
    "com.kw", "edu.kw", "gov.kw", "net.kw", "org.kw",
    // .lb — Lebanon
    "com.lb", "edu.lb", "gov.lb", "net.lb", "org.lb",
    // .lk — Sri Lanka
    "com.lk", "org.lk", "edu.lk", "gov.lk", "ac.lk", "net.lk",
    // .ma — Morocco
    "co.ma", "net.ma", "org.ma", "ac.ma", "gov.ma",
    // .mm — Myanmar
    "com.mm", "net.mm", "org.mm", "edu.mm", "gov.mm",
    // .mo — Macao
    "com.mo", "net.mo", "org.mo", "edu.mo", "gov.mo",
    // .mt — Malta
    "com.mt", "net.mt", "org.mt", "edu.mt",
    // .mx — Mexico
    "com.mx", "net.mx", "org.mx", "edu.mx", "gob.mx",
    // .my — Malaysia
    "com.my", "net.my", "org.my", "edu.my", "gov.my", "mil.my",
    // .mz — Mozambique
    "co.mz", "ac.mz", "org.mz", "edu.mz", "gov.mz",
    // .ng — Nigeria
    "com.ng", "edu.ng", "gov.ng", "net.ng", "org.ng", "mil.ng",
    // .ni — Nicaragua
    "com.ni", "edu.ni", "gob.ni", "net.ni", "org.ni",
    // .np — Nepal
    "com.np", "edu.np", "gov.np", "net.np", "org.np", "mil.np",
    // .nz — New Zealand
    "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz", "geek.nz", "school.nz",
    // .om — Oman
    "co.om", "com.om", "edu.om", "gov.om", "net.om", "org.om",
    // .pa — Panama
    "com.pa", "ac.pa", "gob.pa", "edu.pa", "net.pa", "org.pa",
    // .pe — Peru
    "com.pe", "edu.pe", "gob.pe", "net.pe", "org.pe", "mil.pe",
    // .ph — Philippines
    "com.ph", "net.ph", "org.ph", "edu.ph", "gov.ph", "mil.ph",
    // .pk — Pakistan
    "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk",
    // .pl — Poland
    "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl", "mil.pl", "info.pl", "biz.pl",
    // .pr — Puerto Rico
    "com.pr", "net.pr", "org.pr", "edu.pr", "gov.pr",
    // .ps — Palestine
    "com.ps", "net.ps", "org.ps", "edu.ps", "gov.ps",
    // .pt — Portugal
    "com.pt", "org.pt", "net.pt", "edu.pt", "gov.pt",
    // .py — Paraguay
    "com.py", "edu.py", "gov.py", "mil.py", "net.py", "org.py",
    // .qa — Qatar
    "com.qa", "edu.qa", "gov.qa", "net.qa", "org.qa",
    // .sa — Saudi Arabia
    "com.sa", "net.sa", "org.sa", "edu.sa", "gov.sa", "med.sa", "sch.sa",
    // .sg — Singapore
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg", "per.sg",
    // .sv — El Salvador
    "com.sv", "edu.sv", "gob.sv", "org.sv",
    // .th — Thailand
    "co.th", "ac.th", "go.th", "net.th", "or.th", "in.th", "mi.th",
    // .tr — Turkey
    "com.tr", "net.tr", "org.tr", "edu.tr", "gov.tr", "mil.tr",
    "gen.tr", "bel.tr", "av.tr", "dr.tr", "pol.tr", "bbs.tr",
    // .tw — Taiwan
    "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw", "idv.tw", "mil.tw",
    // .tz — Tanzania
    "co.tz", "ac.tz", "go.tz", "ne.tz", "or.tz", "sc.tz",
    // .ua — Ukraine
    "com.ua", "net.ua", "org.ua", "edu.ua", "gov.ua",
    // .ug — Uganda
    "co.ug", "ac.ug", "go.ug", "ne.ug", "or.ug", "sc.ug",
    // .uk — United Kingdom
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "nhs.uk", "police.uk", "sch.uk", "me.uk",
    // .uy — Uruguay
    "com.uy", "edu.uy", "gub.uy", "mil.uy", "net.uy", "org.uy",
    // .ve — Venezuela
    "co.ve", "com.ve", "edu.ve", "gob.ve", "gov.ve", "mil.ve", "net.ve", "org.ve",
    // .vn — Vietnam
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "ac.vn", "biz.vn", "info.vn",
    // .za — South Africa
    "co.za", "org.za", "ac.za", "gov.za", "net.za", "web.za", "school.za",
    // .zm — Zambia
    "co.zm", "ac.zm", "gov.zm", "org.zm", "sch.zm",
    // .zw — Zimbabwe
    "co.zw", "ac.zw", "gov.zw", "org.zw",

    // --- Hosted services (pseudo-TLDs registered as public suffixes) ---
    "blogspot.com", "blogspot.co.uk", "blogspot.jp",
    "amazonaws.com", "s3.amazonaws.com",
    "appspot.com", "firebaseapp.com",
    "azurewebsites.net", "cloudfront.net", "herokuapp.com",
    "pages.dev", "workers.dev", "r2.dev",
    "github.io", "gitlab.io", "netlify.app", "vercel.app",
  ];

  // Build a lookup Set for O(1) membership tests
  const PSL_SET = new Set(PSL_ENTRIES);

  /**
   * Extract the Organizational Domain from a fully qualified domain name.
   *
   * Per RFC 7489, the organizational domain is the domain directly registered
   * under a public suffix. For example:
   *   "aaa.bbb.google.com"  → "google.com"
   *   "mail.example.co.jp"  → "example.co.jp"
   *   "sub.sub.example.com" → "example.com"
   *
   * @param {string} domain  A domain name (e.g. "mail.example.co.uk")
   * @returns {string}       The organizational domain (e.g. "example.co.uk")
   */
  window.getOrganizationalDomain = (domain) => {
    if (!domain) return "";
    domain = domain.toLowerCase().replace(/\.$/, ""); // normalize
    const labels = domain.split(".");

    if (labels.length <= 1) return domain;

    // Walk from the most specific multi-label suffix to least specific.
    // For labels [a, b, c, d]:
    //   i=1 → check "b.c.d"  (3-label suffix)
    //   i=2 → check "c.d"    (2-label suffix)
    //   (stop before single label — handled by default)
    for (let i = 1; i < labels.length; i++) {
      const candidateSuffix = labels.slice(i).join(".");
      if (PSL_SET.has(candidateSuffix)) {
        // Suffix found; org domain = labels[i-1] + suffix
        return labels.slice(i - 1).join(".");
      }
    }

    // Default: assume last label is a single-level TLD.
    // Organizational domain = last two labels.
    return labels.slice(-2).join(".");
  };
})();
