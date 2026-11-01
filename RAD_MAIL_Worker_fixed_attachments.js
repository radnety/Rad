// RAD MAIL Pro — hardened build V1.4
// D1 binding: DB
// Variables: MAIN_DOMAIN, CF_ZONE_ID
// Secrets: PANEL_PASSWORD, CF_API_TOKEN

const SPAM_WORDS = [
  "viagra", "casino", "lottery", "you have won", "crypto giveaway", 
  "click here now", "100% free", "urgent reply", "wire transfer", 
  "binance reward", "claim prize", "free crypto"
];

const SOCIAL_DOMAINS = [
  "twitter.com", "x.com", "linkedin.com", "facebook.com", "facebookmail.com",
  "instagram.com", "github.com", "gitlab.com", "discord.com", "reddit.com",
  "pinterest.com", "tiktok.com", "telegram.org", "threads.net"
];

const PROMO_KEYWORDS = [
  "discount", "offer", "sale", "coupon", "promo", "deal", "تخفیف", "حراج", "پیشنهاد ویژه", "فروش ویژه", "off%"
];

const UPDATE_KEYWORDS = [
  "statement", "invoice", "receipt", "order confirmation", "bill", "security alert",
  "verification code", "verify your email", "کد تایید", "فاکتور", "رسید", "تراکنش", "هشدار امنیتی"
];

const json = (o, status = 200, headers = {}) => new Response(JSON.stringify(o), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", ...headers }
});

const escCsv = s => '"' + String(s ?? "").replace(/"/g, '""') + '"';

let initPromise;
function init(env) {
  initPromise ||= (async () => {
    await env.DB.batch([
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS mails (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT,
        to_addr TEXT,
        from_addr TEXT,
        from_name TEXT,
        subject TEXT,
        text TEXT,
        html TEXT,
        folder TEXT DEFAULT 'inbox',
        category TEXT DEFAULT 'primary',
        starred INTEGER DEFAULT 0,
        pinned INTEGER DEFAULT 0,
        read INTEGER DEFAULT 0,
        spam_score INTEGER DEFAULT 0,
        unsubscribe_url TEXT DEFAULT '',
        labels TEXT DEFAULT '[]',
        ts INTEGER
      )`),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS blocked (addr TEXT PRIMARY KEY, ts INTEGER)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS custom_labels (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, color TEXT)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS mailboxes (address TEXT PRIMARY KEY, label TEXT DEFAULT '', enabled INTEGER DEFAULT 1, created_ts INTEGER, updated_ts INTEGER)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)"),
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mail_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
        size INTEGER NOT NULL DEFAULT 0,
        storage_key TEXT,
        content BLOB,
        created_ts INTEGER NOT NULL,
        FOREIGN KEY(mail_id) REFERENCES mails(id) ON DELETE CASCADE
      )`),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_attachments_mail_id ON attachments(mail_id)")
    ]);

    const safeAdd = async (colDef) => {
      try { await env.DB.prepare(`ALTER TABLE mails ADD COLUMN ${colDef}`).run(); } catch (_) {}
    };
    await safeAdd("category TEXT DEFAULT 'primary'");
    await safeAdd("pinned INTEGER DEFAULT 0");
    await safeAdd("unsubscribe_url TEXT DEFAULT ''");
    await safeAdd("labels TEXT DEFAULT '[]'");
  })();
  return initPromise;
}

function bytes(s) {
  const u = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i) & 255;
  return u;
}

function b2s(buf) {
  let s = "";
  const u = new Uint8Array(buf);
  for (let i = 0; i < u.length; i += 8192) s += String.fromCharCode(...u.subarray(i, i + 8192));
  return s;
}

const hex = (_, x) => String.fromCharCode(parseInt(x, 16));

function hdrs(block) {
  const h = {};
  block.replace(/\r?\n[ \t]+/g, " ").split(/\r?\n/).forEach(line => {
    const i = line.indexOf(":");
    if (i > 0) h[line.slice(0, i).toLowerCase()] = line.slice(i + 1).trim();
  });
  return h;
}

function decodeWord(s) {
  return (s || "").replace(/=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g, (_, cs, enc, text) => {
    try {
      const data = /b/i.test(enc) ? bytes(atob(text)) : bytes(text.replace(/_/g, " ").replace(/=([0-9A-F]{2})/gi, hex));
      return new TextDecoder(cs).decode(data);
    } catch {
      return text;
    }
  });
}

function decodePart(part, h) {
  const cte = (h["content-transfer-encoding"] || "").toLowerCase();
  const cs = (/charset="?([^";\s]+)/i.exec(h["content-type"] || "") || [])[1] || "utf-8";
  let u;
  try {
    u = cte === "base64" ? bytes(atob(part.replace(/\s/g, ""))) :
        cte === "quoted-printable" ? bytes(part.replace(/=\r?\n/g, "").replace(/=([0-9A-F]{2})/gi, hex)) :
        bytes(part);
  } catch {
    u = bytes(part);
  }
  try {
    return new TextDecoder(cs).decode(u);
  } catch {
    return new TextDecoder().decode(u);
  }
}

function decodeBinaryPart(part, h) {
  const cte = (h["content-transfer-encoding"] || "").toLowerCase();
  const clean = String(part || "").replace(/\r\n/g, "\n");
  if (cte === "base64") {
    const raw = atob(clean.replace(/\s/g, ""));
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }
  if (cte === "quoted-printable") {
    const decoded = clean.replace(/=\n/g, "").replace(/=([0-9A-F]{2})/gi, (_, x) => String.fromCharCode(parseInt(x, 16)));
    return bytes(decoded);
  }
  return bytes(String(part || "").replace(/\r\n/g, "\n"));
}

function mimeFilename(h) {
  const cd = h["content-disposition"] || "";
  const ct = h["content-type"] || "";
  let raw = /filename\*=(?:UTF-8'')?([^;]+)/i.exec(cd)?.[1]
    || /filename="?([^";]+)"?/i.exec(cd)?.[1]
    || /name="?([^";]+)"?/i.exec(ct)?.[1]
    || "";
  raw = raw.trim().replace(/^["']|["']$/g, "");
  try { raw = decodeURIComponent(raw); } catch (_) {}
  return decodeWord(raw).replace(/[\u0000-\u001f\u007f]/g, "").split(/[\\/]/).pop().slice(0, 240);
}

function walkMime(h, body, out) {
  const ct = h["content-type"] || "text/plain";
  const cd = h["content-disposition"] || "";
  const bm = /boundary="?([^";]+)/i.exec(ct);
  if (/multipart/i.test(ct) && bm) {
    body.split("--" + bm[1]).slice(1).forEach(part => {
      if (/^--/.test(part)) return;
      part = part.replace(/^\r?\n/, "").replace(/\r?\n$/, "");
      const j = part.search(/\r?\n\r?\n/);
      if (j >= 0) {
        const partHeaders = hdrs(part.slice(0, j));
        const partBody = part.slice(j).replace(/^\r?\n\r?\n/, "").replace(/\r?\n$/, "");
        walkMime(partHeaders, partBody, out);
      }
    });
    return;
  }
  const filename = mimeFilename(h);
  if (/attachment/i.test(cd) || filename) {
    try {
      const data = decodeBinaryPart(body, h);
      if (data.byteLength) out.attachments.push({
        filename: filename || "attachment",
        content_type: (ct.split(";")[0] || "application/octet-stream").trim().toLowerCase(),
        data
      });
    } catch (e) { console.error("Attachment decode failed:", e); }
    return;
  }
  if (/text\/html/i.test(ct)) out.html += decodePart(body, h);
  else if (/text\/plain/i.test(ct)) out.text += decodePart(body, h);
}

function extractUnsubscribeUrl(headerVal) {
  if (!headerVal) return "";
  const match = /<(https?:\/\/[^>]+)>/i.exec(headerVal) || /(https?:\/\/[^\s,>]+)/i.exec(headerVal);
  if (match) return match[1];
  const mailtoMatch = /<(mailto:[^>]+)>/i.exec(headerVal);
  return mailtoMatch ? mailtoMatch[1] : "";
}

function detectCategory(fromAddr, subject, text, unsubUrl, prec) {
  const lowerFrom = (fromAddr || "").toLowerCase();
  const hay = ((subject || "") + " " + (text || "")).toLowerCase();

  if (SOCIAL_DOMAINS.some(d => lowerFrom.includes(d))) return "social";
  if (prec === "bulk" || unsubUrl || PROMO_KEYWORDS.some(k => hay.includes(k))) return "promotions";
  if (UPDATE_KEYWORDS.some(k => hay.includes(k))) return "updates";
  return "primary";
}

function parseMime(raw) {
  const i = raw.search(/\r?\n\r?\n/);
  const h = hdrs(i < 0 ? raw : raw.slice(0, i));
  const unsubUrl = extractUnsubscribeUrl(h["list-unsubscribe"]);
  const out = { 
    text: "", 
    html: "", 
    subject: decodeWord(h.subject), 
    name: "", 
    unsubscribe_url: unsubUrl,
    precedence: (h["precedence"] || "").toLowerCase(),
    attachments: []
  };
  const m = /^\s*"?([^"<]*?)"?\s*</.exec(decodeWord(h.from));
  if (m) out.name = m[1].trim();
  if (i >= 0) walkMime(h, raw.slice(i).replace(/^\r?\n\r?\n/, ""), out);
  return out;
}

async function sha(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
}

async function store(env, { from, to, subject, text, html, name, unsubscribe_url, precedence, attachments = [] }) {
  from = (from || "").toLowerCase();
  to = (to || "").toLowerCase();
  const hay = ((subject || "") + " " + (text || "")).toLowerCase();
  let score = SPAM_WORDS.filter(w => hay.includes(w)).length * 2;
  if (!text && !html) score += 2;
  const blocked = await env.DB.prepare("SELECT 1 FROM blocked WHERE addr=?").bind(from).first();
  const folder = blocked || score >= 4 ? "spam" : "inbox";
  const category = detectCategory(from, subject, text, unsubscribe_url, precedence);

  const inserted = await env.DB.prepare(
    `INSERT INTO mails(domain, to_addr, from_addr, from_name, subject, text, html, folder, category, spam_score, unsubscribe_url, ts)
     VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(to.split("@")[1] || "", to, from, name || "", subject || "(no subject)",
    (text || "").slice(0, 500000), (html || "").slice(0, 1000000),
    folder, category, blocked ? 9 : score, unsubscribe_url || "", Date.now()).run();

  const mailId = inserted.meta?.last_row_id;
  if (!mailId) throw new Error("Could not determine inserted mail ID");

  for (const file of attachments) {
    const data = file.data instanceof Uint8Array ? file.data : new Uint8Array(file.data || []);
    if (!data.byteLength) continue;
    const filename = String(file.filename || "attachment").replace(/[\u0000-\u001f\u007f]/g, "").split(/[\\/]/).pop().slice(0, 240) || "attachment";
    const contentType = String(file.content_type || "application/octet-stream").slice(0, 120);
    const created = Date.now();
    if (env.FILES && typeof env.FILES.put === "function") {
      const key = `mail/${mailId}/${crypto.randomUUID()}`;
      await env.FILES.put(key, data, { httpMetadata: { contentType: "application/octet-stream" } });
      await env.DB.prepare(
        "INSERT INTO attachments(mail_id, filename, content_type, size, storage_key, created_ts) VALUES(?,?,?,?,?,?)"
      ).bind(mailId, filename, contentType, data.byteLength, key, created).run();
    } else if (data.byteLength <= 1200000) {
      await env.DB.prepare(
        "INSERT INTO attachments(mail_id, filename, content_type, size, content, created_ts) VALUES(?,?,?,?,?,?)"
      ).bind(mailId, filename, contentType, data.byteLength, data, created).run();
    } else {
      console.warn(`Attachment "${filename}" skipped: configure R2 binding FILES for large attachments.`);
    }
  }
}

function cookieHas(req, tok) {
  return (req.headers.get("cookie") || "").split(";").map(x => x.trim()).some(x => x === "s=" + tok);
}

async function getSettings(env) {
  const { results } = await env.DB.prepare("SELECT key, value FROM settings").all();
  const o = { brand: "RAD MAIL", theme: "dark", lang: "fa", avatar: "" };
  for (const r of results || []) {
    try {
      o[r.key] = JSON.parse(r.value);
    } catch {
      o[r.key] = r.value;
    }
  }
  return o;
}

async function setSettings(env, s) {
  for (const [k, v] of Object.entries(s)) {
    await env.DB.prepare("INSERT OR REPLACE INTO settings(key, value) VALUES(?,?)").bind(k, JSON.stringify(v)).run();
  }
}

async function performCleanup(env) {
  try {
    const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
    await env.DB.prepare("DELETE FROM mails WHERE folder IN ('trash', 'spam') AND ts < ?").bind(thirtyDaysAgo).run();
  } catch (e) {
    console.error("Cleanup error:", e);
  }
}

const SVG_ICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#00a2ff"/>
      <stop offset="25%" stop-color="#0077ff"/>
      <stop offset="70%" stop-color="#0050f0"/>
      <stop offset="100%" stop-color="#0038c8"/>
    </linearGradient>
    <linearGradient id="cardGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#ffffff"/>
      <stop offset="85%" stop-color="#f5f8ff"/>
      <stop offset="100%" stop-color="#e7efff"/>
    </linearGradient>
    <linearGradient id="blueWingL" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0080ff"/>
      <stop offset="100%" stop-color="#0052e0"/>
    </linearGradient>
    <linearGradient id="blueWingR" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#2196f3"/>
      <stop offset="100%" stop-color="#0062eb"/>
    </linearGradient>
    <linearGradient id="bottomRibbon" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#005be3"/>
      <stop offset="100%" stop-color="#003dbd"/>
    </linearGradient>
    <filter id="softShadow" x="-15%" y="-15%" width="130%" height="130%">
      <feDropShadow dx="0" dy="16" stdDeviation="20" flood-color="#00186b" flood-opacity="0.38"/>
      <feDropShadow dx="0" dy="4" stdDeviation="8" flood-color="#00186b" flood-opacity="0.22"/>
    </filter>
  </defs>
  <rect x="24" y="24" width="464" height="464" rx="118" fill="url(#bgGrad)" filter="url(#softShadow)"/>
  <rect x="26" y="26" width="460" height="460" rx="116" fill="none" stroke="rgba(255,255,255,0.4)" stroke-width="3"/>
  <g transform="translate(96, 126)">
    <rect x="0" y="0" width="320" height="260" rx="60" fill="url(#cardGrad)" filter="url(#softShadow)"/>
    <path d="M 0,60 C 0,38 12,20 28,10 L 88,140 L 0,195 Z" fill="url(#blueWingL)" opacity="0.95"/>
    <path d="M 68,104 L 160,188 L 292,38 C 304,48 320,64 320,85 L 320,135 L 174,235 C 165,241 155,241 146,235 L 0,132 L 0,95 Z" fill="url(#bottomRibbon)"/>
    <path d="M 2,52 C 4,24 24,4 52,4 L 268,4 C 296,4 316,24 318,52 L 318,65 L 168,168 C 163,171 157,171 152,168 L 2,65 Z" fill="#ffffff"/>
    <path d="M 12,48 L 152,148 C 157,151 163,151 168,148 L 308,48 C 304,26 288,10 266,10 L 54,10 C 32,10 16,26 12,48 Z" fill="url(#cardGrad)"/>
    <path d="M 320,80 L 160,196 L 202,230 L 320,150 Z" fill="url(#blueWingR)" opacity="0.92"/>
  </g>
</svg>`;

const MANIFEST_JSON = {
  name: "RAD MAIL",
  short_name: "RAD MAIL",
  id: "/",
  start_url: "/",
  scope: "/",
  display: "standalone",
  orientation: "portrait",
  background_color: "#141517",
  theme_color: "#1e1f22",
  description: "سیستم مدیریت ایمیل هوشمند و امن RAD MAIL",
  icons: [
    { src: "/icon-192.png", sizes: "192x192", type: "image/svg+xml", purpose: "any maskable" },
    { src: "/icon-512.png", sizes: "512x512", type: "image/svg+xml", purpose: "any maskable" }
  ]
};

const SW_CODE = `
const CACHE_NAME = 'radmail-m3-v2.2.0';
self.addEventListener('install', e => { self.skipWaiting(); });
self.addEventListener('activate', e => { e.waitUntil(clients.claim()); });
self.addEventListener('fetch', e => {});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then(w => {
    if (w.length > 0) return w[0].focus();
    return clients.openWindow('/');
  }));
});
`;

const UI_HTML = "<!doctype html>\n<html lang=\"fa\" data-theme=\"dark\" dir=\"rtl\">\n<head>\n  <meta charset=\"utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, viewport-fit=cover, maximum-scale=1.0, user-scalable=no\">\n  <meta name=\"theme-color\" content=\"#1e1f22\">\n  <meta name=\"apple-mobile-web-app-capable\" content=\"yes\">\n  <meta name=\"apple-mobile-web-app-status-bar-style\" content=\"black-translucent\">\n  <meta name=\"apple-mobile-web-app-title\" content=\"RAD MAIL\">\n  <link rel=\"manifest\" href=\"/manifest.webmanifest\">\n  <link rel=\"icon\" type=\"image/svg+xml\" href=\"/icon-192.png\">\n  <link rel=\"apple-touch-icon\" href=\"/icon-192.png\">\n  <title>RAD MAIL</title>\n  \n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link href=\"https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;700&family=Vazirmatn:wght@400;500;600;700&display=swap\" rel=\"stylesheet\">\n\n  <style>\n    :root {\n      --gm-font: 'Google Sans', 'Vazirmatn', -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif;\n      --bg-base: #f6f8fc;\n      --bg-surface: #ffffff;\n      --bg-elevated: #eef2f8;\n      --bg-search: #eaf1fb;\n      --bg-drawer: #ffffff;\n      --bg-active-pill: #c2e7ff;\n      --bg-hover: #f0f4f9;\n      --text-main: #1f1f1f;\n      --text-sub: #444746;\n      --text-muted: #727775;\n      --border-subtle: #e0e2ec;\n      --primary: #0b57d0;\n      --primary-pill-text: #001d35;\n      --fab-bg: #c2e7ff;\n      --fab-text: #001d35;\n      --unread-dot: #0b57d0;\n      --chip-bg: #e1e7f0;\n      --chip-text: #1f1f1f;\n      --star-active: #f29900;\n      --badge-promotions: #c4eed0;\n      --badge-promotions-text: #072711;\n      --badge-social: #c2e7ff;\n      --badge-social-text: #001d35;\n      --badge-updates: #ffdcc2;\n      --badge-updates-text: #2e1500;\n      --bottom-bar-bg: #edf2fa;\n      --bottom-pill: #c2e7ff;\n      --selection-bg: #22374e;\n      --selection-card: #1c2738;\n      --radius-sm: 8px;\n      --radius-md: 16px;\n      --radius-pill: 28px;\n      --radius-full: 9999px;\n      --transition: 0.2s cubic-bezier(0.4, 0, 0.2, 1);\n    }\n\n    html[data-theme=\"dark\"] {\n      --bg-base: #141517;\n      --bg-surface: #1e1f22;\n      --bg-elevated: #282a2e;\n      --bg-search: #2d2f33;\n      --bg-drawer: #1b1d22;\n      --bg-active-pill: #283344;\n      --bg-hover: #26282c;\n      --text-main: #e2e2e6;\n      --text-sub: #c4c6cb;\n      --text-muted: #8e9095;\n      --border-subtle: #2d3036;\n      --primary: #a8c7fa;\n      --primary-pill-text: #d3e3fd;\n      --fab-bg: #283348;\n      --fab-text: #d3e3fd;\n      --unread-dot: #a8c7fa;\n      --chip-bg: #2d333e;\n      --chip-text: #d3e3fd;\n      --star-active: #fdd663;\n      --badge-promotions: #233e2a;\n      --badge-promotions-text: #a8ebb5;\n      --badge-social: #203b57;\n      --badge-social-text: #b5d9fd;\n      --badge-updates: #4c301d;\n      --badge-updates-text: #fecfa6;\n      --bottom-bar-bg: #1e1f22;\n      --bottom-pill: #283348;\n      --selection-bg: #1c2b3e;\n      --selection-card: #202d3f;\n    }\n\n    html[dir=\"rtl\"] {\n      --gm-font: 'Vazirmatn', 'Google Sans', -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif;\n    }\n\n    * { box-sizing: border-box; margin: 0; padding: 0; -webkit-tap-highlight-color: transparent; }\n    body {\n      font-family: var(--gm-font);\n      background-color: var(--bg-base);\n      color: var(--text-main);\n      height: 100vh;\n      overflow: hidden;\n      display: flex;\n      flex-direction: column;\n    }\n\n    button, input, select, textarea { font-family: inherit; }\n    button { cursor: pointer; border: none; background: none; outline: none; }\n\n    /* Top Search Header */\n    .top-header-area {\n      padding: 10px 14px 6px;\n      display: flex;\n      align-items: center;\n      justify-content: center;\n      z-index: 50;\n      flex-shrink: 0;\n      width: 100%;\n      transition: all var(--transition);\n    }\n\n    .gmail-search-pill {\n      width: 100%;\n      max-width: 880px;\n      height: 52px;\n      background: var(--bg-search);\n      border-radius: var(--radius-pill);\n      display: flex;\n      align-items: center;\n      padding: 0 8px 0 14px;\n      gap: 12px;\n      box-shadow: 0 1px 3px rgba(0,0,0,0.22);\n      transition: background var(--transition);\n    }\n\n    /* Top Selection Action Bar (Matching Screenshot 3) */\n    .selection-action-bar {\n      display: none;\n      width: 100%;\n      max-width: 880px;\n      height: 52px;\n      align-items: center;\n      padding: 0 4px 0 8px;\n      background: transparent;\n      gap: 4px;\n      z-index: 55;\n    }\n    body.is-selection-mode .gmail-search-pill { display: none !important; }\n    body.is-selection-mode .selection-action-bar { display: flex; }\n    body.is-selection-mode .top-header-area { background: var(--selection-bg); }\n\n    .selection-count-badge {\n      font-size: 18px;\n      font-weight: 700;\n      color: var(--text-main);\n      margin-left: 8px;\n      margin-right: 8px;\n    }\n\n    .select-all-row {\n      display: none;\n      padding: 8px 18px;\n      background: var(--selection-bg);\n      border-bottom: 1px solid var(--border-subtle);\n      font-size: 13px;\n      font-weight: 600;\n      color: var(--primary);\n      align-items: center;\n      gap: 10px;\n      cursor: pointer;\n    }\n    body.is-selection-mode .select-all-row { display: flex; }\n\n    .icon-btn {\n      width: 40px;\n      height: 40px;\n      border-radius: var(--radius-full);\n      display: flex;\n      align-items: center;\n      justify-content: center;\n      color: var(--text-sub);\n      transition: background var(--transition);\n      flex-shrink: 0;\n    }\n    .icon-btn:hover { background: var(--bg-hover); color: var(--text-main); }\n    .icon-btn svg { width: 22px; height: 22px; fill: currentColor; }\n\n    .search-input-box { flex: 1; min-width: 0; }\n    .search-input-box input {\n      width: 100%;\n      border: none;\n      background: transparent;\n      outline: none;\n      font-size: 16px;\n      color: var(--text-main);\n    }\n    .search-input-box input::placeholder { color: var(--text-muted); }\n\n    .user-avatar {\n      width: 34px;\n      height: 34px;\n      border-radius: var(--radius-full);\n      background: #7a40b8;\n      color: white;\n      display: flex;\n      align-items: center;\n      justify-content: center;\n      font-weight: 700;\n      font-size: 15px;\n      cursor: pointer;\n      overflow: hidden;\n      flex-shrink: 0;\n    }\n    .user-avatar img { width: 100%; height: 100%; object-fit: cover; display: block; }\n\n    .view-section-header {\n      padding: 10px 18px 4px;\n      font-size: 13px;\n      font-weight: 600;\n      color: var(--text-sub);\n      letter-spacing: 0.2px;\n      display: flex;\n      align-items: center;\n      justify-content: space-between;\n    }\n\n    .workspace {\n      flex: 1;\n      display: flex;\n      overflow: hidden;\n      position: relative;\n    }\n\n    /* Drawer Navigation */\n    .sidebar-backdrop {\n      position: fixed;\n      inset: 0;\n      background: rgba(0,0,0,0.6);\n      backdrop-filter: blur(2px);\n      z-index: 90;\n      display: none;\n    }\n    .sidebar-backdrop.open { display: block; }\n\n    .drawer-nav {\n      position: fixed;\n      top: 0;\n      left: -320px;\n      bottom: 0;\n      width: 300px;\n      background: var(--bg-drawer);\n      z-index: 100;\n      display: flex;\n      flex-direction: column;\n      overflow-y: auto;\n      transition: left 0.25s cubic-bezier(0.4, 0, 0.2, 1), right 0.25s cubic-bezier(0.4, 0, 0.2, 1);\n      padding: 18px 12px 24px;\n      box-shadow: 4px 0 24px rgba(0,0,0,0.4);\n    }\n    html[dir=\"rtl\"] .drawer-nav {\n      left: auto;\n      right: -320px;\n      box-shadow: -4px 0 24px rgba(0,0,0,0.4);\n    }\n    .drawer-nav.open { left: 0; }\n    html[dir=\"rtl\"] .drawer-nav.open { right: 0; }\n\n    .drawer-header-brand {\n      padding: 4px 14px 18px;\n      font-size: 22px;\n      font-weight: 700;\n      color: var(--text-main);\n      display: flex;\n      align-items: center;\n      gap: 12px;\n    }\n\n    .drawer-item {\n      height: 48px;\n      padding: 0 16px;\n      border-radius: var(--radius-pill);\n      display: flex;\n      align-items: center;\n      gap: 16px;\n      color: var(--text-sub);\n      font-size: 14px;\n      font-weight: 500;\n      transition: background var(--transition);\n      user-select: none;\n      margin-bottom: 2px;\n    }\n    .drawer-item:hover { background: var(--bg-hover); color: var(--text-main); }\n    .drawer-item.active {\n      background: var(--bg-active-pill);\n      color: var(--primary-pill-text);\n      font-weight: 700;\n    }\n    .drawer-item svg { width: 22px; height: 22px; fill: currentColor; flex-shrink: 0; }\n    .drawer-item .badge {\n      margin-left: auto;\n      font-size: 12px;\n      font-weight: 700;\n      padding: 3px 10px;\n      border-radius: var(--radius-pill);\n    }\n    html[dir=\"rtl\"] .drawer-item .badge { margin-left: 0; margin-right: auto; }\n    .badge-count { color: var(--text-muted); font-size: 13px; font-weight: 500; margin-left: auto; }\n    html[dir=\"rtl\"] .badge-count { margin-left: 0; margin-right: auto; }\n    .badge-promo { background: var(--badge-promotions); color: var(--badge-promotions-text); }\n    .badge-social { background: var(--badge-social); color: var(--badge-social-text); }\n    .badge-updates { background: var(--badge-updates); color: var(--badge-updates-text); }\n\n    .drawer-section-label {\n      padding: 16px 16px 6px;\n      font-size: 12px;\n      font-weight: 700;\n      color: var(--text-muted);\n      letter-spacing: 0.4px;\n    }\n    .drawer-divider { height: 1px; background: var(--border-subtle); margin: 8px 12px; }\n\n    .mail-scroll-pane {\n      flex: 1;\n      overflow-y: auto;\n      display: flex;\n      flex-direction: column;\n      position: relative;\n    }\n\n    /* Mail Item (Screenshot 1 & 3 Pixel-Perfect) */\n    .mail-card-item {\n      display: flex;\n      align-items: flex-start;\n      padding: 12px 16px;\n      gap: 14px;\n      border-bottom: 1px solid var(--border-subtle);\n      cursor: pointer;\n      transition: background var(--transition);\n      user-select: none;\n      position: relative;\n    }\n    .mail-card-item:hover { background: var(--bg-hover); }\n    .mail-card-item.unread {\n      background: var(--bg-surface);\n    }\n    .mail-card-item.unread .sender-text {\n      font-weight: 700;\n      color: var(--text-main);\n    }\n    .mail-card-item.unread .subject-text {\n      font-weight: 600;\n      color: var(--text-main);\n    }\n    .mail-card-item:not(.unread) .sender-text {\n      font-weight: 500;\n      color: var(--text-sub);\n    }\n    .mail-card-item:not(.unread) .subject-text {\n      font-weight: 400;\n      color: var(--text-sub);\n    }\n\n    .mail-card-item.selected {\n      background: var(--selection-card) !important;\n    }\n\n    .circle-avatar {\n      width: 40px;\n      height: 40px;\n      border-radius: var(--radius-full);\n      display: flex;\n      align-items: center;\n      justify-content: center;\n      font-size: 17px;\n      font-weight: 700;\n      color: #ffffff;\n      flex-shrink: 0;\n      margin-top: 2px;\n      transition: transform 0.18s ease, background 0.18s ease;\n    }\n    .mail-card-item.selected .circle-avatar {\n      background: #1a73e8 !important;\n    }\n    .mail-card-item.selected .circle-avatar svg {\n      width: 22px;\n      height: 22px;\n      fill: #ffffff;\n    }\n\n    .mail-body-content {\n      flex: 1;\n      min-width: 0;\n      display: flex;\n      flex-direction: column;\n      gap: 3px;\n    }\n\n    .line-top {\n      display: flex;\n      align-items: center;\n      justify-content: space-between;\n      gap: 8px;\n    }\n    .sender-text {\n      font-size: 15px;\n      white-space: nowrap;\n      overflow: hidden;\n      text-overflow: ellipsis;\n    }\n    .date-and-dot {\n      display: flex;\n      align-items: center;\n      gap: 6px;\n      flex-shrink: 0;\n    }\n    .mail-time-text {\n      font-size: 12px;\n      color: var(--text-muted);\n      font-weight: 500;\n    }\n    .unread-indicator-dot {\n      width: 8px;\n      height: 8px;\n      border-radius: 50%;\n      background: var(--unread-dot);\n      display: inline-block;\n    }\n\n    .subject-text {\n      font-size: 14px;\n      white-space: nowrap;\n      overflow: hidden;\n      text-overflow: ellipsis;\n      line-height: 1.35;\n    }\n\n    .snippet-text {\n      font-size: 13px;\n      color: var(--text-muted);\n      white-space: nowrap;\n      overflow: hidden;\n      text-overflow: ellipsis;\n      line-height: 1.35;\n    }\n\n    .mail-action-chips {\n      display: flex;\n      align-items: center;\n      gap: 8px;\n      margin-top: 6px;\n      flex-wrap: wrap;\n    }\n    .action-chip-pill {\n      height: 30px;\n      padding: 0 12px;\n      border-radius: var(--radius-pill);\n      background: var(--chip-bg);\n      color: var(--chip-text);\n      font-size: 12px;\n      font-weight: 600;\n      display: inline-flex;\n      align-items: center;\n      gap: 6px;\n      border: 1px solid rgba(255,255,255,0.06);\n    }\n    .action-chip-pill svg { width: 14px; height: 14px; fill: currentColor; }\n\n    .star-cell {\n      padding-top: 4px;\n      color: var(--text-muted);\n      display: flex;\n      align-items: center;\n      justify-content: center;\n    }\n    .star-cell.starred { color: var(--star-active); }\n    .star-cell svg { width: 22px; height: 22px; fill: currentColor; }\n\n    /* New Address Floating FAB */\n    .compose-floating-fab {\n      position: fixed;\n      bottom: 74px;\n      right: 18px;\n      height: 56px;\n      padding: 0 22px 0 18px;\n      border-radius: 16px;\n      background: var(--fab-bg);\n      color: var(--fab-text);\n      display: inline-flex;\n      align-items: center;\n      gap: 12px;\n      font-size: 15px;\n      font-weight: 700;\n      box-shadow: 0 4px 16px rgba(0,0,0,0.35);\n      z-index: 60;\n      transition: all var(--transition);\n    }\n    html[dir=\"rtl\"] .compose-floating-fab { right: auto; left: 18px; padding: 0 18px 0 22px; }\n    .compose-floating-fab:active { transform: scale(0.96); }\n    .compose-floating-fab svg { width: 22px; height: 22px; fill: currentColor; }\n\n    /* Small round FAB when in selection mode (Screenshot 3) */\n    body.is-selection-mode .compose-floating-fab {\n      padding: 0;\n      width: 56px;\n      border-radius: 16px;\n      justify-content: center;\n    }\n    body.is-selection-mode .compose-floating-fab span { display: none; }\n\n    .bottom-nav-bar {\n      height: 60px;\n      background: var(--bottom-bar-bg);\n      border-top: 1px solid var(--border-subtle);\n      display: flex;\n      align-items: center;\n      justify-content: space-around;\n      z-index: 45;\n      flex-shrink: 0;\n    }\n    .bottom-tab {\n      display: flex;\n      align-items: center;\n      justify-content: center;\n      position: relative;\n      cursor: pointer;\n    }\n    .bottom-tab-pill {\n      height: 32px;\n      padding: 0 20px;\n      border-radius: var(--radius-pill);\n      display: flex;\n      align-items: center;\n      justify-content: center;\n      position: relative;\n      color: var(--text-sub);\n    }\n    .bottom-tab.active .bottom-tab-pill {\n      background: var(--bottom-pill);\n      color: var(--primary-pill-text);\n    }\n    .bottom-tab svg { width: 24px; height: 24px; fill: currentColor; }\n    .bottom-badge {\n      position: absolute;\n      top: -4px;\n      right: 10px;\n      background: #c5221f;\n      color: white;\n      font-size: 10px;\n      font-weight: 800;\n      padding: 1px 5px;\n      border-radius: 99px;\n      border: 2px solid var(--bottom-bar-bg);\n    }\n\n    /* Email Reader Screen */\n    .mail-reader-overlay {\n      position: fixed;\n      inset: 0;\n      background: var(--bg-surface);\n      z-index: 80;\n      display: none;\n      flex-direction: column;\n      overflow-y: auto;\n    }\n    body.is-reading-mail .mail-reader-overlay { display: flex; }\n    body.is-reading-mail .top-header-area,\n    body.is-reading-mail .select-all-row,\n    body.is-reading-mail .bottom-nav-bar,\n    body.is-reading-mail .compose-floating-fab { display: none !important; }\n\n    .reader-toolbar {\n      height: 56px;\n      display: flex;\n      align-items: center;\n      padding: 0 10px;\n      gap: 4px;\n      border-bottom: 1px solid var(--border-subtle);\n      background: var(--bg-surface);\n      position: sticky;\n      top: 0;\n      z-index: 10;\n    }\n\n    .reader-body-content {\n      padding: 16px;\n      display: flex;\n      flex-direction: column;\n      gap: 16px;\n      max-width: 860px;\n      width: 100%;\n      margin: 0 auto;\n    }\n\n    .reader-subject {\n      font-size: 20px;\n      font-weight: 700;\n      color: var(--text-main);\n      line-height: 1.4;\n    }\n\n    .reader-sender-row {\n      display: flex;\n      align-items: center;\n      gap: 12px;\n    }\n    .reader-sender-info { flex: 1; min-width: 0; }\n    .reader-sender-name { font-size: 15px; font-weight: 700; color: var(--text-main); }\n    .reader-to-line { font-size: 12px; color: var(--text-muted); }\n\n    .reader-iframe-box {\n      width: 100%;\n      border-radius: var(--radius-sm);\n      overflow-x: hidden;\n      background: #ffffff;\n      border: 1px solid var(--border-subtle);\n    }\n    .reader-iframe-box iframe {\n      width: 100%;\n      border: none;\n      min-height: 380px;\n      display: block;\n    }\n    .attachment-list { border:1px solid var(--border-subtle); border-radius:14px; padding:12px; background:var(--bg-elevated); display:flex; flex-direction:column; gap:8px; }\n    .attachment-heading { font-size:13px; font-weight:700; color:var(--text-sub); margin-bottom:2px; }\n    .attachment-item { display:flex; align-items:center; gap:10px; min-width:0; padding:10px 12px; border:1px solid var(--border-subtle); border-radius:11px; background:var(--bg-surface); color:var(--text-main); text-decoration:none; }\n    .attachment-file-icon { width:36px; height:36px; border-radius:10px; display:grid; place-items:center; background:var(--bg-active-pill); flex-shrink:0; }\n    .attachment-file-info { display:flex; flex-direction:column; gap:3px; min-width:0; flex:1; }\n    .attachment-file-info strong { font-size:13px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }\n    .attachment-file-info small { font-size:11px; color:var(--text-muted); }\n    .attachment-download { font-size:12px; font-weight:700; color:var(--primary); flex-shrink:0; }\n    .reader-plain-box {\n      white-space: pre-wrap;\n      font-size: 14px;\n      line-height: 1.8;\n      background: var(--bg-elevated);\n      padding: 16px;\n      border-radius: var(--radius-sm);\n      border: 1px solid var(--border-subtle);\n    }\n\n    /* Modal Sheet */\n    .modal-overlay {\n      position: fixed;\n      inset: 0;\n      background: rgba(0,0,0,0.55);\n      backdrop-filter: blur(4px);\n      display: none;\n      align-items: center;\n      justify-content: center;\n      z-index: 120;\n      padding: 16px;\n    }\n    .modal-overlay.open { display: flex; }\n    .modal-card {\n      background: var(--bg-surface);\n      border-radius: 20px;\n      width: min(460px, 100%);\n      box-shadow: 0 10px 30px rgba(0,0,0,0.4);\n      overflow: hidden;\n      border: 1px solid var(--border-subtle);\n    }\n    .modal-header {\n      padding: 16px 20px;\n      border-bottom: 1px solid var(--border-subtle);\n      display: flex;\n      align-items: center;\n      justify-content: space-between;\n      font-size: 16px;\n      font-weight: 700;\n    }\n    .modal-body { padding: 18px 20px; display: flex; flex-direction: column; gap: 14px; }\n    .modal-footer {\n      padding: 12px 20px;\n      border-top: 1px solid var(--border-subtle);\n      display: flex;\n      justify-content: flex-end;\n      gap: 10px;\n    }\n\n    .profile-sheet {\n      display: flex;\n      flex-direction: column;\n      align-items: center;\n      text-align: center;\n      padding: 10px 0;\n    }\n    .profile-sheet-avatar {\n      width: 90px;\n      height: 90px;\n      border-radius: 50%;\n      background: #7a40b8;\n      color: white;\n      font-size: 36px;\n      font-weight: 700;\n      display: flex;\n      align-items: center;\n      justify-content: center;\n      margin-bottom: 12px;\n      position: relative;\n      cursor: pointer;\n      overflow: hidden;\n    }\n    .profile-sheet-avatar img { width: 100%; height: 100%; object-fit: cover; }\n    .camera-tag {\n      position: absolute;\n      bottom: 2px;\n      right: 2px;\n      width: 28px;\n      height: 28px;\n      border-radius: 50%;\n      background: var(--bg-surface);\n      border: 2px solid var(--border-subtle);\n      display: flex;\n      align-items: center;\n      justify-content: center;\n      color: var(--primary);\n    }\n    .camera-tag svg { width: 16px; height: 16px; fill: currentColor; }\n\n    .btn-pill {\n      height: 40px;\n      padding: 0 20px;\n      border-radius: var(--radius-pill);\n      border: 1px solid var(--border-subtle);\n      background: var(--bg-elevated);\n      color: var(--text-main);\n      font-size: 13px;\n      font-weight: 600;\n      display: inline-flex;\n      align-items: center;\n      gap: 8px;\n    }\n    .btn-pill.primary {\n      background: var(--primary);\n      color: #001d35;\n      font-weight: 700;\n      border: none;\n    }\n\n    .form-group { display: flex; flex-direction: column; gap: 6px; }\n    .form-group label { font-size: 13px; font-weight: 600; color: var(--text-sub); }\n    .form-control {\n      height: 44px;\n      border-radius: var(--radius-sm);\n      border: 1px solid var(--border-subtle);\n      background: var(--bg-elevated);\n      color: var(--text-main);\n      padding: 0 12px;\n      outline: none;\n    }\n\n    .snackbar {\n      position: fixed;\n      bottom: 24px;\n      left: 50%;\n      transform: translateX(-50%) translateY(30px);\n      background: #323232;\n      color: #fff;\n      padding: 10px 20px;\n      border-radius: var(--radius-pill);\n      font-size: 13px;\n      box-shadow: 0 4px 14px rgba(0,0,0,0.4);\n      opacity: 0;\n      transition: all 0.25s ease;\n      z-index: 150;\n      pointer-events: none;\n    }\n    .snackbar.show { opacity: 1; transform: translateX(-50%) translateY(0); }\n\n    .login-overlay { position:fixed; inset:0; z-index:300; display:none; align-items:center; justify-content:center; padding:22px; background:var(--bg-base); }\n    .login-overlay.open { display:flex; }\n    .login-card { width:min(420px,100%); padding:28px; border:1px solid var(--border-subtle); border-radius:24px; background:var(--bg-surface); box-shadow:0 18px 55px rgba(0,0,0,.28); }\n    .login-brand { display:flex; align-items:center; justify-content:center; gap:12px; margin-bottom:22px; font-size:22px; font-weight:800; }\n    .login-brand img { width:42px; height:42px; border-radius:12px; }\n    .login-card p { color:var(--text-muted); font-size:13px; line-height:1.8; text-align:center; margin-bottom:18px; }\n    .login-card input { width:100%; height:48px; border-radius:12px; border:1px solid var(--border-subtle); background:var(--bg-elevated); color:var(--text-main); padding:0 14px; outline:none; }\n    .login-card input:focus { border-color:var(--primary); }\n    .login-submit { width:100%; height:48px; margin-top:12px; border-radius:999px; background:var(--primary); color:#071a2e; font-weight:800; }\n    .login-submit:disabled { opacity:.65; }\n    .login-error { min-height:20px; margin-top:10px; color:#e57373; font-size:12px; text-align:center; }\n  </style>\n</head>\n<body>\n\n  <input type=\"file\" id=\"avatarFileInput\" accept=\"image/*\" style=\"display:none;\">\n\n  <header class=\"top-header-area\">\n    <!-- Standard Search Pill -->\n    <div class=\"gmail-search-pill\">\n      <button class=\"icon-btn\" id=\"menuToggleBtn\" title=\"Main menu\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z\"/></svg>\n      </button>\n\n      <div class=\"search-input-box\">\n        <input type=\"text\" id=\"searchInput\" placeholder=\"Search in mail\" autocomplete=\"off\">\n      </div>\n\n      <div class=\"user-avatar\" id=\"topAvatar\" title=\"Google Account\">M</div>\n    </div>\n\n    <!-- Multi-Selection Action Bar (Matching Screenshot 3) -->\n    <div class=\"selection-action-bar\" id=\"selectionActionBar\">\n      <button class=\"icon-btn\" id=\"cancelSelectionBtn\" title=\"Clear selection\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z\"/></svg>\n      </button>\n\n      <span class=\"selection-count-badge\" id=\"selectionCount\">1</span>\n\n      <div style=\"flex:1;\"></div>\n\n      <button class=\"icon-btn\" id=\"bulkArchiveBtn\" title=\"Archive\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"m20.54 5.23-1.39-1.68C18.88 3.21 18.47 3 18 3H6c-.47 0-.88.21-1.16.55L3.46 5.23C3.17 5.57 3 6.02 3 6.5V19c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V6.5c0-.48-.17-.93-.46-1.27zM6.24 5h11.52l.83 1H5.42l.82-1zM5 19V8h14v11H5zm11-5.5h-2.5V10h-3v3.5H8l4 4 4-4z\"/></svg>\n      </button>\n\n      <button class=\"icon-btn\" id=\"bulkDeleteBtn\" title=\"Delete\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z\"/></svg>\n      </button>\n\n      <button class=\"icon-btn\" id=\"bulkReadBtn\" title=\"Mark as read/unread\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4-8 5-8-5V6l8 5 8-5v2z\"/></svg>\n      </button>\n\n      <button class=\"icon-btn\" id=\"bulkMoreBtn\" title=\"More options\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z\"/></svg>\n      </button>\n    </div>\n  </header>\n\n  <!-- Select All Ribbon -->\n  <div class=\"select-all-row\" id=\"selectAllRow\">\n    <svg width=\"20\" height=\"20\" viewBox=\"0 0 24 24\" fill=\"currentColor\"><path d=\"M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-2 10H7v-2h10v2z\"/></svg>\n    <span id=\"selectAllLabel\">Select all</span>\n  </div>\n\n  <div class=\"view-section-header\" id=\"currentSectionTitle\">\n    <span id=\"sectionLabel\">Primary</span>\n  </div>\n\n  <div class=\"workspace\">\n    <div class=\"sidebar-backdrop\" id=\"sidebarBackdrop\"></div>\n\n    <aside class=\"drawer-nav\" id=\"drawerNav\">\n      <div class=\"drawer-header-brand\">\n        <img src=\"/icon-192.png\" width=\"32\" height=\"32\" style=\"border-radius:8px;\" alt=\"RAD MAIL\">\n        <span>RAD MAIL</span>\n      </div>\n\n      <button class=\"drawer-item\" data-folder=\"all-inboxes\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V5h14v14z\"/><path d=\"M7 12h10v2H7z\"/></svg>\n        <span data-i18n=\"all_inboxes\">All inboxes</span>\n      </button>\n\n      <div class=\"drawer-divider\"></div>\n\n      <button class=\"drawer-item active\" data-folder=\"inbox\" data-cat=\"primary\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M19 3H4.99c-1.11 0-1.98.89-1.98 2L3 19c0 1.1.88 2 1.99 2H19c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 12h-4c0 1.66-1.35 3-3 3s-3-1.34-3-3H4.99V5H19v10z\"/></svg>\n        <span data-i18n=\"primary\">Primary</span>\n        <span class=\"badge-count\" id=\"drawerCountPrimary\">0</span>\n      </button>\n\n      <button class=\"drawer-item\" data-folder=\"inbox\" data-cat=\"promotions\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M21.41 11.58l-9-9C12.05 2.22 11.55 2 11 2H4c-1.1 0-2 .9-2 2v7c0 .55.22 1.05.59 1.42l9 9c.36.36.86.58 1.41.58.55 0 1.05-.22 1.41-.59l7-7c.37-.36.59-.86.59-1.41 0-.55-.23-1.06-.59-1.42zM5.5 7C4.67 7 4 6.33 4 5.5S4.67 4 5.5 4 7 4.67 7 5.5 6.33 7 5.5 7z\"/></svg>\n        <span data-i18n=\"promotions\">Promotions</span>\n        <span class=\"badge badge-promo\" id=\"drawerCountPromo\" style=\"display:none;\">0 new</span>\n      </button>\n\n      <button class=\"drawer-item\" data-folder=\"inbox\" data-cat=\"social\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 3s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z\"/></svg>\n        <span data-i18n=\"social\">Social</span>\n        <span class=\"badge badge-social\" id=\"drawerCountSocial\" style=\"display:none;\">0 new</span>\n      </button>\n\n      <button class=\"drawer-item\" data-folder=\"inbox\" data-cat=\"updates\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z\"/></svg>\n        <span data-i18n=\"updates\">Updates</span>\n        <span class=\"badge badge-updates\" id=\"drawerCountUpdates\" style=\"display:none;\">0 new</span>\n      </button>\n\n      <div class=\"drawer-section-label\" data-i18n=\"all_labels\">All labels</div>\n\n      <button class=\"drawer-item\" data-folder=\"starred\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"m12 17.27 4.15 2.51c.76.46 1.69-.22 1.49-1.08l-1.1-4.72 3.67-3.18c.67-.58.31-1.68-.57-1.75l-4.83-.41-1.89-4.46c-.34-.81-1.5-.81-1.84 0L9.19 8.63l-4.83.41c-.88.07-1.24 1.17-.57 1.75l3.67 3.18-1.1 4.72c-.2.86.73 1.54 1.49 1.08l4.15-2.5z\"/></svg>\n        <span data-i18n=\"starred\">Starred</span>\n        <span class=\"badge-count\" id=\"drawerCountStarred\">0</span>\n      </button>\n\n      <button class=\"drawer-item\" data-filter=\"pinned\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z\"/></svg>\n        <span data-i18n=\"snoozed\">Snoozed / Pinned</span>\n      </button>\n\n      <button class=\"drawer-item\" data-filter=\"purchases\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M18 6h-2c0-2.21-1.79-4-4-4S8 3.79 8 6H6c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2zm-6-2c1.1 0 2 .9 2 2h-4c0-1.1.9-2 2-2zm6 16H6V8h2v2c0 .55.45 1 1 1s1-.45 1-1V8h4v2c0 .55.45 1 1 1s1-.45 1-1V8h2v12z\"/></svg>\n        <span data-i18n=\"purchases\">Purchases</span>\n        <span class=\"badge-count\" id=\"drawerCountPurchases\">0</span>\n      </button>\n\n      <button class=\"drawer-item\" data-folder=\"archive\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M2.01 21L23 12 2.01 3 2 10l15 2-15 2z\"/></svg>\n        <span data-i18n=\"sent\">Sent</span>\n      </button>\n\n      <button class=\"drawer-item\" data-folder=\"all\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M19 3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.11 0 2-.9 2-2V5c0-1.1-.89-2-2-2zm0 16H5V7h14v12zm0-14H5V5h14v2z\"/></svg>\n        <span data-i18n=\"all_mail\">All mail</span>\n        <span class=\"badge-count\" id=\"drawerCountAllMail\">0</span>\n      </button>\n\n      <button class=\"drawer-item\" data-folder=\"spam\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M15.73 3H8.27L3 8.27v7.46L8.27 21h7.46L21 15.73V8.27L15.73 3zM12 17.3c-.72 0-1.3-.58-1.3-1.3 0-.72.58-1.3 1.3-1.3.72 0 1.3.58 1.3 1.3 0 .72-.58 1.3-1.3 1.3zm1-4.3h-2V7h2v6z\"/></svg>\n        <span data-i18n=\"spam\">Spam</span>\n        <span class=\"badge-count\" id=\"drawerCountSpam\">0</span>\n      </button>\n\n      <button class=\"drawer-item\" data-folder=\"trash\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z\"/></svg>\n        <span data-i18n=\"trash\">Trash</span>\n        <span class=\"badge-count\" id=\"drawerCountTrash\">0</span>\n      </button>\n\n      <div class=\"drawer-section-label\" data-i18n=\"google_apps\">Google apps</div>\n\n      <button class=\"drawer-item\" data-page=\"mailboxes\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4-8 5-8-5V6l8 5 8-5v2z\"/></svg>\n        <span data-i18n=\"mailboxes\">Mailboxes</span>\n      </button>\n\n      <button class=\"drawer-item\" data-page=\"contacts\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z\"/></svg>\n        <span data-i18n=\"contacts\">Contacts</span>\n      </button>\n\n      <div class=\"drawer-divider\"></div>\n\n      <button class=\"drawer-item\" data-page=\"settings\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z\"/></svg>\n        <span data-i18n=\"settings\">Settings</span>\n      </button>\n\n      <button class=\"drawer-item\" id=\"helpFeedbackBtn\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 16h-2v-2h2v2zm1.07-7.75l-.9.92C12.45 11.9 12 12.5 12 14h-2v-.5c0-1.1.45-2.1 1.17-2.83l1.24-1.26c.37-.36.59-.86.59-1.41 0-1.1-.9-2-2-2s-2 .9-2 2H7c0-2.76 2.24-5 5-5s5 2.24 5 5c0 1.04-.42 1.99-1.07 2.75z\"/></svg>\n        <span data-i18n=\"help_feedback\">Help & feedback</span>\n      </button>\n\n      <div style=\"margin-top:auto; padding:16px 14px 4px; font-size:11px; font-weight:800; color:var(--text-muted);\">\n        RAD MAIL V1.4\n      </div>\n    </aside>\n\n    <main class=\"mail-scroll-pane\" id=\"mailScrollPane\">\n      <!-- Dynamically injected -->\n    </main>\n  </div>\n\n  <!-- Smart Action Button: \"New Address\" instead of Compose -->\n  <button class=\"compose-floating-fab\" id=\"composeFabBtn\">\n    <svg viewBox=\"0 0 24 24\"><path d=\"M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z\"/></svg>\n    <span data-i18n=\"new_address\">New Address</span>\n  </button>\n\n  <nav class=\"bottom-nav-bar\">\n    <div class=\"bottom-tab active\" id=\"tabMail\">\n      <div class=\"bottom-tab-pill\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4-8 5-8-5V6l8 5 8-5v2z\"/></svg>\n        <span class=\"bottom-badge\" id=\"bottomBadge\" style=\"display:none;\">0</span>\n      </div>\n    </div>\n    <div class=\"bottom-tab\" id=\"tabVideo\">\n      <div class=\"bottom-tab-pill\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M17 10.5V7c0-.55-.45-1-1-1H4c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h12c.55 0 1-.45 1-1v-3.5l4 4v-11l-4 4z\"/></svg>\n      </div>\n    </div>\n  </nav>\n\n  <div class=\"mail-reader-overlay\" id=\"mailReaderOverlay\">\n    <div class=\"reader-toolbar\">\n      <button class=\"icon-btn\" onclick=\"closeMailReader()\" title=\"Back\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z\"/></svg>\n      </button>\n\n      <div style=\"flex:1;\"></div>\n\n      <button class=\"icon-btn\" id=\"readerArchiveBtn\" title=\"Archive\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"m20.54 5.23-1.39-1.68C18.88 3.21 18.47 3 18 3H6c-.47 0-.88.21-1.16.55L3.46 5.23C3.17 5.57 3 6.02 3 6.5V19c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V6.5c0-.48-.17-.93-.46-1.27zM6.24 5h11.52l.83 1H5.42l.82-1zM5 19V8h14v11H5zm11-5.5h-2.5V10h-3v3.5H8l4 4 4-4z\"/></svg>\n      </button>\n\n      <button class=\"icon-btn\" id=\"readerTrashBtn\" title=\"Delete\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z\"/></svg>\n      </button>\n\n      <button class=\"icon-btn\" id=\"readerUnreadBtn\" title=\"Mark as unread\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4-8 5-8-5V6l8 5 8-5v2z\"/></svg>\n      </button>\n\n      <button class=\"icon-btn\" id=\"readerStarBtn\" title=\"Star\">\n        <svg viewBox=\"0 0 24 24\"><path d=\"m12 17.27 4.15 2.51c.76.46 1.69-.22 1.49-1.08l-1.1-4.72 3.67-3.18c.67-.58.31-1.68-.57-1.75l-4.83-.41-1.89-4.46c-.34-.81-1.5-.81-1.84 0L9.19 8.63l-4.83.41c-.88.07-1.24 1.17-.57 1.75l3.67 3.18-1.1 4.72c-.2.86.73 1.54 1.49 1.08l4.15-2.5z\"/></svg>\n      </button>\n    </div>\n\n    <div class=\"reader-body-content\" id=\"readerContentZone\">\n      <!-- Injected Dynamically -->\n    </div>\n  </div>\n\n  <div class=\"modal-overlay\" id=\"globalModal\">\n    <div class=\"modal-card\" id=\"modalCard\"></div>\n  </div>\n\n  <div class=\"snackbar\" id=\"snackbar\"></div>\n\n  <section class=\"login-overlay open\" id=\"loginOverlay\" aria-label=\"Sign in\">\n    <form class=\"login-card\" id=\"loginForm\">\n      <div class=\"login-brand\"><img src=\"/icon-192.png\" alt=\"\"><span>RAD MAIL</span></div>\n      <p>برای ورود به صندوق ایمیل، رمز عبور پنل را وارد کن.</p>\n      <input id=\"loginPassword\" type=\"password\" autocomplete=\"current-password\" placeholder=\"رمز عبور پنل\" required>\n      <button class=\"login-submit\" id=\"loginSubmit\" type=\"submit\">ورود به پنل</button>\n      <div class=\"login-error\" id=\"loginError\" role=\"alert\"></div>\n    </form>\n  </section>\n\n  <script>\n    (() => {\n      const $ = (s, p = document) => p.querySelector(s);\n      const $$ = (s, p = document) => [...p.querySelectorAll(s)];\n\n      const I18N = {\n        en: {\n          search_placeholder: \"Search in mail\",\n          all_inboxes: \"All inboxes\",\n          primary: \"Primary\",\n          promotions: \"Promotions\",\n          social: \"Social\",\n          updates: \"Updates\",\n          all_labels: \"All labels\",\n          starred: \"Starred\",\n          snoozed: \"Snoozed / Pinned\",\n          purchases: \"Purchases\",\n          sent: \"Archive\",\n          all_mail: \"All mail\",\n          spam: \"Spam\",\n          trash: \"Trash\",\n          google_apps: \"Google apps\",\n          mailboxes: \"Mailboxes\",\n          contacts: \"Contacts\",\n          settings: \"Settings\",\n          help_feedback: \"Help & feedback\",\n          new_address: \"New Address\",\n          select_all: \"Select all\",\n          unselect_all: \"Unselect all\",\n          nothing_here: \"You're all done!\",\n          empty_folder: \"Nothing in\",\n          msgs: \"msgs\",\n          view_order: \"View order\",\n          order_placed: \"Order placed\",\n          unsubscribe: \"Unsubscribe\",\n          copied: \"Copied to clipboard\",\n          archived: \"Archived\",\n          deleted: \"Moved to trash\",\n          marked_unread: \"Marked unread\",\n          marked_read: \"Marked read\",\n          general_settings: \"General Settings\",\n          theme: \"Theme\",\n          light: \"Light\",\n          dark: \"Dark\",\n          language: \"Language\",\n          logout: \"Log out\",\n          logout_desc: \"End active session on this device\",\n          creator: \"Creator: Mohsen Salehi (محسن صالحی)\",\n          version: \"Version: RAD MAIL V1.4\",\n          active_inboxes: \"Active Inboxes\",\n          add_address: \"+ Add Address\",\n          export_csv: \"Export CSV\"\n        },\n        fa: {\n          search_placeholder: \"جستجو در ایمیل‌ها\",\n          all_inboxes: \"همه صندوق‌ها\",\n          primary: \"اصلی (Primary)\",\n          promotions: \"تبلیغات (Promotions)\",\n          social: \"شبکه‌های اجتماعی\",\n          updates: \"اطلاع‌رسانی‌ها\",\n          all_labels: \"همه برچسب‌ها\",\n          starred: \"ستاره‌دار\",\n          snoozed: \"سنجاق‌شده / Snoozed\",\n          purchases: \"خریدها و فاکتورها\",\n          sent: \"بایگانی\",\n          all_mail: \"همه ایمیل‌ها\",\n          spam: \"هرزنامه (اسپم)\",\n          trash: \"سطل زباله\",\n          google_apps: \"ابزارهای متصل\",\n          mailboxes: \"صندوق‌های ایمیل\",\n          contacts: \"مخاطبین هوشمند\",\n          settings: \"تنظیمات\",\n          help_feedback: \"راهنما و درباره\",\n          new_address: \"آدرس جدید\",\n          select_all: \"انتخاب همه\",\n          unselect_all: \"لغو انتخاب\",\n          nothing_here: \"صندوق شما خالی است!\",\n          empty_folder: \"ایمیلی وجود ندارد در\",\n          msgs: \"پیام\",\n          view_order: \"مشاهده سفارش\",\n          order_placed: \"ثبت سفارش\",\n          unsubscribe: \"لغو اشتراک\",\n          copied: \"در کلیپ‌بورد کپی شد\",\n          archived: \"بایگانی شد\",\n          deleted: \"به سطل زباله منتقل شد\",\n          marked_unread: \"خوانده‌نشده شد\",\n          marked_read: \"خوانده شد\",\n          general_settings: \"تنظیمات عمومی\",\n          theme: \"پوسته و تم\",\n          light: \"روشن\",\n          dark: \"تاریک\",\n          language: \"زبان برنامه\",\n          logout: \"خروج از حساب\",\n          logout_desc: \"اتمام نشست فعال روی این دستگاه\",\n          creator: \"سازنده: محسن صالحی (Mohsen Salehi)\",\n          version: \"نسخه: RAD MAIL V1.4\",\n          active_inboxes: \"صندوق‌های فعال\",\n          add_address: \"+ افزودن آدرس\",\n          export_csv: \"خروجی CSV\"\n        }\n      };\n\n      const esc = s => String(s ?? \"\").replace(/[&<>\"']/g, c => ({\n        \"&\": \"&amp;\", \"<\": \"&lt;\", \">\": \"&gt;\", '\"': \"&quot;\", \"'\": \"&#39;\"\n      }[c]));\n\n      const linkify = text => {\n        const urlRegex = /(https?:\\/\\/[^\\s<]+[^<.,:;\"')\\]\\s])/g;\n        return esc(text).replace(urlRegex, url => '<a href=\"' + url + '\" target=\"_blank\" rel=\"noopener noreferrer\">' + url + '</a>');\n      };\n\n      const formatGmailDate = ts => {\n        if (!ts) return \"\";\n        const d = new Date(ts);\n        const now = new Date();\n        const isToday = d.toDateString() === now.toDateString();\n        if (isToday) {\n          const h = String(d.getHours()).padStart(2, \"0\");\n          const m = String(d.getMinutes()).padStart(2, \"0\");\n          return h + \":\" + m;\n        }\n        const months = [\"Jan\", \"Feb\", \"Mar\", \"Apr\", \"May\", \"Jun\", \"Jul\", \"Aug\", \"Sep\", \"Oct\", \"Nov\", \"Dec\"];\n        return months[d.getMonth()] + \" \" + d.getDate();\n      };\n\n      const M3_AVATAR_PALETTE = [\n        \"#00897b\", \"#7cb342\", \"#039be5\", \"#3949ab\", \"#8e24aa\", \"#e53935\", \"#d81b60\", \"#f4511e\"\n      ];\n      const getAvatarColor = s => {\n        let hash = 0;\n        for (let i = 0; i < (s || \"\").length; i++) hash = s.charCodeAt(i) + ((hash << 5) - hash);\n        return M3_AVATAR_PALETTE[Math.abs(hash) % M3_AVATAR_PALETTE.length];\n      };\n\n      let state = {\n        folder: \"inbox\",\n        category: \"primary\",\n        customFilter: \"\",\n        mails: [],\n        currentMail: null,\n        counts: {},\n        selectedIds: new Set(),\n        labels: [],\n        mailboxes: [],\n        contacts: [],\n        settings: { brand: \"RAD MAIL\", theme: \"dark\", lang: \"fa\", avatar: \"\" },\n        searchQuery: \"\",\n        lastMaxId: 0\n      };\n\n      function t(key) {\n        const lang = state.settings.lang || \"en\";\n        return (I18N[lang] && I18N[lang][key]) || (I18N.en[key] || key);\n      }\n\n      function updateTranslations() {\n        const lang = state.settings.lang || \"en\";\n        document.documentElement.lang = lang;\n        document.documentElement.dir = lang === \"fa\" ? \"rtl\" : \"ltr\";\n\n        $$(\"[data-i18n]\").forEach(el => {\n          const k = el.dataset.i18n;\n          el.textContent = t(k);\n        });\n\n        const sInput = $(\"#searchInput\");\n        if (sInput) sInput.placeholder = t(\"search_placeholder\");\n      }\n\n      function applyTheme(th) {\n        document.documentElement.dataset.theme = th;\n        localStorage.setItem(\"rad_mail_theme\", th);\n        const metaColor = $('meta[name=\"theme-color\"]');\n        if (metaColor) metaColor.content = th === \"dark\" ? \"#1e1f22\" : \"#f6f8fc\";\n      }\n\n      function applyLang(l) {\n        state.settings.lang = l;\n        localStorage.setItem(\"rad_mail_lang\", l);\n        updateTranslations();\n        renderMailList();\n      }\n\n      applyTheme(localStorage.getItem(\"rad_mail_theme\") || \"dark\");\n      state.settings.lang = localStorage.getItem(\"rad_mail_lang\") || \"fa\";\n\n      function updateTopAvatar() {\n        const el = $(\"#topAvatar\");\n        if (!el) return;\n        const av = state.settings.avatar;\n        if (av) {\n          el.innerHTML = '<img src=\"' + esc(av) + '\" alt=\"Avatar\">';\n        } else {\n          el.textContent = (state.settings.brand || \"M\")[0].toUpperCase();\n        }\n      }\n\n      function showToast(msg) {\n        const s = $(\"#snackbar\");\n        if (!s) return;\n        s.textContent = msg;\n        s.classList.add(\"show\");\n        clearTimeout(s._timer);\n        s._timer = setTimeout(() => s.classList.remove(\"show\"), 2800);\n      }\n\n      async function api(path, opt = {}) {\n        const res = await fetch(path, {\n          credentials: \"same-origin\",\n          ...opt,\n          headers: { \"content-type\": \"application/json\", ...(opt.headers || {}) }\n        });\n        if (res.status === 401) {\n          throw new Error(\"Unauthorized\");\n        }\n        const data = await res.json().catch(() => ({}));\n        if (!res.ok) throw new Error(data.error || \"Server error\");\n        return data;\n      }\n\n      async function fetchMeta() {\n        try {\n          const d = await api(\"/api/meta\");\n          state.counts = d.counts || {};\n          state.labels = d.labels || [];\n          state.settings = { ...state.settings, ...(d.settings || {}) };\n          updateDrawerBadges();\n          updateTopAvatar();\n          updateTranslations();\n        } catch (e) {\n          console.error(e);\n        }\n      }\n\n      function updateDrawerBadges() {\n        const c = state.counts;\n        // Real-time actual counts from Cloudflare D1\n        const primaryCount = c.inbox_primary || 0;\n        const promoCount = c.inbox_promotions || 0;\n        const socialCount = c.inbox_social || 0;\n        const updatesCount = c.inbox_updates || 0;\n        const starredCount = c.starred || 0;\n        const purchasesCount = c.purchases || 0;\n        const allMailCount = c.all_mail || 0;\n        const spamCount = c.spam || 0;\n        const trashCount = c.trash || 0;\n\n        const setB = (id, val, isPill = false) => {\n          const el = $(id);\n          if (!el) return;\n          if (val > 0) {\n            el.textContent = isPill ? val + \" new\" : val;\n            el.style.display = \"\";\n          } else {\n            if (isPill) el.style.display = \"none\";\n            else el.textContent = \"0\";\n          }\n        };\n\n        setB(\"#drawerCountPrimary\", primaryCount);\n        setB(\"#drawerCountPromo\", promoCount, true);\n        setB(\"#drawerCountSocial\", socialCount, true);\n        setB(\"#drawerCountUpdates\", updatesCount, true);\n        setB(\"#drawerCountStarred\", starredCount);\n        setB(\"#drawerCountPurchases\", purchasesCount);\n        setB(\"#drawerCountAllMail\", allMailCount);\n        setB(\"#drawerCountSpam\", spamCount);\n        setB(\"#drawerCountTrash\", trashCount);\n\n        const bottomB = $(\"#bottomBadge\");\n        if (bottomB) {\n          if (primaryCount > 0) {\n            bottomB.textContent = primaryCount > 99 ? \"99+\" : primaryCount;\n            bottomB.style.display = \"\";\n          } else bottomB.style.display = \"none\";\n        }\n      }\n\n      async function fetchMails() {\n        const p = new URLSearchParams({\n          folder: state.folder,\n          category: state.folder === \"inbox\" ? state.category : \"\",\n          q: state.searchQuery\n        });\n        state.mails = (await api(\"/api/list?\" + p)) || [];\n        if (state.mails.length > 0 && !state.lastMaxId) {\n          state.lastMaxId = Math.max(...state.mails.map(m => m.id));\n        }\n      }\n\n      function updateSelectionMode() {\n        const count = state.selectedIds.size;\n        const isSelection = count > 0;\n        document.body.classList.toggle(\"is-selection-mode\", isSelection);\n        const cntEl = $(\"#selectionCount\");\n        if (cntEl) cntEl.textContent = count;\n\n        const selectAllLbl = $(\"#selectAllLabel\");\n        if (selectAllLbl) {\n          const isAll = state.mails.length > 0 && count === state.mails.length;\n          selectAllLbl.textContent = isAll ? t(\"unselect_all\") : t(\"select_all\");\n        }\n\n        // Toggle card selected classes\n        $$(\".mail-card-item\").forEach(item => {\n          const id = Number(item.dataset.id);\n          item.classList.toggle(\"selected\", state.selectedIds.has(id));\n          const av = item.querySelector(\".circle-avatar\");\n          if (av) {\n            if (state.selectedIds.has(id)) {\n              av.innerHTML = '<svg viewBox=\"0 0 24 24\"><path d=\"M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z\"/></svg>';\n            } else {\n              av.textContent = av.dataset.initial || \"M\";\n            }\n          }\n        });\n      }\n\n      function renderMailList() {\n        const pane = $(\"#mailScrollPane\");\n        if (!pane) return;\n\n        let titleKey = \"primary\";\n        if (state.folder === \"inbox\") titleKey = state.category;\n        else if (state.folder === \"starred\") titleKey = \"starred\";\n        else if (state.folder === \"spam\") titleKey = \"spam\";\n        else if (state.folder === \"archive\") titleKey = \"sent\";\n        else if (state.folder === \"trash\") titleKey = \"trash\";\n        else if (state.folder === \"all\") titleKey = \"all_mail\";\n\n        $(\"#sectionLabel\").textContent = t(titleKey);\n\n        let list = state.mails;\n        if (state.customFilter === \"pinned\") list = list.filter(m => m.pinned);\n        if (state.customFilter === \"purchases\") {\n          const kws = [\"order\", \"receipt\", \"invoice\", \"purchased\", \"subscription\", \"bill\", \"خرید\", \"رسید\"];\n          list = list.filter(m => kws.some(k => ((m.subject||\"\") + \" \" + (m.snip||\"\")).toLowerCase().includes(k)));\n        }\n\n        if (!list.length) {\n          pane.innerHTML = `\n            <div style=\"display:flex; flex-direction:column; align-items:center; justify-content:center; height:60vh; color:var(--text-muted); text-align:center; padding:20px;\">\n              <svg width=\"68\" height=\"68\" viewBox=\"0 0 24 24\" fill=\"var(--border-subtle)\"><path d=\"M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4-8 5-8-5V6l8 5 8-5v2z\"/></svg>\n              <div style=\"font-size:16px; font-weight:700; margin-top:14px; color:var(--text-main);\">${t(\"empty_folder\")} ${t(titleKey)}</div>\n              <div style=\"font-size:13px; margin-top:4px;\">${t(\"nothing_here\")}</div>\n            </div>\n          `;\n          return;\n        }\n\n        pane.innerHTML = list.map(m => {\n          const sender = m.from_name || m.from_addr.split(\"@\")[0] || \"User\";\n          const initial = (sender[0] || \"G\").toUpperCase();\n          const avColor = getAvatarColor(m.from_addr);\n          const isUnread = !m.read;\n          const isSelected = state.selectedIds.has(m.id);\n\n          const hay = ((m.subject || \"\") + \" \" + (m.snip || \"\")).toLowerCase();\n          const isOrder = [\"order\", \"receipt\", \"purchase\", \"subscription\", \"رسید\", \"خرید\"].some(k => hay.includes(k));\n\n          let chipsHtml = \"\";\n          if (isOrder) {\n            chipsHtml = `\n              <div class=\"mail-action-chips\">\n                <span class=\"action-chip-pill\">${t(\"view_order\")}</span>\n                <span class=\"action-chip-pill\" style=\"background:transparent; border:none; padding:0; color:var(--text-muted);\">\n                  <svg viewBox=\"0 0 24 24\"><path d=\"M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V5h14v14z\"/><path d=\"M7 7h10v2H7zm0 4h10v2H7zm0 4h7v2H7z\"/></svg>\n                  <span>${t(\"order_placed\")}</span>\n                </span>\n              </div>\n            `;\n          } else if (m.unsubscribe_url) {\n            chipsHtml = `\n              <div class=\"mail-action-chips\">\n                <span class=\"action-chip-pill\">${t(\"unsubscribe\")}</span>\n              </div>\n            `;\n          }\n\n          return `\n            <div class=\"mail-card-item ${isUnread ? 'unread' : ''} ${isSelected ? 'selected' : ''}\" data-id=\"${m.id}\">\n              <div class=\"circle-avatar\" style=\"background:${avColor};\" data-initial=\"${esc(initial)}\">\n                ${isSelected ? '<svg viewBox=\"0 0 24 24\"><path d=\"M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z\"/></svg>' : initial}\n              </div>\n\n              <div class=\"mail-body-content\">\n                <div class=\"line-top\">\n                  <span class=\"sender-text\">${esc(sender)}</span>\n                  <div class=\"date-and-dot\">\n                    <span class=\"mail-time-text\">${formatGmailDate(m.ts)}</span>\n                    ${isUnread ? '<span class=\"unread-indicator-dot\"></span>' : ''}\n                  </div>\n                </div>\n\n                <div class=\"subject-text\">${esc(m.subject || \"(no subject)\")}</div>\n                <div class=\"snippet-text\">${esc(m.snip || \"\")}</div>\n\n                ${chipsHtml}\n              </div>\n\n              <div class=\"star-cell ${m.starred ? 'starred' : ''}\" data-star-id=\"${m.id}\">\n                <svg viewBox=\"0 0 24 24\"><path d=\"m12 17.27 4.15 2.51c.76.46 1.69-.22 1.49-1.08l-1.1-4.72 3.67-3.18c.67-.58.31-1.68-.57-1.75l-4.83-.41-1.89-4.46c-.34-.81-1.5-.81-1.84 0L9.19 8.63l-4.83.41c-.88.07-1.24 1.17-.57 1.75l3.67 3.18-1.1 4.72c-.2.86.73 1.54 1.49 1.08l4.15-2.5z\"/></svg>\n              </div>\n            </div>\n          `;\n        }).join(\"\");\n\n        bindMailItemEvents();\n        updateSelectionMode();\n      }\n\n      function bindMailItemEvents() {\n        $$(\".mail-card-item\").forEach(item => {\n          const id = Number(item.dataset.id);\n          let pressTimer;\n\n          // Long press support (Screenshot 3)\n          const startPress = () => {\n            pressTimer = setTimeout(() => {\n              toggleSelect(id);\n              if (navigator.vibrate) navigator.vibrate(40);\n            }, 450);\n          };\n          const cancelPress = () => clearTimeout(pressTimer);\n\n          item.addEventListener(\"touchstart\", startPress, { passive: true });\n          item.addEventListener(\"touchend\", cancelPress);\n          item.addEventListener(\"touchmove\", cancelPress);\n          item.addEventListener(\"mousedown\", startPress);\n          item.addEventListener(\"mouseup\", cancelPress);\n          item.addEventListener(\"mouseleave\", cancelPress);\n\n          // Clicking Avatar directly triggers select\n          const av = item.querySelector(\".circle-avatar\");\n          if (av) {\n            av.addEventListener(\"click\", e => {\n              e.stopPropagation();\n              toggleSelect(id);\n            });\n          }\n\n          item.onclick = async e => {\n            if (e.target.closest(\".star-cell\") || e.target.closest(\".action-chip-pill\") || e.target.closest(\".circle-avatar\")) return;\n            \n            // If in selection mode, regular click selects/unselects\n            if (state.selectedIds.size > 0) {\n              toggleSelect(id);\n              return;\n            }\n\n            try {\n              const fullMail = await api(\"/api/mail?id=\" + id);\n              state.currentMail = fullMail;\n              history.pushState({ readingMail: true, id }, \"\");\n              openMailReader(fullMail);\n              const m = state.mails.find(x => x.id === id);\n              if (m) m.read = 1;\n              fetchMeta();\n            } catch (err) {\n              showToast(\"Could not open mail\");\n            }\n          };\n        });\n\n        $$(\".star-cell\").forEach(s => {\n          s.onclick = async e => {\n            e.stopPropagation();\n            const id = Number(s.dataset.starId);\n            const m = state.mails.find(x => x.id === id);\n            if (m) {\n              m.starred = m.starred ? 0 : 1;\n              s.classList.toggle(\"starred\", !!m.starred);\n            }\n            await api(\"/api/act\", { method: \"POST\", body: JSON.stringify({ id, action: \"star\" }) });\n            fetchMeta();\n          };\n        });\n      }\n\n      function toggleSelect(id) {\n        if (state.selectedIds.has(id)) state.selectedIds.delete(id);\n        else state.selectedIds.add(id);\n        updateSelectionMode();\n      }\n\n      $(\"#cancelSelectionBtn\")?.addEventListener(\"click\", () => {\n        state.selectedIds.clear();\n        updateSelectionMode();\n      });\n\n      $(\"#selectAllRow\")?.addEventListener(\"click\", () => {\n        if (state.selectedIds.size === state.mails.length) {\n          state.selectedIds.clear();\n        } else {\n          state.mails.forEach(m => state.selectedIds.add(m.id));\n        }\n        updateSelectionMode();\n      });\n\n      // Bulk action triggers\n      async function doBulk(act) {\n        if (!state.selectedIds.size) return;\n        const ids = [...state.selectedIds];\n        showToast(\"Processing \" + ids.length + \" messages...\");\n        for (const id of ids) {\n          await api(\"/api/act\", { method: \"POST\", body: JSON.stringify({ id, action: act }) });\n        }\n        state.selectedIds.clear();\n        updateSelectionMode();\n        await fetchMeta();\n        await fetchMails();\n        renderMailList();\n        showToast(\"Done\");\n      }\n\n      $(\"#bulkArchiveBtn\")?.addEventListener(\"click\", () => doBulk(\"archive\"));\n      $(\"#bulkDeleteBtn\")?.addEventListener(\"click\", () => doBulk(\"trash\"));\n      $(\"#bulkReadBtn\")?.addEventListener(\"click\", () => doBulk(\"unread\"));\n\n      window.handleIframeScale = iframe => {\n        try {\n          const doc = iframe.contentDocument || iframe.contentWindow.document;\n          if (!doc || !doc.body) return;\n          doc.querySelectorAll('a').forEach(a => {\n            a.target = '_blank';\n            a.rel = 'noopener noreferrer';\n          });\n          const body = doc.body;\n          const html = doc.documentElement;\n          body.style.margin = '0';\n          body.style.padding = '8px';\n          const scrollWidth = Math.max(body.scrollWidth, html.scrollWidth);\n          const containerWidth = iframe.parentElement.clientWidth || (window.innerWidth - 32);\n          if (scrollWidth > containerWidth && containerWidth > 0) {\n            const scale = (containerWidth - 4) / scrollWidth;\n            body.style.transformOrigin = 'top left';\n            body.style.transform = 'scale(' + scale + ')';\n            body.style.width = scrollWidth + 'px';\n            const realH = Math.max(body.scrollHeight, html.scrollHeight);\n            iframe.style.height = Math.ceil(realH * scale + 24) + 'px';\n          } else {\n            iframe.style.height = (Math.max(body.scrollHeight, html.scrollHeight) + 16) + 'px';\n          }\n        } catch (e) {}\n      };\n\n      function formatFileSize(bytes) {\n        const n = Number(bytes) || 0;\n        if (n < 1024) return n + \" B\";\n        if (n < 1024 * 1024) return (n / 1024).toFixed(1) + \" KB\";\n        return (n / (1024 * 1024)).toFixed(1) + \" MB\";\n      }\n\n      function openMailReader(m) {\n        document.body.classList.add(\"is-reading-mail\");\n\n        const sender = m.from_name || m.from_addr;\n        const initial = (sender[0] || \"G\").toUpperCase();\n        const avColor = getAvatarColor(m.from_addr);\n\n        let safeHtml = m.html || \"\";\n        if (safeHtml) {\n          const metaViewport = '<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><base target=\"_blank\"><style>html,body{margin:0;padding:8px;font-family:-apple-system,sans-serif;color:#202124;background:#fff;overflow-wrap:break-word;}img,table{max-width:100%!important;}a{color:#0b57d0;}</style>';\n          safeHtml = metaViewport + safeHtml;\n        }\n\n        $(\"#readerContentZone\").innerHTML = `\n          <div class=\"reader-subject\">${esc(m.subject || \"(no subject)\")}</div>\n\n          <div class=\"reader-sender-row\">\n            <div class=\"circle-avatar\" style=\"background:${avColor}; width:44px; height:44px; font-size:18px;\">${esc(initial)}</div>\n            <div class=\"reader-sender-info\">\n              <div class=\"reader-sender-name\">${esc(sender)}</div>\n              <div class=\"reader-to-line\">to ${esc(m.to_addr)} &bull; ${formatGmailDate(m.ts)}</div>\n            </div>\n            ${m.unsubscribe_url ? `\n              <a href=\"${esc(m.unsubscribe_url)}\" target=\"_blank\" rel=\"noopener noreferrer\" class=\"btn-pill\" style=\"font-size:11px; padding:0 12px; height:32px; color:var(--primary);\">\n                ${t(\"unsubscribe\")}\n              </a>\n            ` : ''}\n          </div>\n\n          ${(m.attachments || []).length ? `\n            <section class=\"attachment-list\" aria-label=\"Attachments\">\n              <div class=\"attachment-heading\">پیوست‌ها · ${m.attachments.length} فایل</div>\n              ${(m.attachments || []).map(file => `\n                <a class=\"attachment-item\" href=\"/api/attachment?id=${Number(file.id)}\" download>\n                  <span class=\"attachment-file-icon\">📎</span>\n                  <span class=\"attachment-file-info\">\n                    <strong>${esc(file.filename)}</strong>\n                    <small>${formatFileSize(file.size)}</small>\n                  </span>\n                  <span class=\"attachment-download\">دانلود</span>\n                </a>\n              `).join(\"\")}\n            </section>\n          ` : \"\"}\n          ${safeHtml ? `\n            <div class=\"reader-iframe-box\">\n              <iframe sandbox=\"allow-popups allow-popups-to-escape-sandbox\" referrerpolicy=\"no-referrer\" loading=\"lazy\" srcdoc=\"${esc(safeHtml)}\"></iframe>\n            </div>\n          ` : `\n            <div class=\"reader-plain-box\">${linkify(m.text || \"(empty mail)\")}</div>\n          `}\n        `;\n\n        $(\"#readerArchiveBtn\").onclick = async () => {\n          await api(\"/api/act\", { method: \"POST\", body: JSON.stringify({ id: m.id, action: \"archive\" }) });\n          closeMailReader();\n          showToast(t(\"archived\"));\n        };\n\n        $(\"#readerTrashBtn\").onclick = async () => {\n          await api(\"/api/act\", { method: \"POST\", body: JSON.stringify({ id: m.id, action: \"trash\" }) });\n          closeMailReader();\n          showToast(t(\"deleted\"));\n        };\n\n        $(\"#readerUnreadBtn\").onclick = async () => {\n          await api(\"/api/act\", { method: \"POST\", body: JSON.stringify({ id: m.id, action: \"unread\" }) });\n          closeMailReader();\n          showToast(t(\"marked_unread\"));\n        };\n\n        const starBtn = $(\"#readerStarBtn\");\n        starBtn.classList.toggle(\"starred\", !!m.starred);\n        starBtn.onclick = async () => {\n          m.starred = m.starred ? 0 : 1;\n          starBtn.classList.toggle(\"starred\", !!m.starred);\n          await api(\"/api/act\", { method: \"POST\", body: JSON.stringify({ id: m.id, action: \"star\" }) });\n        };\n      }\n\n      window.closeMailReader = () => {\n        state.currentMail = null;\n        document.body.classList.remove(\"is-reading-mail\");\n        if (history.state && history.state.readingMail) history.back();\n        fetchMails().then(renderMailList);\n      };\n\n      window.addEventListener(\"popstate\", () => {\n        if (state.currentMail) {\n          state.currentMail = null;\n          document.body.classList.remove(\"is-reading-mail\");\n          fetchMails().then(renderMailList);\n        }\n      });\n\n      const drawer = $(\"#drawerNav\");\n      const backdrop = $(\"#sidebarBackdrop\");\n      function openDrawer() { drawer.classList.add(\"open\"); backdrop.classList.add(\"open\"); }\n      function closeDrawer() { drawer.classList.remove(\"open\"); backdrop.classList.remove(\"open\"); }\n\n      $(\"#menuToggleBtn\")?.addEventListener(\"click\", openDrawer);\n      backdrop?.addEventListener(\"click\", closeDrawer);\n\n      $$(\".drawer-item\").forEach(item => {\n        item.addEventListener(\"click\", () => {\n          $$(\".drawer-item\").forEach(i => i.classList.remove(\"active\"));\n          item.classList.add(\"active\");\n          closeDrawer();\n\n          const folder = item.dataset.folder;\n          const cat = item.dataset.cat;\n          const filter = item.dataset.filter;\n          const page = item.dataset.page;\n\n          if (folder) {\n            state.folder = folder === \"all-inboxes\" ? \"inbox\" : folder;\n            state.category = cat || \"primary\";\n            state.customFilter = \"\";\n            fetchMails().then(renderMailList);\n          } else if (filter) {\n            state.customFilter = filter;\n            renderMailList();\n          } else if (page === \"mailboxes\") {\n            renderMailboxesPage();\n          } else if (page === \"contacts\") {\n            renderContactsPage();\n          } else if (page === \"settings\") {\n            renderSettingsPage();\n          }\n        });\n      });\n\n      function openModal(title, bodyHtml, footerHtml = \"\") {\n        const c = $(\"#modalCard\");\n        c.innerHTML = `\n          <div class=\"modal-header\">\n            <span>${title}</span>\n            <button class=\"icon-btn\" onclick=\"closeModal()\">✕</button>\n          </div>\n          <div class=\"modal-body\">${bodyHtml}</div>\n          <div class=\"modal-footer\">\n            <button class=\"btn-pill\" onclick=\"closeModal()\">Close</button>\n            ${footerHtml}\n          </div>\n        `;\n        $(\"#globalModal\").classList.add(\"open\");\n      }\n      window.closeModal = () => $(\"#globalModal\").classList.remove(\"open\");\n\n      function openProfileDialog() {\n        const av = state.settings.avatar;\n        const brand = state.settings.brand || \"RAD MAIL\";\n        const email = state.mailboxes[0]?.address || \"admin@\" + (location.hostname || \"radmail.local\");\n\n        openModal(\n          \"Google Account\",\n          `\n            <div class=\"profile-sheet\">\n              <div class=\"profile-sheet-avatar\" onclick=\"$('#avatarFileInput').click()\">\n                ${av ? '<img src=\"' + esc(av) + '\" alt=\"Avatar\">' : brand[0].toUpperCase()}\n                <div class=\"camera-tag\">\n                  <svg viewBox=\"0 0 24 24\"><path d=\"M4 4h3l2-2h6l2 2h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm8 3a5 5 0 1 0 0 10 5 5 0 0 0 0-10zm0 2a3 3 0 1 1 0 6 3 3 0 0 1 0-6z\"/></svg>\n                </div>\n              </div>\n              <div style=\"font-size:17px; font-weight:700;\">${esc(brand)}</div>\n              <div style=\"font-size:13px; color:var(--text-muted); font-family:monospace; margin-top:2px;\">${esc(email)}</div>\n\n              <div style=\"display:flex; gap:10px; margin-top:16px;\">\n                <button class=\"btn-pill\" onclick=\"$('#avatarFileInput').click()\">Change photo</button>\n                ${av ? '<button class=\"btn-pill\" onclick=\"removeAvatar()\">Remove</button>' : ''}\n              </div>\n            </div>\n          `\n        );\n      }\n      $(\"#topAvatar\")?.addEventListener(\"click\", openProfileDialog);\n\n      $(\"#avatarFileInput\")?.addEventListener(\"change\", async e => {\n        const file = e.target.files?.[0];\n        if (!file) return;\n        showToast(\"Processing photo...\");\n        const reader = new FileReader();\n        reader.onload = ev => {\n          const img = new Image();\n          img.onload = async () => {\n            const canvas = document.createElement(\"canvas\");\n            const size = 160;\n            canvas.width = size;\n            canvas.height = size;\n            const ctx = canvas.getContext(\"2d\");\n            const minDim = Math.min(img.width, img.height);\n            ctx.drawImage(img, (img.width-minDim)/2, (img.height-minDim)/2, minDim, minDim, 0, 0, size, size);\n            const dataUrl = canvas.toDataURL(\"image/jpeg\", 0.85);\n            state.settings.avatar = dataUrl;\n            await api(\"/api/settings\", { method: \"POST\", body: JSON.stringify({ avatar: dataUrl }) });\n            updateTopAvatar();\n            closeModal();\n            showToast(\"Profile photo updated\");\n          };\n          img.src = ev.target.result;\n        };\n        reader.readAsDataURL(file);\n      });\n\n      window.removeAvatar = async () => {\n        state.settings.avatar = \"\";\n        await api(\"/api/settings\", { method: \"POST\", body: JSON.stringify({ avatar: \"\" }) });\n        updateTopAvatar();\n        closeModal();\n        showToast(\"Photo removed\");\n      };\n\n      $(\"#helpFeedbackBtn\")?.addEventListener(\"click\", () => {\n        closeDrawer();\n        openModal(\n          t(\"help_feedback\"),\n          `\n            <div style=\"text-align:center; padding:10px 0;\">\n              <img src=\"/icon-192.png\" width=\"64\" height=\"64\" style=\"border-radius:16px; margin:0 auto 12px;\" alt=\"RAD MAIL\">\n              <h3 style=\"font-size:18px; font-weight:700;\">RAD MAIL</h3>\n              <p style=\"font-size:14px; margin-top:8px;\">${t(\"creator\")}</p>\n              <p style=\"font-size:13px; color:var(--text-muted); margin-top:4px;\">${t(\"version\")}</p>\n            </div>\n          `\n        );\n      });\n\n      async function renderMailboxesPage() {\n        const pane = $(\"#mailScrollPane\");\n        $(\"#sectionLabel\").textContent = t(\"mailboxes\");\n        const res = await api(\"/api/mailboxes\");\n        const list = res.items || [];\n\n        pane.innerHTML = `\n          <div style=\"padding:16px;\">\n            <div style=\"display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;\">\n              <div style=\"font-weight:700; font-size:16px;\">${t(\"active_inboxes\")}</div>\n              <button class=\"btn-pill primary\" onclick=\"openCreateMailboxDialog()\">${t(\"add_address\")}</button>\n            </div>\n            <div style=\"display:flex; flex-direction:column; gap:10px;\">\n              ${list.map(m => `\n                <div style=\"background:var(--bg-surface); padding:14px; border-radius:12px; border:1px solid var(--border-subtle); display:flex; justify-content:space-between; align-items:center;\">\n                  <div>\n                    <div style=\"font-weight:700; font-size:14px; font-family:monospace;\">${esc(m.address)}</div>\n                    <div style=\"font-size:12px; color:var(--text-muted); margin-top:2px;\">${esc(m.label || \"No label\")}</div>\n                  </div>\n                  <button class=\"btn-pill\" style=\"padding:0 12px; height:32px; font-size:12px;\" onclick=\"copyStr('${esc(m.address)}')\">Copy</button>\n                </div>\n              `).join(\"\") || '<div style=\"color:var(--text-muted);\">No inboxes found</div>'}\n            </div>\n          </div>\n        `;\n      }\n\n      window.openCreateMailboxDialog = () => {\n        openModal(\n          t(\"new_address\"),\n          `\n            <div class=\"form-group\">\n              <label>Username (e.g. support, info)</label>\n              <input class=\"form-control\" id=\"mbUser\" placeholder=\"support\">\n            </div>\n            <div class=\"form-group\">\n              <label>Label</label>\n              <input class=\"form-control\" id=\"mbLabel\" placeholder=\"Support Desk\">\n            </div>\n          `,\n          '<button class=\"btn-pill primary\" onclick=\"submitCreateMb()\">Save</button>'\n        );\n      };\n\n      window.submitCreateMb = async () => {\n        const user = $(\"#mbUser\").value.trim().toLowerCase();\n        const label = $(\"#mbLabel\").value.trim();\n        if (!user) return showToast(\"Enter username\");\n        await api(\"/api/mailboxes\", { method: \"POST\", body: JSON.stringify({ user, label }) });\n        closeModal();\n        renderMailboxesPage();\n        showToast(\"Address created\");\n      };\n\n      async function renderContactsPage() {\n        const pane = $(\"#mailScrollPane\");\n        $(\"#sectionLabel\").textContent = t(\"contacts\");\n        const res = await api(\"/api/contacts\");\n        const list = res.items || [];\n\n        pane.innerHTML = `\n          <div style=\"padding:16px;\">\n            <div style=\"display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;\">\n              <div style=\"font-weight:700; font-size:16px;\">${t(\"contacts\")} (${list.length})</div>\n              <button class=\"btn-pill\" onclick=\"location.href='/api/export'\">${t(\"export_csv\")}</button>\n            </div>\n            <div style=\"display:flex; flex-direction:column; gap:8px;\">\n              ${list.map(c => `\n                <div style=\"background:var(--bg-surface); padding:12px 14px; border-radius:12px; border:1px solid var(--border-subtle); display:flex; align-items:center; gap:12px;\">\n                  <div class=\"circle-avatar\" style=\"background:${getAvatarColor(c.email)}; width:38px; height:38px;\">${esc((c.name||c.email)[0].toUpperCase())}</div>\n                  <div style=\"flex:1; min-width:0;\">\n                    <div style=\"font-weight:700; font-size:14px;\">${esc(c.name || \"Unknown\")}</div>\n                    <div style=\"font-size:12px; color:var(--text-muted); font-family:monospace;\">${esc(c.email)}</div>\n                  </div>\n                  <span class=\"badge badge-social\" style=\"font-size:11px;\">${c.count} ${t(\"msgs\")}</span>\n                </div>\n              `).join(\"\")}\n            </div>\n          </div>\n        `;\n      }\n\n      function renderSettingsPage() {\n        const pane = $(\"#mailScrollPane\");\n        $(\"#sectionLabel\").textContent = t(\"settings\");\n        const currentTheme = localStorage.getItem(\"rad_mail_theme\") || \"dark\";\n        const currentLang = state.settings.lang || \"en\";\n\n        pane.innerHTML = `\n          <div style=\"padding:16px; max-width:600px;\">\n            <div style=\"font-size:18px; font-weight:700; margin-bottom:16px;\">${t(\"general_settings\")}</div>\n            <div style=\"background:var(--bg-surface); border:1px solid var(--border-subtle); border-radius:16px; padding:18px; display:flex; flex-direction:column; gap:16px;\">\n              \n              <!-- Theme Option -->\n              <div>\n                <label style=\"font-size:13px; font-weight:600; color:var(--text-sub);\">${t(\"theme\")}</label>\n                <div style=\"display:flex; gap:10px; margin-top:8px;\">\n                  <button class=\"btn-pill ${currentTheme==='light'?'primary':''}\" style=\"flex:1; justify-content:center;\" onclick=\"applyTheme('light'); renderSettingsPage();\">${t(\"light\")}</button>\n                  <button class=\"btn-pill ${currentTheme==='dark'?'primary':''}\" style=\"flex:1; justify-content:center;\" onclick=\"applyTheme('dark'); renderSettingsPage();\">${t(\"dark\")}</button>\n                </div>\n              </div>\n\n              <!-- Language Option -->\n              <div>\n                <label style=\"font-size:13px; font-weight:600; color:var(--text-sub);\">${t(\"language\")}</label>\n                <div style=\"display:flex; gap:10px; margin-top:8px;\">\n                  <button class=\"btn-pill ${currentLang==='en'?'primary':''}\" style=\"flex:1; justify-content:center;\" onclick=\"applyLang('en'); renderSettingsPage();\">English</button>\n                  <button class=\"btn-pill ${currentLang==='fa'?'primary':''}\" style=\"flex:1; justify-content:center;\" onclick=\"applyLang('fa'); renderSettingsPage();\">فارسی</button>\n                </div>\n              </div>\n\n              <hr style=\"border:none; border-top:1px solid var(--border-subtle);\">\n              \n              <!-- Logout -->\n              <div style=\"display:flex; justify-content:space-between; align-items:center;\">\n                <div>\n                  <div style=\"font-weight:700; font-size:14px;\">${t(\"logout\")}</div>\n                  <div style=\"font-size:12px; color:var(--text-muted);\">${t(\"logout_desc\")}</div>\n                </div>\n                <button class=\"btn-pill\" style=\"color:#c5221f;\" onclick=\"logout()\">${t(\"logout\")}</button>\n              </div>\n            </div>\n          </div>\n        `;\n      }\n\n      window.copyStr = async s => {\n        try { await navigator.clipboard.writeText(s); showToast(t(\"copied\")); } catch {}\n      };\n\n      window.logout = async () => {\n        await api(\"/api/logout\", { method: \"POST\" });\n        location.reload();\n      };\n\n      let searchTimer;\n      $(\"#searchInput\")?.addEventListener(\"input\", e => {\n        clearTimeout(searchTimer);\n        searchTimer = setTimeout(() => {\n          state.searchQuery = e.target.value.trim();\n          fetchMails().then(renderMailList);\n        }, 250);\n      });\n\n      // Floating Action Button triggers Create Mailbox directly\n      $(\"#composeFabBtn\")?.addEventListener(\"click\", () => {\n        openCreateMailboxDialog();\n      });\n\n      $(\"#tabMail\")?.addEventListener(\"click\", () => {\n        $(\"#tabMail\").classList.add(\"active\");\n        $(\"#tabVideo\").classList.remove(\"active\");\n        state.folder = \"inbox\";\n        state.category = \"primary\";\n        fetchMails().then(renderMailList);\n      });\n      $(\"#tabVideo\")?.addEventListener(\"click\", () => {\n        $(\"#tabVideo\").classList.add(\"active\");\n        $(\"#tabMail\").classList.remove(\"active\");\n        renderMailboxesPage();\n      });\n\n      setInterval(async () => {\n        try {\n          const list = await api(\"/api/list?folder=inbox\");\n          if (list?.length) {\n            const max = Math.max(...list.map(x => x.id));\n            if (state.lastMaxId && max > state.lastMaxId) {\n              state.lastMaxId = max;\n              if (state.folder === \"inbox\") {\n                await fetchMails();\n                renderMailList();\n              }\n              await fetchMeta();\n            }\n          }\n        } catch (e) {}\n      }, 12000);\n\n      if (\"serviceWorker\" in navigator) {\n        window.addEventListener(\"load\", () => {\n          navigator.serviceWorker.register(\"/sw.js\").catch(console.error);\n        });\n      }\n\n      const loginOverlay = $(\"#loginOverlay\");\n      const loginForm = $(\"#loginForm\");\n      const loginPassword = $(\"#loginPassword\");\n      const loginError = $(\"#loginError\");\n      const showLogin = () => {\n        loginOverlay?.classList.add(\"open\");\n        setTimeout(() => loginPassword?.focus(), 50);\n      };\n      const hideLogin = () => loginOverlay?.classList.remove(\"open\");\n\n      loginForm?.addEventListener(\"submit\", async e => {\n        e.preventDefault();\n        if (!loginPassword?.value) return;\n        const submit = $(\"#loginSubmit\");\n        if (submit) { submit.disabled = true; submit.textContent = \"در حال بررسی…\"; }\n        if (loginError) loginError.textContent = \"\";\n        try {\n          const res = await fetch(\"/api/login\", {\n            method: \"POST\",\n            credentials: \"same-origin\",\n            headers: { \"content-type\": \"application/json\" },\n            body: JSON.stringify({ password: loginPassword.value })\n          });\n          const data = await res.json().catch(() => ({}));\n          if (!res.ok) throw new Error(data.error || \"Login failed\");\n          loginPassword.value = \"\";\n          await boot();\n        } catch (err) {\n          if (loginError) loginError.textContent = \"رمز عبور صحیح نیست یا ورود انجام نشد.\";\n          loginPassword.select();\n        } finally {\n          if (submit) { submit.disabled = false; submit.textContent = \"ورود به پنل\"; }\n        }\n      });\n\n      async function boot() {\n        try {\n          await fetchMeta();\n          await fetchMails();\n          renderMailList();\n          hideLogin();\n        } catch (e) {\n          showLogin();\n        }\n      }\n      boot();\n    })();\n  </script>\n</body>\n</html>";

export default {
  async scheduled(controller, env, ctx) {
    await init(env);
    await performCleanup(env);
  },

  async email(msg, env) {
    await init(env);
    const raw = b2s(await new Response(msg.raw).arrayBuffer()).slice(0, 5000000);
    const p = parseMime(raw);
    await store(env, {
      from: msg.from,
      to: msg.to,
      subject: p.subject,
      text: p.text,
      html: p.html,
      name: p.name,
      unsubscribe_url: p.unsubscribe_url,
      precedence: p.precedence,
      attachments: p.attachments
    });
  },

  async fetch(req, env) {
    const u = new URL(req.url);

    if (u.pathname === "/" && req.method === "GET") {
      return new Response(UI_HTML, {
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "permissions-policy": "camera=(), microphone=(), geolocation=()", "x-frame-options": "DENY" }
      });
    }

    if (u.pathname === "/manifest.webmanifest") {
      return json(MANIFEST_JSON, 200, {
        "content-type": "application/manifest+json; charset=utf-8",
        "cache-control": "public, max-age=86400"
      });
    }

    if (u.pathname === "/sw.js") {
      return new Response(SW_CODE, {
        headers: { "content-type": "application/javascript; charset=utf-8", "cache-control": "no-store" }
      });
    }

    if (u.pathname === "/icon-192.png" || u.pathname === "/icon-512.png") {
      return new Response(SVG_ICON, {
        headers: { "content-type": "image/svg+xml", "cache-control": "public, max-age=604800" }
      });
    }

    await init(env);
    const tok = await sha((env.PANEL_PASSWORD || "") + "|rad-mail-pro");

    if (u.pathname === "/api/login" && req.method === "POST") {
      const { password } = await req.json().catch(() => ({}));
      if (!env.PANEL_PASSWORD || password !== env.PANEL_PASSWORD) return json({ error: "bad password" }, 403);
      return json({ ok: 1 }, 200, {
        "set-cookie": "s=" + tok + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000"
      });
    }

    if (u.pathname === "/api/logout" && req.method === "POST") {
      return json({ ok: 1 }, 200, {
        "set-cookie": "s=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
      });
    }

    if (!cookieHas(req, tok)) return json({ error: "auth" }, 401);

    if (Math.random() < 0.05) await performCleanup(env);

    const body = (req.method === "POST" || req.method === "PUT" || req.method === "DELETE")
      ? await req.json().catch(() => ({}))
      : {};

    if (u.pathname === "/api/meta") {
      // Real counts from D1 database without hardcoded fake values
      const c = await env.DB.prepare(
        `SELECT 
          SUM(CASE WHEN folder='inbox' AND category='primary' THEN 1 ELSE 0 END) inbox_primary,
          SUM(CASE WHEN folder='inbox' AND category='promotions' AND read=0 THEN 1 ELSE 0 END) inbox_promotions,
          SUM(CASE WHEN folder='inbox' AND category='social' AND read=0 THEN 1 ELSE 0 END) inbox_social,
          SUM(CASE WHEN folder='inbox' AND category='updates' AND read=0 THEN 1 ELSE 0 END) inbox_updates,
          SUM(CASE WHEN folder='spam' THEN 1 ELSE 0 END) spam,
          SUM(CASE WHEN starred=1 AND folder!='trash' THEN 1 ELSE 0 END) starred,
          SUM(CASE WHEN folder='trash' THEN 1 ELSE 0 END) trash,
          SUM(CASE WHEN folder!='trash' THEN 1 ELSE 0 END) all_mail,
          SUM(CASE WHEN (subject LIKE '%order%' OR subject LIKE '%receipt%' OR text LIKE '%receipt%' OR text LIKE '%order%') AND folder!='trash' THEN 1 ELSE 0 END) purchases
        FROM mails`
      ).first();
      const { results: lbls } = await env.DB.prepare("SELECT * FROM custom_labels ORDER BY id ASC").all();
      return json({ counts: c || {}, labels: lbls || [], settings: await getSettings(env) });
    }

    if (u.pathname === "/api/list") {
      const f = u.searchParams.get("folder") || "inbox";
      const cat = u.searchParams.get("category");
      const q = u.searchParams.get("q");
      const w = [];
      const p = [];

      if (f === "starred") {
        w.push("starred=1 AND folder!='trash'");
      } else if (f === "all") {
        w.push("folder!='trash'");
      } else {
        w.push("folder=?");
        p.push(f);
      }

      if (f === "inbox" && cat && ["primary", "social", "promotions", "updates"].includes(cat)) {
        w.push("category=?");
        p.push(cat);
      }

      if (q) {
        w.push("(subject LIKE ? OR from_addr LIKE ? OR to_addr LIKE ? OR from_name LIKE ?)");
        p.push("%" + q + "%", "%" + q + "%", "%" + q + "%", "%" + q + "%");
      }

      const { results } = await env.DB.prepare(
        `SELECT id, domain, to_addr, from_addr, from_name, subject, substr(text, 1, 160) snip, folder, category, starred, pinned, read, spam_score, unsubscribe_url, labels, ts 
         FROM mails WHERE ` + w.join(" AND ") +
        ` ORDER BY pinned DESC, ts DESC LIMIT 200`
      ).bind(...p).all();

      return json(results || []);
    }

    if (u.pathname === "/api/mail") {
      const id = Number(u.searchParams.get("id"));
      if (!Number.isSafeInteger(id) || id < 1) return json({ error: "invalid mail ID" }, 400);
      await env.DB.prepare("UPDATE mails SET read=1 WHERE id=?").bind(id).run();
      const mail = await env.DB.prepare("SELECT * FROM mails WHERE id=?").bind(id).first();
      if (!mail) return json({ error: "mail not found" }, 404);
      const { results: files } = await env.DB.prepare(
        "SELECT id, filename, content_type, size FROM attachments WHERE mail_id=? ORDER BY id"
      ).bind(id).all();
      mail.attachments = files || [];
      return json(mail);
    }

    if (u.pathname === "/api/attachment") {
      const attachmentId = Number(u.searchParams.get("id"));
      if (!Number.isSafeInteger(attachmentId) || attachmentId < 1) return json({ error: "invalid attachment ID" }, 400);
      const file = await env.DB.prepare(
        "SELECT id, filename, content_type, size, storage_key, content FROM attachments WHERE id=?"
      ).bind(attachmentId).first();
      if (!file) return json({ error: "attachment not found" }, 404);
      let data = file.content;
      if (file.storage_key) {
        if (!env.FILES || typeof env.FILES.get !== "function") return json({ error: "attachment storage is not configured" }, 503);
        const object = await env.FILES.get(file.storage_key);
        if (!object) return json({ error: "attachment file missing from storage" }, 404);
        data = await object.arrayBuffer();
      }
      if (!data) return json({ error: "attachment content unavailable" }, 404);
      const safeName = String(file.filename || "attachment").replace(/[\r\n"\\]/g, "_").slice(0, 180) || "attachment";
      return new Response(data, { headers: {
        "content-type": "application/octet-stream",
        "content-length": String(file.size || 0),
        "content-disposition": `attachment; filename*=UTF-8''${encodeURIComponent(safeName)}`,
        "cache-control": "private, no-store",
        "x-content-type-options": "nosniff"
      }});
    }

    if (u.pathname === "/api/act") {
      const id = Number(body.id);
      const action = String(body.action || "");
      const allowedActions = new Set(["star", "pin", "read", "unread", "spam", "inbox", "archive", "trash", "delete"]);
      if (!Number.isSafeInteger(id) || id < 1 || !allowedActions.has(action)) {
        return json({ error: "invalid action" }, 400);
      }
      const run = (sql, ...args) => env.DB.prepare(sql).bind(...args).run();

      if (action === "star") await run("UPDATE mails SET starred=1-starred WHERE id=?", id);
      if (action === "pin") await run("UPDATE mails SET pinned=1-pinned WHERE id=?", id);
      if (action === "read") await run("UPDATE mails SET read=1 WHERE id=?", id);
      if (action === "unread") await run("UPDATE mails SET read=0 WHERE id=?", id);
      if (action === "spam") await run("UPDATE mails SET folder='spam' WHERE id=?", id);
      if (action === "inbox") await run("UPDATE mails SET folder='inbox' WHERE id=?", id);
      if (action === "archive") await run("UPDATE mails SET folder='archive' WHERE id=?", id);
      if (action === "trash") await run("UPDATE mails SET folder='trash' WHERE id=?", id);
      if (action === "delete") await run("DELETE FROM mails WHERE id=?", id);
      return json({ ok: 1 });
    }

    if (u.pathname === "/api/mailboxes" && req.method === "GET") {
      const { results } = await env.DB.prepare("SELECT address, label, enabled, created_ts, updated_ts FROM mailboxes ORDER BY created_ts DESC").all();
      return json({ items: results || [] });
    }

    if (u.pathname === "/api/mailboxes" && req.method === "POST") {
      const user = String(body.user || "").trim().toLowerCase();
      const domain = String(env.MAIN_DOMAIN || "").trim().toLowerCase().replace(/^@/, "");
      if (!/^[a-z0-9][a-z0-9._+-]{0,63}$/i.test(user)) return json({ error: "invalid username" }, 400);
      if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(domain)) {
        return json({ error: "MAIN_DOMAIN is missing or invalid" }, 503);
      }
      const address = user + "@" + domain;
      const now = Date.now();
      await env.DB.prepare(
        "INSERT INTO mailboxes(address, label, enabled, created_ts, updated_ts) VALUES(?,?,?,?,?) " +
        "ON CONFLICT(address) DO UPDATE SET label=excluded.label, enabled=1, updated_ts=excluded.updated_ts"
      ).bind(address, String(body.label || "").slice(0, 80), 1, now, now).run();
      return json({ ok: 1, address });
    }

    if (u.pathname === "/api/contacts") {
      const { results } = await env.DB.prepare("SELECT from_addr email, MAX(from_name) name, COUNT(*) count, MAX(ts) last_ts FROM mails WHERE from_addr!='' GROUP BY from_addr ORDER BY last_ts DESC LIMIT 500").all();
      return json({ items: results || [] });
    }

    if (u.pathname === "/api/settings" && req.method === "POST") {
      await setSettings(env, body);
      return json({ ok: 1 });
    }

    if (u.pathname === "/api/export") {
      const { results } = await env.DB.prepare("SELECT id, domain, to_addr, from_addr, from_name, subject, folder, category, read, starred, pinned, spam_score, ts FROM mails ORDER BY ts DESC").all();
      const csv = "id,domain,to,from,name,subject,folder,category,read,starred,pinned,spam_score,date\n" +
        (results || []).map(r => [
          r.id, r.domain, r.to_addr, r.from_addr, r.from_name, r.subject, r.folder, r.category, r.read, r.starred, r.pinned, r.spam_score, new Date(r.ts).toISOString()
        ].map(escCsv).join(",")).join("\n");
      return new Response("\ufeff" + csv, {
        headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": "attachment; filename=rad-mail-export.csv" }
      });
    }

    return json({ error: "not found" }, 404);
  }
};