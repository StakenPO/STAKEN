// STAKEN — Cloudflare Worker: приём постбэков Pocket Option, привязка ID аккаунта, выдача ключей, админка.
// Статика (index.html, status.html, admin.html) отдаётся через binding ASSETS.
//
// Схема работы:
//   1. Сайт создаёт click_id и открывает регистрацию Pocket Option со ссылкой, где есть этот click_id.
//   2. Pocket Option шлёт постбэки reg / ftd на /pb (с click_id, trader_id, sumdep).
//      Каждый аккаунт (trader_id) хранится в таблице regs и закрепляется за первым click_id, с которым пришёл.
//      Под одним click_id может быть несколько аккаунтов (клиент создал, забыл, создал новый).
//   3. Клиент на странице статуса вводит ID своего аккаунта (/api/bind). ID должен быть среди аккаунтов,
//      зарегистрированных именно с его click_id. Чужой аккаунт взять нельзя.
//   4. Когда ID подтверждён и депозит этого аккаунта >= MIN_DEPOSIT, клиенту выдаётся ключ (один ключ на click_id).
//      Ключ берётся из пула, а если пул пуст, сервер сам генерирует новый.
//   5. Расширение проверяет ключ на сервере (/api/license/activate и /api/license/check): ключ привязывается
//      к устройствам (не больше MAX_DEVICES), сервер возвращает подписанный токен (ECDSA P-256), который
//      расширение проверяет встроенным публичным ключом. Ключ можно заблокировать или сбросить устройства в админке.

const HEX32 = /^[a-f0-9]{32}$/;
const UID_RE = /^\d{4,15}$/;
const EVENTS_REG = ["reg", "registration"];
const EVENTS_FTD = ["ftd", "deposit"];
let schemaReady = null;

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

function safeEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

const minDeposit = (env) => Number(env.MIN_DEPOSIT) || 100;
const now = () => Math.floor(Date.now() / 1000);
const getRow = (env, id) => env.DB.prepare("SELECT * FROM clicks WHERE click_id=?1").bind(id).first();

// ---------- Лицензии: общие функции ----------
const DAY_MS = 86400000;
const KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 32 символа без похожих (0/O, 1/I)
const DEV_RE = /^[a-f0-9]{32}$/;
const KEY_RE = /^PP[A-Z0-9]{16}$/;
const maxDevices = (env) => Math.max(1, parseInt(env.MAX_DEVICES, 10) || 2);
const autoDays = (env) => { const n = parseInt(env.AUTO_KEY_DAYS, 10); return Number.isFinite(n) && n >= 0 ? n : 0; }; // 0 = навсегда
const ttlMs = (env) => (parseInt(env.LICENSE_TTL_HOURS, 10) || 72) * 3600000;
const parseDays = (v) => { const n = parseInt(v, 10); return Number.isFinite(n) && n >= 0 && n <= 3650 ? n : null; };
const normKey = (k) => String(k || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
const fmtKey = (n) => `${n.slice(0, 2)}-${n.slice(2, 6)}-${n.slice(6, 10)}-${n.slice(10, 14)}-${n.slice(14, 18)}`;
const canonKey = (k) => { const n = normKey(k); return KEY_RE.test(n) ? fmtKey(n) : k; };

function genKey() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  let s = "PP";
  for (const x of b) s += KEY_ALPHABET[x % 32];
  return fmtKey(s);
}

// Создаёт новый ключ прямо на сервере и сразу закрепляет его за получателем
async function createKey(env, claimedBy, note, days) {
  for (let i = 0; i < 5; i++) {
    const key = genKey();
    const r = await env.DB.prepare(
      "INSERT OR IGNORE INTO keys(key,added_at,claimed_by,claimed_at,note,days) VALUES(?1,?2,?3,?4,?5,?6) RETURNING key"
    ).bind(key, now(), claimedBy, now(), note, days).all();
    if (r.results && r.results[0]) return key;
  }
  throw new Error("key_generation_failed");
}

const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

let signKeyCache = null;
async function getSignKey(env) {
  if (!env.LICENSE_PRIVATE_JWK) return null;
  if (!signKeyCache || signKeyCache.raw !== env.LICENSE_PRIVATE_JWK) {
    const key = await crypto.subtle.importKey(
      "jwk", JSON.parse(env.LICENSE_PRIVATE_JWK), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
    );
    signKeyCache = { raw: env.LICENSE_PRIVATE_JWK, key };
  }
  return signKeyCache.key;
}

async function signToken(env, payload) {
  const k = await getSignKey(env);
  if (!k) return null;
  const body = b64u(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k, new TextEncoder().encode(body));
  return body + "." + b64u(sig);
}

// ---------- Схема БД (создаётся и обновляется автоматически) ----------
// clicks: одна строка на click_id (ключ, введённый клиентом ID, число попыток).
// regs:   одна строка на аккаунт Pocket Option (trader_id), с click_id, с которым он пришёл (может быть NULL).
function ensureSchema(env) {
  if (!schemaReady) {
    schemaReady = (async () => {
      const hadRegs = await env.DB.prepare("SELECT 1 AS x FROM sqlite_master WHERE type='table' AND name='regs'").first();
      await env.DB.batch([
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS clicks(
          click_id TEXT PRIMARY KEY, created_at INTEGER, reg_at INTEGER, ftd_at INTEGER,
          trader_id TEXT, dep REAL DEFAULT 0, key TEXT, uid TEXT, bind_n INTEGER DEFAULT 0)`),
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS keys(
          key TEXT PRIMARY KEY, added_at INTEGER, claimed_by TEXT, claimed_at INTEGER, note TEXT)`),
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS events(
          ts INTEGER, event TEXT, click_id TEXT, trader_id TEXT, dep REAL, result TEXT)`),
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS regs(
          trader_id TEXT PRIMARY KEY, click_id TEXT, reg_at INTEGER, ftd_at INTEGER, dep REAL DEFAULT 0)`),
        env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_regs_click ON regs(click_id)`),
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS activations(
          key TEXT, device TEXT, first_at INTEGER, last_at INTEGER, PRIMARY KEY(key, device))`),
      ]);
      // Если таблица clicks создана старой версией Worker, добавляем новые столбцы
      const info = await env.DB.prepare("PRAGMA table_info(clicks)").all();
      const have = new Set((info.results || []).map((r) => r.name));
      if (!have.has("uid")) await env.DB.prepare("ALTER TABLE clicks ADD COLUMN uid TEXT").run();
      if (!have.has("bind_n")) await env.DB.prepare("ALTER TABLE clicks ADD COLUMN bind_n INTEGER DEFAULT 0").run();
      // Лицензии: столбцы в keys и таблица устройств
      const kinfo = await env.DB.prepare("PRAGMA table_info(keys)").all();
      const khave = new Set((kinfo.results || []).map((r) => r.name));
      if (!khave.has("days")) await env.DB.prepare("ALTER TABLE keys ADD COLUMN days INTEGER").run();
      if (!khave.has("until")) await env.DB.prepare("ALTER TABLE keys ADD COLUMN until INTEGER").run();
      if (!khave.has("activated_at")) await env.DB.prepare("ALTER TABLE keys ADD COLUMN activated_at INTEGER").run();
      if (!khave.has("revoked")) await env.DB.prepare("ALTER TABLE keys ADD COLUMN revoked INTEGER DEFAULT 0").run();
      // Один раз переносим аккаунты из старой схемы (trader_id/dep лежали прямо в clicks)
      if (!hadRegs) {
        await env.DB.batch([
          env.DB.prepare(
            `INSERT OR IGNORE INTO regs(trader_id,click_id,reg_at,ftd_at,dep)
             SELECT trader_id, CASE WHEN click_id LIKE 't:%' THEN NULL ELSE click_id END, reg_at, ftd_at, COALESCE(dep,0)
             FROM clicks WHERE trader_id IS NOT NULL AND trader_id!=''`
          ),
          env.DB.prepare("DELETE FROM clicks WHERE click_id LIKE 't:%'"),
        ]);
      }
    })().catch((e) => { schemaReady = null; throw e; });
  }
  return schemaReady;
}

// ---------- Ключи ----------
// Атомарно забираем свободный ключ из пула
async function claimKey(env, claimedBy, note) {
  const r = await env.DB.prepare(
    `UPDATE keys SET claimed_by=?1, claimed_at=?2, note=?3
     WHERE key=(SELECT key FROM keys WHERE claimed_by IS NULL ORDER BY added_at, key LIMIT 1)
     RETURNING key`
  ).bind(claimedBy, now(), note).all();
  return r.results && r.results[0] ? r.results[0].key : null;
}

const releaseKey = (env, key) =>
  env.DB.prepare("UPDATE keys SET claimed_by=NULL, claimed_at=NULL, note=NULL WHERE key=?1").bind(key).run();

// ---------- Главная логика: состояние и выдача ключа ----------
// Состояния: none, need_uid, uid_wait, mismatch, uid_ok, low, taken, dup, empty, key
//   uid_wait: по этому click_id ещё не было ни одной регистрации, ждём постбэк
//   mismatch: регистрации по click_id есть, но введённого ID среди них нет (опечатка или постбэк ещё не пришёл)
//   taken:    аккаунт уже закреплён за другим click_id
async function tryIssue(env, clickId) {
  const min = minDeposit(env);
  const me = await getRow(env, clickId);
  if (!me) return { key: null, state: "none", uid: null, dep: 0, reg: false, ftd: false };

  const cnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM regs WHERE click_id=?1").bind(clickId).first();
  const base = { uid: me.uid || null, dep: 0, reg: !!(cnt && cnt.n > 0), ftd: false };

  let acct = me.uid ? await env.DB.prepare("SELECT * FROM regs WHERE trader_id=?1").bind(me.uid).first() : null;
  if (acct && !acct.click_id) {
    // Постбэк пришёл без click_id: закрепляем аккаунт за тем, кто ввёл этот ID первым
    await env.DB.prepare("UPDATE regs SET click_id=?1 WHERE trader_id=?2 AND click_id IS NULL").bind(clickId, me.uid).run();
    acct = await env.DB.prepare("SELECT * FROM regs WHERE trader_id=?1").bind(me.uid).first();
  }
  const mine = acct && acct.click_id === clickId ? acct : null;
  if (mine) { base.reg = true; base.dep = mine.dep || 0; base.ftd = !!mine.ftd_at; }

  if (me.key) return { ...base, key: me.key, state: "key" };
  if (!me.uid) return { ...base, key: null, state: "need_uid" };
  if (!acct) return { ...base, key: null, state: base.reg ? "mismatch" : "uid_wait" };
  if (!mine) return { ...base, key: null, state: "taken" };

  if (base.dep < min) return { ...base, key: null, state: base.ftd ? "low" : "uid_ok" };

  const dup = await env.DB.prepare(
    "SELECT 1 AS x FROM clicks WHERE uid=?1 AND key IS NOT NULL AND click_id!=?2 LIMIT 1"
  ).bind(me.uid, clickId).first();
  if (dup) return { ...base, key: null, state: "dup" };

  const prev = await env.DB.prepare("SELECT key FROM keys WHERE claimed_by=?1 LIMIT 1").bind(clickId).first();
  let key = prev ? prev.key : null;
  const fresh = !key;
  if (fresh) key = (await claimKey(env, clickId, "auto")) || (await createKey(env, clickId, "auto", autoDays(env)));
  if (!key) return { ...base, key: null, state: "empty" };

  const upd = await env.DB.prepare("UPDATE clicks SET key=?1 WHERE click_id=?2 AND key IS NULL RETURNING key")
    .bind(key, clickId).all();
  if (!upd.results || !upd.results[0]) {
    // Параллельный запрос уже выдал ключ этому клику: возвращаем лишний в пул
    if (fresh) await releaseKey(env, key);
    const again = await getRow(env, clickId);
    return { ...base, key: again && again.key, state: again && again.key ? "key" : "empty" };
  }
  return { ...base, key, state: "key" };
}

// ---------- Постбэк от Pocket Option ----------
async function handlePostback(url, env) {
  if (!env.PB_TOKEN) return new Response("server not configured", { status: 500 });
  const q = url.searchParams;
  if (!safeEq(q.get("token") || "", env.PB_TOKEN)) return new Response("forbidden", { status: 403 });

  const ev = (q.get("event") || "").toLowerCase();
  const clickId = (q.get("click_id") || q.get("clickid") || q.get("subid") || q.get("sub_id1") || "").toLowerCase().trim();
  const trader = (q.get("trader_id") || q.get("uid") || "").replace(/[\s#]/g, "").slice(0, 64);
  const dep = parseFloat(q.get("sumdep") || q.get("amount") || "0") || 0;
  const t = now();

  let result;
  const isReg = EVENTS_REG.includes(ev);
  const isFtd = EVENTS_FTD.includes(ev);
  const target = HEX32.test(clickId) ? clickId : null;

  if (!isReg && !isFtd) result = "unknown_event";
  else if (!trader) result = "no_trader";
  else {
    const row = await env.DB.prepare("SELECT * FROM regs WHERE trader_id=?1").bind(trader).first();
    if (row && row.click_id && target && row.click_id !== target) {
      result = "trader_mismatch"; // аккаунт уже закреплён за другим click_id: игнорируем
    } else {
      const cid = (row && row.click_id) || target; // может быть null, если Pocket Option не прислал click_id
      if (cid) await env.DB.prepare("INSERT OR IGNORE INTO clicks(click_id,created_at) VALUES(?1,?2)").bind(cid, t).run();
      if (isReg) {
        await env.DB.prepare(
          `INSERT INTO regs(trader_id,click_id,reg_at) VALUES(?1,?2,?3)
           ON CONFLICT(trader_id) DO UPDATE SET click_id=COALESCE(click_id,?2), reg_at=COALESCE(reg_at,?3)`
        ).bind(trader, cid, t).run();
        result = "reg_saved" + (cid ? "" : ":no_click_id");
      } else {
        await env.DB.prepare(
          `INSERT INTO regs(trader_id,click_id,reg_at,ftd_at,dep) VALUES(?1,?2,?3,?3,?4)
           ON CONFLICT(trader_id) DO UPDATE SET click_id=COALESCE(click_id,?2), reg_at=COALESCE(reg_at,?3),
           ftd_at=COALESCE(ftd_at,?3), dep=MAX(COALESCE(dep,0),?4)`
        ).bind(trader, cid, t, dep).run();
        result = cid ? "ftd_saved:" + (await tryIssue(env, cid)).state : "ftd_saved:no_click_id";
      }
    }
  }

  await env.DB.prepare("INSERT INTO events(ts,event,click_id,trader_id,dep,result) VALUES(?1,?2,?3,?4,?5,?6)")
    .bind(t, ev, clickId.slice(0, 40), trader, dep, result).run();
  if (Math.random() < 0.05) await env.DB.prepare("DELETE FROM events WHERE ts<?1").bind(t - 30 * 86400).run();
  return new Response("ok");
}

// ---------- Статус для сайта ----------
const publicView = (r, min) => ({ state: r.state, uid: r.uid, reg: r.reg, ftd: r.ftd, dep: r.dep, min, key: r.key });

async function handleStatus(url, env) {
  const c = (url.searchParams.get("c") || "").toLowerCase();
  if (!HEX32.test(c)) return json({ error: "bad_id" }, 400);
  return json(publicView(await tryIssue(env, c), minDeposit(env)));
}

// ---------- Клиент вводит ID своего аккаунта ----------
// Вводить можно любой аккаунт, зарегистрированный с этим click_id, и менять ID до выдачи ключа.
// Нельзя взять аккаунт, закреплённый за другим click_id.
async function handleBind(req, env) {
  if (req.method !== "POST") return json({ ok: false, error: "method" }, 405);
  const body = await req.json().catch(() => ({}));
  const c = String(body.c || "").toLowerCase().trim();
  const uid = String(body.uid || "").replace(/\D/g, "");
  if (!HEX32.test(c)) return json({ ok: false, error: "bad_id" }, 400);
  if (!UID_RE.test(uid)) return json({ ok: false, error: "bad_uid" }, 400);

  await env.DB.prepare("INSERT OR IGNORE INTO clicks(click_id,created_at,bind_n) VALUES(?1,?2,0)").bind(c, now()).run();
  const me = await getRow(env, c);
  if (me.key) return json({ ok: true, ...publicView(await tryIssue(env, c), minDeposit(env)) });
  if ((me.bind_n || 0) >= 15) return json({ ok: false, error: "too_many" }, 429);
  const acct = await env.DB.prepare("SELECT click_id FROM regs WHERE trader_id=?1").bind(uid).first();
  if (acct && acct.click_id && acct.click_id !== c) return json({ ok: false, error: "uid_taken" }, 409);
  await env.DB.prepare("UPDATE clicks SET uid=?1, bind_n=COALESCE(bind_n,0)+1 WHERE click_id=?2").bind(uid, c).run();
  return json({ ok: true, ...publicView(await tryIssue(env, c), minDeposit(env)) });
}

// ---------- Проверка ключа расширением ----------
const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "POST, OPTIONS",
  "access-control-allow-headers": "content-type",
};
const jsonL = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

// create=true: активация (может занять новое устройство). create=false: проверка уже активированного устройства.
async function licenseAuth(env, rawKey, device, create) {
  const norm = normKey(rawKey);
  if (!KEY_RE.test(norm)) return { status: 400, body: { ok: false, error: "bad_key" } };
  if (!DEV_RE.test(device)) return { status: 400, body: { ok: false, error: "bad_device" } };
  if (!env.LICENSE_PRIVATE_JWK) return { status: 500, body: { ok: false, error: "not_configured" } };

  let row = await env.DB.prepare("SELECT * FROM keys WHERE REPLACE(REPLACE(UPPER(key),'-',''),' ','')=?1 LIMIT 1")
    .bind(norm).first();
  if (!row) return { status: 404, body: { ok: false, error: "invalid_key" } };
  if (row.revoked) return { status: 403, body: { ok: false, error: "revoked" } };

  const t = Date.now();
  const days = row.days == null ? autoDays(env) : row.days;
  const act = await env.DB.prepare("SELECT 1 AS x FROM activations WHERE key=?1 AND device=?2").bind(row.key, device).first();
  if (!act) {
    if (!create) return { status: 403, body: { ok: false, error: "unknown_device" } };
    const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM activations WHERE key=?1").bind(row.key).first();
    if (c && c.n >= maxDevices(env)) return { status: 403, body: { ok: false, error: "device_limit", max: maxDevices(env) } };
  }

  // Срок отсчитывается с первой активации. Если на устройстве уже есть другой действующий ключ, время складывается
  if (row.activated_at == null) {
    let until = 0;
    if (days > 0) {
      const cur = await env.DB.prepare(
        `SELECT MAX(k.until) AS u FROM activations a JOIN keys k ON k.key=a.key
         WHERE a.device=?1 AND k.key!=?2 AND k.revoked=0 AND k.until>?3`
      ).bind(device, row.key, t).first();
      until = Math.max(t, (cur && cur.u) || 0) + days * DAY_MS;
    }
    await env.DB.prepare("UPDATE keys SET activated_at=?1, until=?2 WHERE key=?3 AND activated_at IS NULL").bind(t, until, row.key).run();
    row = await env.DB.prepare("SELECT * FROM keys WHERE key=?1").bind(row.key).first();
  }
  const life = !row.until;
  if (!life && row.until <= t) return { status: 403, body: { ok: false, error: "expired" } };

  await env.DB.prepare(
    `INSERT INTO activations(key,device,first_at,last_at) VALUES(?1,?2,?3,?3)
     ON CONFLICT(key,device) DO UPDATE SET last_at=?3`
  ).bind(row.key, device, t).run();

  const payload = { v: 1, d: device, life, until: life ? 0 : row.until, iat: t, exp: t + ttlMs(env) };
  const token = await signToken(env, payload);
  return { status: 200, body: { ok: true, token, life, until: payload.until, days } };
}

async function handleLicense(req, url, env) {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (req.method !== "POST") return jsonL({ ok: false, error: "method" }, 405);
  const create = url.pathname === "/api/license/activate";
  if (!create && url.pathname !== "/api/license/check") return jsonL({ ok: false, error: "not_found" }, 404);
  const body = await req.json().catch(() => ({}));
  const r = await licenseAuth(env, body.key, String(body.device || "").toLowerCase(), create);
  return jsonL(r.body, r.status);
}

// ---------- Админка ----------
async function handleAdmin(req, url, env) {
  if (!env.ADMIN_TOKEN) return json({ error: "ADMIN_TOKEN not set" }, 500);
  const auth = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  if (!safeEq(auth, env.ADMIN_TOKEN)) return json({ error: "unauthorized" }, 401);
  const path = url.pathname.replace("/api/admin/", "");

  if (path === "overview" && req.method === "GET") {
    const stats = await env.DB.prepare(
      `SELECT (SELECT COUNT(*) FROM keys WHERE claimed_by IS NULL) AS free,
              (SELECT COUNT(*) FROM keys WHERE claimed_by IS NOT NULL) AS used,
              (SELECT COUNT(*) FROM regs) AS regs,
              (SELECT COUNT(*) FROM regs WHERE ftd_at IS NOT NULL) AS ftds,
              (SELECT COUNT(*) FROM clicks WHERE key IS NOT NULL) AS issued,
              (SELECT COUNT(*) FROM activations) AS activations`
    ).first();
    const clicks = await env.DB.prepare(
      `SELECT c.click_id AS click_id,
              (SELECT MIN(reg_at) FROM regs r WHERE r.click_id=c.click_id) AS reg_at,
              (SELECT MIN(ftd_at) FROM regs r WHERE r.click_id=c.click_id) AS ftd_at,
              (SELECT group_concat(trader_id, ', ') FROM regs r WHERE r.click_id=c.click_id) AS trader_id,
              c.uid AS uid,
              (SELECT MAX(dep) FROM regs r WHERE r.click_id=c.click_id) AS dep,
              c.key AS key
       FROM clicks c
       ORDER BY COALESCE((SELECT MAX(COALESCE(ftd_at,reg_at)) FROM regs r WHERE r.click_id=c.click_id), c.created_at) DESC
       LIMIT 100`
    ).all();
    const keys = await env.DB.prepare(
      `SELECT k.key AS key, k.claimed_by AS claimed_by, k.claimed_at AS claimed_at, k.note AS note,
              k.days AS days, k.until AS until, k.revoked AS revoked, k.activated_at AS activated_at,
              (SELECT COUNT(*) FROM activations a WHERE a.key=k.key) AS devs
       FROM keys k WHERE k.claimed_by IS NOT NULL ORDER BY k.claimed_at DESC LIMIT 200`
    ).all();
    const events = await env.DB.prepare("SELECT * FROM events ORDER BY ts DESC LIMIT 40").all();
    return json({
      min: minDeposit(env), maxDevices: maxDevices(env), autoDays: autoDays(env), signing: !!env.LICENSE_PRIVATE_JWK,
      stats, clicks: clicks.results, keys: keys.results, events: events.results,
    });
  }

  if (req.method !== "POST") return json({ error: "method" }, 405);
  const body = await req.json().catch(() => ({}));

  if (path === "keys/add") {
    // Добавить готовые ключи в пул. days: на сколько дней ключ (0 = навсегда); не указано = как у автоключей
    const days = parseDays(body.days);
    const list = [...new Set((body.keys || []).map((k) => String(k).trim()).filter((k) => k.length >= 3 && k.length <= 500).map(canonKey))].slice(0, 2000);
    const stmts = [];
    for (let i = 0; i < list.length; i += 30) {
      const chunk = list.slice(i, i + 30);
      const ph = chunk.map((_, j) => `(?${j * 3 + 1},?${j * 3 + 2},?${j * 3 + 3})`).join(",");
      const args = chunk.flatMap((k) => [k, now(), days]);
      stmts.push(env.DB.prepare(
        `INSERT INTO keys(key,added_at,days) VALUES ${ph}
         ON CONFLICT(key) DO UPDATE SET days=excluded.days WHERE keys.claimed_by IS NULL AND keys.activated_at IS NULL`
      ).bind(...args));
    }
    if (stmts.length) await env.DB.batch(stmts);
    return json({ ok: true, submitted: list.length });
  }

  if (path === "keys/generate" || path === "keys/take") {
    // Создать новые ключи на сервере (для себя, тестеров, покупателей)
    const count = path === "keys/take" ? 1 : Math.min(Math.max(parseInt(body.count, 10) || 1, 1), 200);
    const days = parseDays(body.days);
    const note = String(body.note || "manual").slice(0, 200);
    const keys = [];
    for (let i = 0; i < count; i++) keys.push(await createKey(env, "manual", note, days == null ? autoDays(env) : days));
    return json({ ok: true, key: keys[0], keys });
  }

  if (path === "keys/grant") {
    const id = String(body.click_id || "").toLowerCase().trim();
    if (!HEX32.test(id)) return json({ ok: false, error: "bad_click_id" }, 400);
    await env.DB.prepare("INSERT OR IGNORE INTO clicks(click_id,created_at) VALUES(?1,?2)").bind(id, now()).run();
    const c = await getRow(env, id);
    if (c && c.key) return json({ ok: true, key: c.key, already: true });
    const key = (await claimKey(env, id, "manual-grant")) || (await createKey(env, id, "manual-grant", autoDays(env)));
    await env.DB.prepare("UPDATE clicks SET key=?1 WHERE click_id=?2").bind(key, id).run();
    return json({ ok: true, key });
  }

  if (path === "keys/revoke") {
    // Заблокировать или разблокировать ключ. Расширение узнает об этом при ближайшей проверке (до 6 часов онлайн)
    const key = String(body.key || "");
    const r = await env.DB.prepare("UPDATE keys SET revoked=?1 WHERE key=?2 RETURNING key").bind(body.revoked ? 1 : 0, key).all();
    return json({ ok: !!(r.results && r.results[0]) });
  }

  if (path === "keys/reset") {
    // Освободить все устройства ключа (клиент сменил компьютер)
    const key = String(body.key || "");
    await env.DB.prepare("DELETE FROM activations WHERE key=?1").bind(key).run();
    return json({ ok: true });
  }

  return json({ error: "not_found" }, 404);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const p = url.pathname;
    try {
      if (p === "/pb" || p === "/api/status" || p === "/api/bind" || p.startsWith("/api/admin/") || p.startsWith("/api/license/")) {
        await ensureSchema(env);
        if (p.startsWith("/api/license/")) return await handleLicense(req, url, env);
        if (p === "/pb") return await handlePostback(url, env);
        if (p === "/api/status") return await handleStatus(url, env);
        if (p === "/api/bind") return await handleBind(req, env);
        return await handleAdmin(req, url, env);
      }
    } catch (e) {
      return json({ error: "server_error", detail: String((e && e.message) || e) }, 500);
    }
    return env.ASSETS.fetch(req);
  },
};
