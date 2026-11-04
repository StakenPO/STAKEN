// STAKEN — Cloudflare Worker: приём постбэков Pocket Option, привязка ID аккаунта, выдача ключей, админка.
// Статика (index.html, status.html, admin.html) отдаётся через binding ASSETS.
//
// Схема работы:
//   1. Сайт создаёт click_id и открывает регистрацию Pocket Option со ссылкой, где есть этот click_id.
//   2. Pocket Option шлёт постбэки reg / ftd на /pb (с click_id, trader_id, sumdep).
//   3. Клиент на странице статуса вводит ID своего аккаунта (/api/bind). ID сверяется с trader_id из постбэка.
//   4. Когда ID подтверждён и депозит >= MIN_DEPOSIT, из пула выдаётся ключ.

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

// ---------- Схема БД (создаётся и обновляется автоматически) ----------
function ensureSchema(env) {
  if (!schemaReady) {
    schemaReady = (async () => {
      await env.DB.batch([
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS clicks(
          click_id TEXT PRIMARY KEY, created_at INTEGER, reg_at INTEGER, ftd_at INTEGER,
          trader_id TEXT, dep REAL DEFAULT 0, key TEXT, uid TEXT, bind_n INTEGER DEFAULT 0)`),
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS keys(
          key TEXT PRIMARY KEY, added_at INTEGER, claimed_by TEXT, claimed_at INTEGER, note TEXT)`),
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS events(
          ts INTEGER, event TEXT, click_id TEXT, trader_id TEXT, dep REAL, result TEXT)`),
        env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_clicks_trader ON clicks(trader_id)`),
      ]);
      // Если таблица clicks создана старой версией Worker, добавляем новые столбцы
      const info = await env.DB.prepare("PRAGMA table_info(clicks)").all();
      const have = new Set((info.results || []).map((r) => r.name));
      if (!have.has("uid")) await env.DB.prepare("ALTER TABLE clicks ADD COLUMN uid TEXT").run();
      if (!have.has("bind_n")) await env.DB.prepare("ALTER TABLE clicks ADD COLUMN bind_n INTEGER DEFAULT 0").run();
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

// ---------- Постбэки без click_id ----------
// Если Pocket Option прислал постбэк без click_id, храним его под псевдо-ключом "t:<trader_id>".
// Когда клиент вводит ID (или приходит постбэк с click_id), данные переносятся в его строку.
async function absorbPseudo(env, targetId, trader) {
  if (!trader || targetId.startsWith("t:")) return;
  const p = await getRow(env, "t:" + trader);
  if (!p) return;
  const t = await getRow(env, targetId);
  if (!t || (t.trader_id && t.trader_id !== trader)) return;
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE clicks SET trader_id=?2, reg_at=COALESCE(reg_at,?3), ftd_at=COALESCE(ftd_at,?4),
       dep=MAX(COALESCE(dep,0),?5) WHERE click_id=?1`
    ).bind(targetId, trader, p.reg_at ?? null, p.ftd_at ?? null, p.dep || 0),
    env.DB.prepare("DELETE FROM clicks WHERE click_id=?1").bind(p.click_id),
  ]);
}

// ---------- Главная логика: состояние и выдача ключа ----------
// Состояния: none, need_uid, uid_wait, uid_ok, low, mismatch, taken, dup, empty, key
async function tryIssue(env, clickId) {
  const min = minDeposit(env);
  let me = await getRow(env, clickId);
  if (!me) return { key: null, state: "none", uid: null, dep: 0, reg: false, ftd: false };
  if (me.uid && !me.trader_id) {
    await absorbPseudo(env, clickId, me.uid);
    me = await getRow(env, clickId);
  }
  const base = { uid: me.uid || null, dep: me.dep || 0, reg: !!me.reg_at, ftd: !!me.ftd_at };

  if (me.key) return { ...base, key: me.key, state: "key" };
  if (!me.uid) return { ...base, key: null, state: "need_uid" };
  if (me.trader_id && me.trader_id !== me.uid) return { ...base, key: null, state: "mismatch" };

  if (!me.trader_id) {
    // Постбэк с этим ID ещё не пришёл. Если ID уже закреплён за другой сессией, отказываем.
    const other = await env.DB.prepare("SELECT 1 AS x FROM clicks WHERE trader_id=?1 AND click_id!=?2 LIMIT 1")
      .bind(me.uid, clickId).first();
    return { ...base, key: null, state: other ? "taken" : "uid_wait" };
  }

  if ((me.dep || 0) < min) return { ...base, key: null, state: me.ftd_at ? "low" : "uid_ok" };

  const dup = await env.DB.prepare(
    "SELECT 1 AS x FROM clicks WHERE trader_id=?1 AND key IS NOT NULL AND click_id!=?2 LIMIT 1"
  ).bind(me.trader_id, clickId).first();
  if (dup) return { ...base, key: null, state: "dup" };

  const prev = await env.DB.prepare("SELECT key FROM keys WHERE claimed_by=?1 LIMIT 1").bind(clickId).first();
  let key = prev ? prev.key : null;
  const fresh = !key;
  if (fresh) key = await claimKey(env, clickId, "auto");
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
  let target = null;
  if (HEX32.test(clickId)) target = clickId;
  else if (trader) {
    // click_id не пришёл: ищем строку по trader_id или заводим временную
    const ex = await env.DB.prepare(
      "SELECT click_id FROM clicks WHERE trader_id=?1 ORDER BY (key IS NOT NULL) DESC, COALESCE(ftd_at,reg_at,created_at) DESC LIMIT 1"
    ).bind(trader).first();
    target = ex ? ex.click_id : "t:" + trader;
  }

  if (!isReg && !isFtd) result = "unknown_event";
  else if (!target) result = "no_click_id_no_trader";
  else {
    const row = await getRow(env, target);
    if (row && row.trader_id && trader && row.trader_id !== trader) {
      result = "trader_mismatch"; // тот же click_id, но другой аккаунт: игнорируем
    } else if (isReg) {
      await env.DB.prepare(
        `INSERT INTO clicks(click_id,created_at,reg_at,trader_id) VALUES(?1,?2,?2,NULLIF(?3,''))
         ON CONFLICT(click_id) DO UPDATE SET reg_at=COALESCE(reg_at,?2),
         trader_id=COALESCE(NULLIF(trader_id,''),NULLIF(?3,''))`
      ).bind(target, t, trader).run();
      await absorbPseudo(env, target, trader);
      result = "reg_saved" + (target.startsWith("t:") ? ":no_click_id" : "");
    } else {
      await env.DB.prepare(
        `INSERT INTO clicks(click_id,created_at,reg_at,ftd_at,trader_id,dep) VALUES(?1,?2,?2,?2,NULLIF(?3,''),?4)
         ON CONFLICT(click_id) DO UPDATE SET reg_at=COALESCE(reg_at,?2), ftd_at=COALESCE(ftd_at,?2),
         dep=MAX(COALESCE(dep,0),?4), trader_id=COALESCE(NULLIF(trader_id,''),NULLIF(?3,''))`
      ).bind(target, t, trader, dep).run();
      await absorbPseudo(env, target, trader);
      if (target.startsWith("t:")) result = "ftd_saved:no_click_id";
      else result = "ftd_saved:" + (await tryIssue(env, target)).state;
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
  if (me.trader_id && me.trader_id !== uid) return json({ ok: false, error: "uid_mismatch" }, 409);
  if (!me.trader_id) {
    const other = await env.DB.prepare(
      "SELECT 1 AS x FROM clicks WHERE trader_id=?1 AND click_id!=?2 AND click_id NOT LIKE 't:%' LIMIT 1"
    ).bind(uid, c).first();
    if (other) return json({ ok: false, error: "uid_taken" }, 409);
  }
  await env.DB.prepare("UPDATE clicks SET uid=?1, bind_n=COALESCE(bind_n,0)+1 WHERE click_id=?2").bind(uid, c).run();
  return json({ ok: true, ...publicView(await tryIssue(env, c), minDeposit(env)) });
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
              (SELECT COUNT(*) FROM clicks WHERE reg_at IS NOT NULL) AS regs,
              (SELECT COUNT(*) FROM clicks WHERE ftd_at IS NOT NULL) AS ftds,
              (SELECT COUNT(*) FROM clicks WHERE key IS NOT NULL) AS issued`
    ).first();
    const clicks = await env.DB.prepare(
      "SELECT click_id,reg_at,ftd_at,trader_id,uid,dep,key FROM clicks ORDER BY COALESCE(ftd_at,reg_at,created_at) DESC LIMIT 100"
    ).all();
    const keys = await env.DB.prepare(
      "SELECT key,claimed_by,claimed_at,note FROM keys WHERE claimed_by IS NOT NULL ORDER BY claimed_at DESC LIMIT 200"
    ).all();
    const events = await env.DB.prepare("SELECT * FROM events ORDER BY ts DESC LIMIT 40").all();
    return json({ min: minDeposit(env), stats, clicks: clicks.results, keys: keys.results, events: events.results });
  }

  if (req.method !== "POST") return json({ error: "method" }, 405);
  const body = await req.json().catch(() => ({}));

  if (path === "keys/add") {
    const list = [...new Set((body.keys || []).map((k) => String(k).trim()).filter((k) => k.length >= 3 && k.length <= 500))].slice(0, 2000);
    const stmts = [];
    for (let i = 0; i < list.length; i += 45) {
      const chunk = list.slice(i, i + 45);
      const ph = chunk.map((_, j) => `(?${j * 2 + 1},?${j * 2 + 2})`).join(",");
      const args = chunk.flatMap((k) => [k, now()]);
      stmts.push(env.DB.prepare(`INSERT OR IGNORE INTO keys(key,added_at) VALUES ${ph}`).bind(...args));
    }
    if (stmts.length) await env.DB.batch(stmts);
    return json({ ok: true, submitted: list.length });
  }

  if (path === "keys/take") {
    const key = await claimKey(env, "manual", String(body.note || "manual").slice(0, 200));
    return key ? json({ ok: true, key }) : json({ ok: false, error: "pool_empty" }, 409);
  }

  if (path === "keys/grant") {
    const id = String(body.click_id || "").toLowerCase().trim();
    if (!HEX32.test(id)) return json({ ok: false, error: "bad_click_id" }, 400);
    await env.DB.prepare("INSERT OR IGNORE INTO clicks(click_id,created_at) VALUES(?1,?2)").bind(id, now()).run();
    const c = await getRow(env, id);
    if (c && c.key) return json({ ok: true, key: c.key, already: true });
    const key = await claimKey(env, id, "manual-grant");
    if (!key) return json({ ok: false, error: "pool_empty" }, 409);
    await env.DB.prepare("UPDATE clicks SET key=?1 WHERE click_id=?2").bind(key, id).run();
    return json({ ok: true, key });
  }
  return json({ error: "not_found" }, 404);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const p = url.pathname;
    try {
      if (p === "/pb" || p === "/api/status" || p === "/api/bind" || p.startsWith("/api/admin/")) {
        await ensureSchema(env);
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
