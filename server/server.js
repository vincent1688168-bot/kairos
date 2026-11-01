// KAIROS · Binance Agentic Wallet 扫码登录代理（Node 18+，无依赖）
//
// 网站 POST /api/agent-wallet  { action, body }，请求头 X-KZ-Session 带上 login 返回的 sid。
// 动作：login / query / session / preview / execute / logout
//
// 安全限制：
// - 只会调用 KAIROS 合约（环境变量 ALLOW_TO）的 mintWithBnb；调用数据由服务器自己生成，
//   网页传不进任意交易。
// - 只执行本会话自己预览过的 requestId，每个只执行一次。
// - 会话只存在内存里，15 分钟过期；铸造完成后网页会调用 logout。
//
// 环境变量：
//   ALLOW_TO       KAIROS 合约地址（必填）
//   ALLOW_ORIGINS  允许的网站来源，逗号分隔，默认 https://kairosagentai.store,https://www.kairosagentai.store
//   RPC_URL        BSC RPC，默认 https://bsc-dataseed.bnbchain.org
//   PORT           端口，Render 会自动设置

const http = require("node:http");
const crypto = require("node:crypto");
const os = require("node:os");

const ALLOW_TO = (process.env.ALLOW_TO || "").toLowerCase();
const ALLOW_ORIGINS = (process.env.ALLOW_ORIGINS || "https://kairosagentai.store,https://www.kairosagentai.store").split(",").map((s) => s.trim()).filter(Boolean);
const RPC_URL = process.env.RPC_URL || "https://bsc-dataseed.bnbchain.org";
const BN_BASE = "https://www.binance.com";
const EP = "/bapi/defi/v1/public/wallet-direct/agent-wallet";
const CLIENT_VERSION = "1.12.0";
const SESSION_TTL = 15 * 60 * 1000;
const MAX_SESSIONS = 500;

// 函数选择器 = keccak256(签名) 前 4 字节（Node 自带的 sha3-256 不是 keccak，所以写死）
const SEL_MINT = "0xe38fd349"; // mintWithBnb(uint256,address,uint256)
const SEL_QUOTE = "0x68bce8cd"; // bnbQuote(uint256)

const sessions = new Map(); // sid -> session

// ---------------------------------------------------------------- 工具

const hex32 = (n) => BigInt(n).toString(16).padStart(64, "0");
const addr32 = (a) => a.toLowerCase().replace(/^0x/, "").padStart(64, "0");
const isAddr = (a) => typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a);

async function rpc(method, params) {
  const r = await fetch(RPC_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = await r.json();
  if (j.error) throw new Error(j.error.message || "rpc error");
  return j.result;
}

function newSession() {
  if (sessions.size >= MAX_SESSIONS) {
    const oldest = [...sessions.entries()].sort((a, b) => a[1].touched - b[1].touched)[0];
    if (oldest) sessions.delete(oldest[0]);
  }
  const sid = crypto.randomBytes(24).toString("hex");
  const s = { sid, clientId: crypto.randomUUID(), agentSessionId: null, qr: null, address: null, previews: new Set(), executed: new Map(), touched: Date.now() };
  sessions.set(sid, s);
  return s;
}

function getSession(req) {
  const sid = req.headers["x-kz-session"];
  const s = sid && sessions.get(String(sid));
  if (!s) throw httpErr(401, "会话已过期，请重新扫码 / Session expired, please sign in again");
  if (Date.now() - s.touched > SESSION_TTL) { sessions.delete(s.sid); throw httpErr(401, "会话已过期，请重新扫码 / Session expired, please sign in again"); }
  s.touched = Date.now();
  return s;
}

function httpErr(status, message) { const e = new Error(message); e.status = status; return e; }

// 调币安接口，带上该会话自己的 agentSessionId
async function bn(s, path, method, body) {
  const headers = {
    "Content-Type": "application/json",
    agentClientId: s.clientId,
    agentClientSystem: `${os.platform() === "linux" ? "Linux" : os.platform()} ${os.release()}`,
    agentClientMac: s.clientId,
    "bnc-uuid": s.clientId,
    "x-trace-id": crypto.randomBytes(16).toString("hex"),
    device_name: "kairos-web",
    system_lang: "en-US",
    timezone: "UTC",
    system_version: `${os.type()} ${os.release()} ${os.arch()}`,
    version_code: CLIENT_VERSION,
    clientVersion: CLIENT_VERSION,
    agentClientType: "AGENT_CLI",
    agentClientVersion: CLIENT_VERSION,
  };
  if (s.agentSessionId) headers.Cookie = `agentSessionId=${s.agentSessionId}`;
  const r = await fetch(BN_BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const setCookie = r.headers.get("set-cookie");
  const m = setCookie && setCookie.match(/agentSessionId=([^;]+)/);
  if (m) s.agentSessionId = m[1];
  if (!r.ok) throw httpErr(502, `Binance HTTP ${r.status}`);
  const j = await r.json();
  if (j.code !== "000000") throw httpErr(400, j.message || `Binance error ${j.code}`);
  return j.data;
}

// ---------------------------------------------------------------- 动作

const actions = {
  async login() {
    const s = newSession();
    const ecdh = crypto.createECDH("secp256k1");
    ecdh.generateKeys();
    const pub = ecdh.getPublicKey("hex", "compressed").substring(2);
    const d = await bn(s, `${EP}/login`, "POST", { isFirstLogin: true, os: "Linux", publicKeyHex: pub });
    if (!d || !d.qrInfo) throw httpErr(502, "Binance did not return a QR code");
    s.qr = d.qrInfo;
    return {
      sid: s.sid,
      qrCodeUrl: d.qrInfo.qrCodeUrl,
      pairingCode: pub.substring(0, 3) + pub.substring(pub.length - 3),
      expiresAt: Number(d.qrInfo.expireAt),
    };
  },

  async query(s) {
    if (!s.qr) throw httpErr(400, "not logging in");
    if (Date.now() > Number(s.qr.expireAt) && !s.connected) return { expired: true };
    if (!s.connected) {
      const c = await bn(s, `${EP}/login/confirm`, "POST", { qrCodeId: s.qr.qrCodeId });
      if (c.connectionStatus !== "CONNECTED") return { walletReady: false, status: c.connectionStatus };
      s.connected = true;
    }
    const q = await bn(s, `${EP}/login/query`, "GET");
    if (q.connectionStatus === "UNCONNECTED") return { expired: true };
    return { walletReady: q.walletCreateStatus === "CREATED" };
  },

  async session(s) {
    if (!s.address) {
      const d = await bn(s, `${EP}/mpc-wallet/list`, "POST");
      const subs = (d && d[0] && d[0].subWalletList) || [];
      for (const w of subs) for (const a of w.addresses || []) if (String(a.binanceChainId) === "56" && isAddr(a.address)) s.address = a.address;
      if (!s.address) for (const w of subs) if (w.curve === "secp256k1" && w.addresses && w.addresses[0] && isAddr(w.addresses[0].address)) s.address = w.addresses[0].address;
      if (!s.address) throw httpErr(400, "Agentic Wallet has no BSC address");
    }
    return { address: s.address };
  },

  async preview(s, body) {
    if (!ALLOW_TO) throw httpErr(503, "ALLOW_TO not configured");
    if (!s.address) await actions.session(s);
    const shares = Number(body && body.shares);
    if (!Number.isInteger(shares) || shares < 1 || shares > 10) throw httpErr(400, "shares must be 1–10");
    const referrer = body && isAddr(body.referrer) ? body.referrer : "0x0000000000000000000000000000000000000000";
    const quote = BigInt(await rpc("eth_call", [{ to: ALLOW_TO, data: SEL_QUOTE + hex32(shares) }, "latest"]));
    const maxCost = (quote * 102n) / 100n;
    const inputData = SEL_MINT + hex32(shares) + addr32(referrer) + hex32(maxCost);
    const d = await bn(s, `${EP}/contract-call/preview`, "POST", {
      binanceChainId: "56",
      from: s.address,
      to: ALLOW_TO,
      value: maxCost.toString(),
      inputData,
    });
    const requestId = d && d.requestId;
    if (!requestId) throw httpErr(502, "Binance preview returned no requestId");
    s.previews.add(String(requestId));
    return { requestId, costWei: quote.toString(), maxCostWei: maxCost.toString(), risks: d.risks || d.riskList || [], raw: summarize(d) };
  },

  // 第一次调用真正执行；之后的调用只查询状态，不会重复执行
  async execute(s, body) {
    const requestId = String(body && body.requestId);
    if (!s.previews.has(requestId)) throw httpErr(403, "unknown requestId");
    let ex = s.executed.get(requestId);
    if (!ex) {
      const d = await bn(s, `${EP}/contract-call/execute`, "POST", { requestId });
      ex = { hash: findHash(d), orderId: d && (d.orderId || d.id), raw: d };
      s.executed.set(requestId, ex);
    }
    if (!ex.hash && ex.orderId) {
      try {
        const st = await bn(s, `/bapi/defi/v2/public/wallet-direct/agent/tx-status?orderId=${encodeURIComponent(ex.orderId)}`, "GET");
        ex.hash = findHash(st) || ex.hash;
        if (st && /fail/i.test(String(st.status || st.txStatus || ""))) return { status: "failed" };
      } catch {}
    }
    if (!ex.hash) return { status: "pending", message: "Submitted, waiting for hash" };
    const rc = await rpc("eth_getTransactionReceipt", [ex.hash]).catch(() => null);
    if (!rc) return { status: "pending", hash: ex.hash };
    return { status: rc.status === "0x1" ? "success" : "failed", hash: ex.hash };
  },

  async logout(s) {
    try { await bn(s, `${EP}/login/logout`, "POST"); } catch {}
    sessions.delete(s.sid);
    return {};
  },
};

function findHash(o) {
  if (!o || typeof o !== "object") return null;
  for (const [k, v] of Object.entries(o)) {
    if (typeof v === "string" && /^0x[0-9a-fA-F]{64}$/.test(v) && /hash/i.test(k)) return v;
    if (v && typeof v === "object") { const h = findHash(v); if (h) return h; }
  }
  return null;
}

function summarize(d) {
  if (!d || typeof d !== "object") return null;
  const out = {};
  for (const k of ["gasFee", "gasFeeUsd", "estimatedGas", "balanceChanges", "simulationResult", "status"]) if (k in d) out[k] = d[k];
  return out;
}

// ---------------------------------------------------------------- HTTP

function cors(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOW_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-KZ-Session");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Vary", "Origin");
    return true;
  }
  return false;
}

function send(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(JSON.stringify(obj));
}

// ---------------------------------------------------------------- 演示数据（只给 /demo/ 演示页用）
// 管理页调好数字 → POST /api/demo（带 X-Demo-Key）→ 演示页开机时 GET /api/demo 读一次。
// 主站 index.html 不读这里，永远显示链上真实数据。

const fs = require("node:fs");
const path = require("node:path");
const DEMO_KEY = process.env.DEMO_KEY || "kairos-demo"; // 没设环境变量就用默认值，开箱即用；想换密码在 Render 设 DEMO_KEY 即可
const DEMO_FILE = path.join(__dirname, "demo.json");
let demoCfg = null;
try { demoCfg = JSON.parse(fs.readFileSync(DEMO_FILE, "utf8")); } catch {}

const intIn = (v, lo, hi, d) => { const n = Math.floor(Number(v)); return Number.isFinite(n) ? Math.max(lo, Math.min(hi, n)) : d; };
function normDemo(b) {
  const o = b && typeof b === "object" ? b : {};
  const extra = Array.isArray(o.extra)
    ? o.extra.filter((x) => x && typeof x.who === "string" && Number.isInteger(x.n) && x.n >= 1 && x.n <= 10).slice(-20)
    : [];
  return {
    sold: intIn(o.sold, 0, 309000, 6800),
    minted: intIn(o.minted, 0, 10, 0),
    n: intIn(o.n, 1, 10, 1),
    seed: intIn(o.seed, 1, 99999999, 7),
    jitter: !!o.jitter,
    extra,
    updatedAt: Date.now(),
  };
}
function saveDemo() { try { fs.writeFileSync(DEMO_FILE, JSON.stringify(demoCfg)); } catch {} }
function demoJson(req, res, status, obj) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Demo-Key");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  send(res, status, obj);
}
async function readBody(req, limit = 20000) {
  let raw = "";
  for await (const chunk of req) { raw += chunk; if (raw.length > limit) throw httpErr(413, "too large"); }
  return raw;
}

const server = http.createServer(async (req, res) => {
  if (req.url.split("?")[0] === "/api/demo") {
    if (req.method === "OPTIONS") { demoJson(req, res, 204, {}); return; }
    if (req.method === "GET") return demoJson(req, res, 200, { ok: true, data: demoCfg });
    if (req.method !== "POST") return demoJson(req, res, 405, { ok: false, error: { message: "method not allowed" } });
    if (String(req.headers["x-demo-key"] || "") !== DEMO_KEY) return demoJson(req, res, 401, { ok: false, error: { message: "wrong key" } });
    try {
      const body = JSON.parse((await readBody(req)) || "{}");
      demoCfg = normDemo(body.data || body);
      saveDemo();
      console.log("demo config saved", JSON.stringify(demoCfg).slice(0, 120));
      return demoJson(req, res, 200, { ok: true, data: demoCfg });
    } catch (e) {
      return demoJson(req, res, e.status || 400, { ok: false, error: { message: e.message || "bad request" } });
    }
  }
  const allowed = cors(req, res);
  if (req.method === "OPTIONS") { res.writeHead(allowed ? 204 : 403); return res.end(); }
  if (req.method === "GET" && (req.url === "/" || req.url === "/health")) return send(res, 200, { ok: true, contract: ALLOW_TO || null, sessions: sessions.size, demo: !!demoCfg });
  if (req.url !== "/api/agent-wallet" || req.method !== "POST") return send(res, 404, { ok: false, error: { message: "not found" } });
  if (!allowed) return send(res, 403, { ok: false, error: { message: "origin not allowed" } });
  let raw = "";
  for await (const chunk of req) { raw += chunk; if (raw.length > 10_000) return send(res, 413, { ok: false, error: { message: "too large" } }); }
  try {
    const { action, body } = JSON.parse(raw || "{}");
    const fn = Object.prototype.hasOwnProperty.call(actions, action) ? actions[action] : null;
    if (!fn) throw httpErr(400, "unknown action");
    const data = action === "login" ? await fn() : await fn(getSession(req), body);
    send(res, 200, { ok: true, data });
  } catch (e) {
    send(res, e.status || 500, { ok: false, error: { message: e.message || "error" } });
  }
});

setInterval(() => { const now = Date.now(); for (const [k, s] of sessions) if (now - s.touched > SESSION_TTL) sessions.delete(k); }, 60_000).unref();

server.listen(Number(process.env.PORT) || 10000, () => console.log("kairos agent-wallet proxy on", server.address().port, "contract", ALLOW_TO || "(not set)"));
