const KV_KEY = "nodes";
const KV_EXPIRY = "expiry";
const KV_TRAFFIC = "traffic";
const KV_SUBNAME = "subname";
const KV_SUBTOKEN = "subtoken";
const KV_SUBLIST = "sublist";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path === "/sub") return handleSub(request, env, url);
    if (path === "/admin") return handleAdmin(url.origin);
    if (path === "/api/login" && method === "POST") return handleLogin(request, env);
    if (path === "/api/list" && method === "GET") return handleList(request, env);
    if (path === "/api/save" && method === "POST") return handleSave(request, env);
    if (path === "/api/getexpiry" && method === "GET") return handleGetExpiry(request, env);
    if (path === "/api/setexpiry" && method === "POST") return handleSetExpiry(request, env);
    if (path === "/api/gettraffic" && method === "GET") return handleGetTraffic(request, env);
    if (path === "/api/settraffic" && method === "POST") return handleSetTraffic(request, env);
    if (path === "/api/getsubinfo" && method === "GET") return handleGetSubInfo(request, env);
    if (path === "/api/setsubinfo" && method === "POST") return handleSetSubInfo(request, env);
    if (path === "/api/getsublist" && method === "GET") return handleGetSubList(request, env);
    if (path === "/api/savesublist" && method === "POST") return handleSaveSubList(request, env);

    return new Response("Not Found", { status: 404 });
  }
};

function ok(data) {
  return new Response(JSON.stringify(data), {
    headers: { "Content-Type": "application/json" }
  });
}

function err(msg, status) {
  return new Response(JSON.stringify({ error: msg }), {
    status: status || 400,
    headers: { "Content-Type": "application/json" }
  });
}

function authed(request) {
  const cookie = request.headers.get("Cookie") || "";
  return cookie.includes("auth=1");
}

async function handleLogin(request, env) {
  let body;
  try { body = await request.json(); } catch { return err("bad request"); }
  if (body.password === env.PASSWORD) {
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": "auth=1; Path=/; HttpOnly; Max-Age=86400"
      }
    });
  }
  return ok({ ok: false });
}

async function handleList(request, env) {
  if (!authed(request)) return err("unauthorized", 401);
  let nodes = [];
  try { nodes = JSON.parse(await env.KV.get(KV_KEY) || "[]"); } catch {}
  return ok({ nodes });
}

async function handleSave(request, env) {
  if (!authed(request)) return err("unauthorized", 401);
  let body;
  try { body = await request.json(); } catch { return err("bad request"); }
  const nodes = body.nodes || [];
  const formattedNodes = nodes.map(item => {
    if (typeof item === 'string') {
      return { url: item.trim(), remark: '', enabled: true };
    } else if (typeof item === 'object' && item !== null) {
      return { 
        url: (item.url || '').trim(), 
        remark: (item.remark || '').trim(),
        enabled: item.enabled !== undefined ? item.enabled : true
      };
    }
    return null;
  }).filter(item => item && item.url);
  
  await env.KV.put(KV_KEY, JSON.stringify(formattedNodes));
  return ok({ ok: true });
}

async function handleGetExpiry(request, env) {
  if (!authed(request)) return err("unauthorized", 401);
  const expiry = await env.KV.get(KV_EXPIRY) || "";
  return ok({ expiry });
}

async function handleSetExpiry(request, env) {
  if (!authed(request)) return err("unauthorized", 401);
  let body;
  try { body = await request.json(); } catch { return err("bad request"); }
  const expiry = (body.expiry || "").trim();
  if (expiry && isNaN(Date.parse(expiry))) return err("invalid date");
  await env.KV.put(KV_EXPIRY, expiry);
  return ok({ ok: true });
}

async function handleGetTraffic(request, env) {
  if (!authed(request)) return err("unauthorized", 401);
  let traffic = { upload: "", download: "", total: "" };
  try { traffic = JSON.parse(await env.KV.get(KV_TRAFFIC) || "{}"); } catch {}
  return ok({ traffic });
}

async function handleSetTraffic(request, env) {
  if (!authed(request)) return err("unauthorized", 401);
  let body;
  try { body = await request.json(); } catch { return err("bad request"); }
  const traffic = {
    upload: (body.traffic.upload || "").trim(),
    download: (body.traffic.download || "").trim(),
    total: (body.traffic.total || "").trim()
  };
  await env.KV.put(KV_TRAFFIC, JSON.stringify(traffic));
  return ok({ ok: true });
}

async function handleGetSubInfo(request, env) {
  if (!authed(request)) return err("unauthorized", 401);
  const subname = await env.KV.get(KV_SUBNAME) || "";
  const subtoken = await env.KV.get(KV_SUBTOKEN) || "";
  return ok({ subname, subtoken });
}

async function handleSetSubInfo(request, env) {
  if (!authed(request)) return err("unauthorized", 401);
  let body;
  try { body = await request.json(); } catch { return err("bad request"); }
  const subname = (body.subname || "").trim();
  const subtoken = (body.subtoken || "").trim();
  await env.KV.put(KV_SUBNAME, subname);
  await env.KV.put(KV_SUBTOKEN, subtoken);
  return ok({ ok: true });
}

async function handleGetSubList(request, env) {
  if (!authed(request)) return err("unauthorized", 401);
  let sublist = [];
  try { sublist = JSON.parse(await env.KV.get(KV_SUBLIST) || "[]"); } catch {}
  return ok({ sublist });
}

async function handleSaveSubList(request, env) {
  if (!authed(request)) return err("unauthorized", 401);
  let body;
  try { body = await request.json(); } catch { return err("bad request"); }
  const sublist = body.sublist || [];
  
  if (sublist.length === 0) {
    await env.KV.put(KV_SUBLIST, JSON.stringify([]));
    return ok({ ok: true });
  }
  
  const tokens = new Set();
  for (const item of sublist) {
    if (!item.token || !item.token.trim()) {
      return err("每个订阅必须有一个 Token", 400);
    }
    const token = item.token.trim();
    if (tokens.has(token)) {
      return err(`Token "${token}" 重复`, 400);
    }
    tokens.add(token);
    
    if (item.expiry && isNaN(Date.parse(item.expiry))) {
      return err(`订阅 "${item.name}" 的过期时间格式无效`, 400);
    }
    
    // 验证流量格式
    if (item.traffic) {
      const traffic = item.traffic;
      if (traffic.upload && !traffic.upload.match(/^[\d.]+[KMGT]?B?$/i)) {
        return err(`订阅 "${item.name}" 的上传流量格式无效`, 400);
      }
      if (traffic.download && !traffic.download.match(/^[\d.]+[KMGT]?B?$/i)) {
        return err(`订阅 "${item.name}" 的下载流量格式无效`, 400);
      }
      if (traffic.total && !traffic.total.match(/^[\d.]+[KMGT]?B?$/i)) {
        return err(`订阅 "${item.name}" 的总流量格式无效`, 400);
      }
    }
  }
  
  await env.KV.put(KV_SUBLIST, JSON.stringify(sublist));
  return ok({ ok: true });
}

function parseBytes(str) {
  if (!str) return 0;
  str = str.trim().toUpperCase();
  const m = str.match(/^([\d.]+)\s*([KMGT]?)B?$/);
  if (!m) return 0;
  const n = parseFloat(m[1]);
  const units = { "": 1, K: 1024, M: 1024 ** 2, G: 1024 ** 3, T: 1024 ** 4 };
  return Math.round(n * (units[m[2]] || 1));
}

async function handleSub(request, env, url) {
  const reqToken = url.searchParams.get("token") || "";
  
  const mainToken = await env.KV.get(KV_SUBTOKEN) || "";
  
  if (reqToken) {
    if (mainToken && reqToken === mainToken) {
      return handleMainSub(request, env, url);
    }
    
    let sublist = [];
    try { sublist = JSON.parse(await env.KV.get(KV_SUBLIST) || "[]"); } catch {}
    const subConfig = sublist.find(s => s.token === reqToken);
    if (subConfig) {
      if (subConfig.expiry) {
        const now = new Date();
        const expiryDate = new Date(subConfig.expiry);
        // 按天比较
        now.setHours(0, 0, 0, 0);
        expiryDate.setHours(0, 0, 0, 0);
        if (expiryDate < now) {
          return new Response("Subscription expired", { 
            status: 403,
            headers: { "Content-Type": "text/plain; charset=utf-8" }
          });
        }
      }
      return handleCustomSub(request, env, url, subConfig);
    }
    
    return new Response("Invalid token", { status: 403 });
  }
  
  if (mainToken && mainToken.length > 0) {
    return new Response("Missing token parameter. Please use ?token=xxx", { 
      status: 400,
      headers: { "Content-Type": "text/plain; charset=utf-8" }
    });
  }
  
  return handleMainSub(request, env, url);
}

async function handleMainSub(request, env, url) {
  let raw = [];
  try { raw = JSON.parse(await env.KV.get(KV_KEY) || "[]"); } catch {}

  const out = [];
  await Promise.all(raw.map(async item => {
    if (item.enabled === false) return;
    
    const line = typeof item === 'string' ? item : item.url;
    if (!line) return;
    
    if (line.startsWith("http://") || line.startsWith("https://")) {
      try {
        let text = await fetch(line).then(r => r.text());
        const clean = text.trim().replace(/\s/g, "");
        if (/^[A-Za-z0-9+/]+=*$/.test(clean)) {
          try { text = decodeURIComponent(escape(atob(clean))); } catch {}
        }
        text.split("\n").forEach(l => {
          l = l.trim();
          if (l && !l.startsWith("#") && !l.includes("EXPIRE")) out.push(l);
        });
      } catch {}
    } else if (line.trim()) {
      out.push(line.trim());
    }
  }));

  return buildSubResponse(out, env, null);
}

async function handleCustomSub(request, env, url, subConfig) {
  let raw = [];
  try { raw = JSON.parse(await env.KV.get(KV_KEY) || "[]"); } catch {}

  const selectedIndices = new Set(subConfig.selectedIndices || []);
  
  const out = [];
  await Promise.all(raw.map(async (item, index) => {
    if (!selectedIndices.has(index)) return;
    if (item.enabled === false) return;
    
    const line = typeof item === 'string' ? item : item.url;
    if (!line) return;
    
    if (line.startsWith("http://") || line.startsWith("https://")) {
      try {
        let text = await fetch(line).then(r => r.text());
        const clean = text.trim().replace(/\s/g, "");
        if (/^[A-Za-z0-9+/]+=*$/.test(clean)) {
          try { text = decodeURIComponent(escape(atob(clean))); } catch {}
        }
        text.split("\n").forEach(l => {
          l = l.trim();
          if (l && !l.startsWith("#") && !l.includes("EXPIRE")) out.push(l);
        });
      } catch {}
    } else if (line.trim()) {
      out.push(line.trim());
    }
  }));

  return buildSubResponse(out, env, subConfig);
}

async function buildSubResponse(out, env, subConfig) {
  const encoded = btoa(unescape(encodeURIComponent(out.join("\n"))));

  // 获取全局流量
  let globalTraffic = { upload: "", download: "", total: "" };
  try { globalTraffic = JSON.parse(await env.KV.get(KV_TRAFFIC) || "{}"); } catch {}

  const parts = [];
  
  // 优先使用自定义订阅的流量，如果没有则使用全局流量
  let upload = globalTraffic.upload;
  let download = globalTraffic.download;
  let total = globalTraffic.total;
  
  if (subConfig && subConfig.traffic) {
    if (subConfig.traffic.upload !== undefined) upload = subConfig.traffic.upload;
    if (subConfig.traffic.download !== undefined) download = subConfig.traffic.download;
    if (subConfig.traffic.total !== undefined) total = subConfig.traffic.total;
  }
  
  if (upload) parts.push("upload=" + parseBytes(upload));
  if (download) parts.push("download=" + parseBytes(download));
  if (total) parts.push("total=" + parseBytes(total));
  
  // 获取到期时间
  const globalExpiry = await env.KV.get(KV_EXPIRY) || "";
  let finalExpiry = globalExpiry;
  if (subConfig && subConfig.expiry) {
    finalExpiry = subConfig.expiry;
  }
  
  if (finalExpiry) {
    const dateObj = new Date(finalExpiry);
    // 如果是 YYYY-MM-DD 格式，设置为当天 23:59:59
    if (finalExpiry.match(/^\d{4}-\d{2}-\d{2}$/)) {
      dateObj.setHours(23, 59, 59, 999);
    }
    parts.push("expire=" + Math.floor(dateObj.getTime() / 1000));
  }

  const subname = await env.KV.get(KV_SUBNAME) || "";
  
  const headers = {
    "Content-Type": "text/plain; charset=utf-8",
    "Profile-Update-Interval": "24",
    "Subscription-Userinfo": parts.join("; ")
  };
  
  if (subname) {
    headers["Profile-Title"] = subname;
  }

  return new Response(encoded, { headers });
}

function handleAdmin(origin) {
  const subUrl = origin + "/sub";

  const style = [
    "*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}",
    ":root{--bg:#0d0e14;--sur:#13151e;--bor:#1f2130;--a:#7c6ef5;--b:#5de7b4;--tx:#dde1f0;--mu:#6b7097;--red:#f56e6e;--warn:#f5a623;--r:12px}",
    "body{background:var(--bg);color:var(--tx);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}",
    ".wrap{width:100%;max-width:960px}",
    ".hd{text-align:center;margin-bottom:32px}",
    ".hd h1{font-size:1.7rem;font-weight:700;background:linear-gradient(135deg,var(--a),var(--b));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}",
    ".hd p{color:var(--mu);margin-top:6px;font-size:.9rem}",
    ".card{background:var(--sur);border:1px solid var(--bor);border-radius:var(--r);padding:24px;margin-bottom:16px}",
    ".label{font-size:.75rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--mu);margin-bottom:14px}",
    ".row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}",
    ".grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:12px}",
    ".grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px}",
    ".field label{font-size:.75rem;color:var(--mu);display:block;margin-bottom:4px}",
    "input[type=password],input[type=date],input[type=text]{width:100%;background:var(--bg);border:1px solid var(--bor);border-radius:8px;color:var(--tx);padding:10px 14px;font-size:.95rem;outline:none;transition:border-color .2s}",
    "input[type=date]{color-scheme:dark}",
    "input:focus{border-color:var(--a)}",
    ".btn{border:none;border-radius:8px;padding:10px 18px;font-size:.9rem;font-weight:600;cursor:pointer;white-space:nowrap;transition:transform .1s}",
    ".btn:active{transform:scale(.97)}",
    ".pa{background:linear-gradient(135deg,var(--a),#5b52d8);color:#fff}",
    ".pb{background:linear-gradient(135deg,var(--b),#39c49a);color:#0d0e14}",
    ".pc{background:transparent;border:1px solid var(--bor);color:var(--tx)}",
    ".sm{padding:6px 12px;font-size:.82rem}",
    ".subbox{display:flex;align-items:center;gap:10px;background:var(--bg);border:1px solid var(--bor);border-radius:8px;padding:10px 14px}",
    ".suburl{flex:1;font-family:monospace;font-size:.88rem;color:var(--b);word-break:break-all}",
    ".nodes-container{display:flex;flex-direction:column;gap:8px;margin-top:8px}",
    ".node-item{display:flex;gap:8px;align-items:center;background:var(--bg);border:1px solid var(--bor);border-radius:8px;padding:8px 12px}",
    ".node-item.disabled{opacity:0.5;border-color:var(--mu)}",
    ".node-toggle{flex-shrink:0;width:36px;height:20px;background:var(--bor);border-radius:10px;cursor:pointer;position:relative;transition:background .3s;border:none;padding:0}",
    ".node-toggle.active{background:var(--a)}",
    ".node-toggle::after{content:'';position:absolute;top:2px;left:2px;width:16px;height:16px;background:#fff;border-radius:50%;transition:transform .3s}",
    ".node-toggle.active::after{transform:translateX(16px)}",
    ".node-url{flex:2;background:transparent;border:none;color:var(--tx);font-family:monospace;font-size:.82rem;padding:6px;outline:none;min-width:0}",
    ".node-remark{flex:1;background:transparent;border:none;color:var(--mu);font-size:.82rem;padding:6px;outline:none;border-left:1px solid var(--bor);padding-left:12px;min-width:0}",
    ".node-url:focus,.node-remark:focus{color:var(--tx)}",
    ".node-actions{display:flex;gap:4px;flex-shrink:0}",
    ".node-actions button{background:transparent;border:none;color:var(--mu);cursor:pointer;padding:4px 8px;font-size:.8rem;border-radius:4px}",
    ".node-actions button:hover{background:var(--bor);color:var(--tx)}",
    ".node-actions .del:hover{color:var(--red)}",
    ".add-node-btn{background:var(--bg);border:1px dashed var(--bor);border-radius:8px;padding:10px;color:var(--mu);cursor:pointer;text-align:center;font-size:.85rem;transition:all .2s}",
    ".add-node-btn:hover{border-color:var(--a);color:var(--a)}",
    ".foot{display:flex;align-items:center;justify-content:space-between;margin-top:12px;gap:10px;flex-wrap:wrap}",
    ".stats{display:flex;gap:16px;flex-wrap:wrap}",
    ".stat{font-size:.82rem;color:var(--mu)}",
    ".stat b{color:var(--tx);font-weight:600}",
    ".stat .enabled-count{color:var(--b)}",
    ".stat .disabled-count{color:var(--mu)}",
    ".preview{background:var(--bg);border:1px solid var(--bor);border-radius:8px;padding:10px 14px;font-size:.82rem;color:var(--mu);margin-top:12px;font-family:monospace;min-height:36px}",
    ".preview span{color:var(--b)}",
    ".tip{background:rgba(124,110,245,.08);border:1px solid rgba(124,110,245,.2);border-radius:8px;padding:12px 14px;font-size:.82rem;color:var(--mu);line-height:1.8}",
    ".tip strong{color:var(--a)}",
    ".expiry-bar{border-radius:8px;padding:10px 14px;font-size:.85rem;font-weight:500;margin-top:12px;display:flex;align-items:center;gap:8px}",
    ".expiry-ok{background:rgba(93,231,180,.08);border:1px solid rgba(93,231,180,.25);color:var(--b)}",
    ".expiry-warn{background:rgba(245,166,35,.1);border:1px solid rgba(245,166,35,.35);color:var(--warn)}",
    ".expiry-danger{background:rgba(245,110,110,.1);border:1px solid rgba(245,110,110,.35);color:var(--red)}",
    ".expiry-none{background:rgba(107,112,151,.08);border:1px solid var(--bor);color:var(--mu)}",
    ".token-badge{display:inline-flex;align-items:center;gap:6px;background:rgba(93,231,180,.08);border:1px solid rgba(93,231,180,.2);border-radius:6px;padding:4px 10px;font-size:.78rem;color:var(--b);margin-top:8px}",
    ".token-none{background:rgba(107,112,151,.08);border-color:var(--bor);color:var(--mu)}",
    ".sublist-container{display:flex;flex-direction:column;gap:12px;margin-top:8px}",
    ".sub-item{background:var(--bg);border:1px solid var(--bor);border-radius:8px;padding:12px}",
    ".sub-item-header{display:flex;gap:10px;align-items:flex-start;margin-bottom:8px;flex-wrap:wrap}",
    ".sub-item .sub-name{flex:1;min-width:100px;background:transparent;border:1px solid var(--bor);border-radius:6px;color:var(--tx);padding:6px 10px;font-size:.85rem}",
    ".sub-item .sub-token-input{flex:1;min-width:130px;background:transparent;border:1px solid var(--bor);border-radius:6px;color:var(--b);padding:6px 10px;font-size:.82rem;font-family:monospace}",
    ".sub-item .sub-expiry-input{flex:0.8;min-width:120px;background:transparent;border:1px solid var(--bor);border-radius:6px;color:var(--tx);padding:6px 10px;font-size:.82rem;color-scheme:dark}",
    ".sub-item .sub-actions{display:flex;gap:4px;flex-wrap:wrap}",
    ".sub-item .sub-actions button{background:transparent;border:none;color:var(--mu);cursor:pointer;padding:4px 8px;font-size:.8rem;border-radius:4px}",
    ".sub-item .sub-actions button:hover{background:var(--bor);color:var(--tx)}",
    ".sub-item .sub-actions .del:hover{color:var(--red)}",
    ".sub-item .sub-expiry-status{font-size:.72rem;padding:2px 8px;border-radius:4px;white-space:nowrap}",
    ".sub-item .sub-expiry-status.active{background:rgba(93,231,180,.1);color:var(--b)}",
    ".sub-item .sub-expiry-status.expired{background:rgba(245,110,110,.1);color:var(--red)}",
    ".sub-item .sub-expiry-status.none{background:rgba(107,112,151,.08);color:var(--mu)}",
    ".sub-item .sub-expiry-status.warning{background:rgba(245,166,35,.1);color:var(--warn)}",
    ".sub-item .node-select-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:6px;margin-top:8px}",
    ".sub-item .node-select-item{display:flex;align-items:center;gap:6px;font-size:.82rem;padding:4px 8px;background:rgba(255,255,255,.03);border-radius:4px}",
    ".sub-item .node-select-item input[type=checkbox]{accent-color:var(--a);cursor:pointer}",
    ".sub-item .node-select-item label{cursor:pointer;color:var(--tx);flex:1}",
    ".sub-item .node-select-item .node-idx{color:var(--mu);font-size:.7rem;margin-right:4px}",
    ".add-sub-btn{background:var(--bg);border:1px dashed var(--bor);border-radius:8px;padding:10px;color:var(--mu);cursor:pointer;text-align:center;font-size:.85rem;transition:all .2s;margin-top:8px}",
    ".add-sub-btn:hover{border-color:var(--a);color:var(--a)}",
    ".sub-url-box{display:flex;gap:8px;align-items:center;background:rgba(124,110,245,.05);border:1px solid rgba(124,110,245,.15);border-radius:6px;padding:4px 8px;margin-top:8px}",
    ".sub-url-box .sub-url{flex:1;font-family:monospace;font-size:.78rem;color:var(--b);word-break:break-all}",
    ".sub-url-box .copy-btn{background:transparent;border:none;color:var(--mu);cursor:pointer;font-size:.75rem;padding:2px 8px;border-radius:4px}",
    ".sub-url-box .copy-btn:hover{background:rgba(255,255,255,.05);color:var(--tx)}",
    ".gen-token-btn{color:var(--b) !important}",
    ".gen-token-btn:hover{background:rgba(93,231,180,.1) !important}",
    ".warning-text{color:var(--warn);font-size:.75rem}",
    ".status-ok{color:var(--b)}",
    ".status-warn{color:var(--warn)}",
    ".sub-item .sub-expiry-row{display:flex;gap:8px;align-items:center;flex:1;min-width:200px}",
    ".sub-item .sub-traffic-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;margin-top:6px}",
    ".sub-item .sub-traffic-grid input{background:transparent;border:1px solid var(--bor);border-radius:6px;color:var(--tx);padding:4px 8px;font-size:.78rem;width:100%}",
    ".sub-item .sub-traffic-grid input::placeholder{color:var(--mu)}",
    ".info-text{color:var(--mu);font-size:.75rem;font-weight:400}",
    ".traffic-label{font-size:.7rem;color:var(--mu);margin-bottom:2px;display:block}",
    ".sub-item .sub-traffic-section{margin-top:6px;padding-top:6px;border-top:1px solid var(--bor)}",
    "#toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%);background:#22253a;border:1px solid var(--bor);color:var(--tx);padding:10px 22px;border-radius:20px;font-size:.88rem;opacity:0;transition:opacity .25s;pointer-events:none;white-space:nowrap;z-index:999}",
    "#toast.on{opacity:1}"
  ].join("\n");

  const script = [
    "var T;",
    "function toast(m,e){",
    "  var el=document.getElementById('toast');",
    "  el.textContent=m;",
    "  el.style.borderColor=e?'var(--red)':'var(--bor)';",
    "  el.classList.add('on');",
    "  clearTimeout(T);",
    "  T=setTimeout(function(){el.classList.remove('on');},2200);",
    "}",

    "function stat(){",
    "  var items=document.querySelectorAll('.node-item');",
    "  var total=items.length;",
    "  var enabled=0,disabled=0,subs=0,nodes=0;",
    "  items.forEach(function(item){",
    "    var url=item.querySelector('.node-url').value;",
    "    var isEnabled=item.dataset.enabled !== 'false';",
    "    if(isEnabled)enabled++;else disabled++;",
    "    if(url.startsWith('http://')||url.startsWith('https://'))subs++;else nodes++;",
    "  });",
    "  document.getElementById('s1').textContent=total;",
    "  document.getElementById('s2').textContent=subs;",
    "  document.getElementById('s3').textContent=nodes;",
    "  document.getElementById('s4').textContent=enabled;",
    "  document.getElementById('s5').textContent=disabled;",
    "}",

    "function toggleNode(btn){",
    "  var item=btn.closest('.node-item');",
    "  var isEnabled=item.dataset.enabled !== 'false';",
    "  item.dataset.enabled=isEnabled?'false':'true';",
    "  btn.classList.toggle('active');",
    "  item.classList.toggle('disabled');",
    "  stat();",
    "  updateSubList();",
    "}",

    "function addNodeRow(url, remark, enabled){",
    "  var container=document.getElementById('nodes-container');",
    "  var div=document.createElement('div');",
    "  div.className='node-item'+(enabled===false?' disabled':'');",
    "  div.dataset.enabled=enabled!==false?'true':'false';",
    "  div.innerHTML='<button class=\"node-toggle'+(enabled!==false?' active':'')+'\" onclick=\"toggleNode(this)\"></button>'",
    "    +'<input class=\"node-url\" type=\"text\" placeholder=\"vmess:// 或 http://...\" value=\"'+escapeHtml(url||'')+'\">'",
    "    +'<input class=\"node-remark\" type=\"text\" placeholder=\"备注（可选）\" value=\"'+escapeHtml(remark||'')+'\">'",
    "    +'<div class=\"node-actions\">'",
    "    +'<button onclick=\"moveNodeUp(this)\" title=\"上移\">↑</button>'",
    "    +'<button onclick=\"moveNodeDown(this)\" title=\"下移\">↓</button>'",
    "    +'<button class=\"del\" onclick=\"deleteNode(this)\" title=\"删除\">✕</button>'",
    "    +'</div>';",
    "  container.appendChild(div);",
    "  stat();",
    "  updateSubList();",
    "}",

    "function escapeHtml(str){",
    "  if(!str)return '';",
    "  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;');",
    "}",

    "function deleteNode(btn){",
    "  var item=btn.closest('.node-item');",
    "  if(item){item.remove();stat();updateSubList();}",
    "}",

    "function moveNodeUp(btn){",
    "  var item=btn.closest('.node-item');",
    "  var prev=item.previousElementSibling;",
    "  if(prev){item.parentNode.insertBefore(item,prev);stat();updateSubList();}",
    "}",

    "function moveNodeDown(btn){",
    "  var item=btn.closest('.node-item');",
    "  var next=item.nextElementSibling;",
    "  if(next){item.parentNode.insertBefore(next,item);stat();updateSubList();}",
    "}",

    "function parseBytes(str){",
    "  if(!str)return 0;",
    "  str=str.trim().toUpperCase();",
    "  var m=str.match(/^([\\d.]+)\\s*([KMGT]?)B?$/);",
    "  if(!m)return 0;",
    "  var n=parseFloat(m[1]);",
    "  var u={'':1,'K':1024,'M':1048576,'G':1073741824,'T':1099511627776};",
    "  return Math.round(n*(u[m[2]]||1));",
    "}",

    "function fmtBytes(b){",
    "  if(!b||b===0)return '';",
    "  if(b>=1099511627776)return (b/1099511627776).toFixed(2)+'T';",
    "  if(b>=1073741824)return (b/1073741824).toFixed(2)+'G';",
    "  if(b>=1048576)return (b/1048576).toFixed(2)+'M';",
    "  if(b>=1024)return (b/1024).toFixed(2)+'K';",
    "  return b+'B';",
    "}",

    "function updatePreview(){",
    "  var up=parseBytes(document.getElementById('t-up').value);",
    "  var dl=parseBytes(document.getElementById('t-dl').value);",
    "  var tot=parseBytes(document.getElementById('t-tot').value);",
    "  var exp=document.getElementById('expiry-input').value;",
    "  var parts=[];",
    "  if(up)parts.push('upload='+up);",
    "  if(dl)parts.push('download='+dl);",
    "  if(tot)parts.push('total='+tot);",
    "  if(exp)parts.push('expire='+Math.floor(new Date(exp).getTime()/1000));",
    "  var prev=document.getElementById('header-preview');",
    "  if(parts.length){",
    "    prev.innerHTML='Subscription-Userinfo: <span>'+parts.join('; ')+'</span>';",
    "  }else{",
    "    prev.textContent='（未填写任何字段，不输出 header）';",
    "  }",
    "}",

    "function renderExpiryBar(dateStr){",
    "  var bar=document.getElementById('expiry-bar');",
    "  if(!dateStr){bar.className='expiry-bar expiry-none';bar.textContent='📅 未设置到期时间';return;}",
    "  var exp=new Date(dateStr);var now=new Date();",
    "  now.setHours(0,0,0,0);exp.setHours(0,0,0,0);",
    "  var diff=Math.round((exp-now)/(86400000));",
    "  if(diff<0){bar.className='expiry-bar expiry-danger';bar.textContent='🚨 域名已过期 '+Math.abs(diff)+' 天，请立即续费！';}",
    "  else if(diff===0){bar.className='expiry-bar expiry-danger';bar.textContent='🚨 域名今天到期，请立即续费！';}",
    "  else if(diff<=30){bar.className='expiry-bar expiry-warn';bar.textContent='⚠️ 域名将在 '+diff+' 天后到期（'+dateStr+'），请及时续费';}",
    "  else{bar.className='expiry-bar expiry-ok';bar.textContent='✓ 域名有效，距到期还有 '+diff+' 天（'+dateStr+'）';}",
    "}",

    "function updateSubUrl(){",
    "  var tok=document.getElementById('inp-token').value.trim();",
    "  var base='" + subUrl + "';",
    "  var full=tok?base+'?token='+encodeURIComponent(tok):base;",
    "  document.getElementById('sub-url-display').textContent=full;",
    "  document.getElementById('sub-url-full').value=full;",
    "  var badge=document.getElementById('token-badge');",
    "  var statusText=document.getElementById('sub-status');",
    "  if(tok){",
    "    badge.className='token-badge';",
    "    badge.innerHTML='🔒 已设置主订阅 Token，访问需要携带 token';",
    "    statusText.className='status-ok';",
    "    statusText.textContent='需要 Token 访问';",
    "  }else{",
    "    badge.className='token-badge token-none';",
    "    badge.innerHTML='🔓 未设置主订阅 Token，直接访问 /sub 即可';",
    "    statusText.className='status-warn';",
    "    statusText.textContent='公开访问';",
    "  }",
    "}",

    "function getNodeLabels(){",
    "  var items=document.querySelectorAll('.node-item');",
    "  var labels=[];",
    "  items.forEach(function(item){",
    "    var url=item.querySelector('.node-url').value;",
    "    var remark=item.querySelector('.node-remark').value;",
    "    var label=remark || url.substring(0,30)+(url.length>30?'...':'');",
    "    labels.push(label);",
    "  });",
    "  return labels;",
    "}",

    "function updateSubList(){",
    "  var items=document.querySelectorAll('.node-item');",
    "  var subItems=document.querySelectorAll('.sub-item');",
    "  var labels=getNodeLabels();",
    "  subItems.forEach(function(subItem){",
    "    var container=subItem.querySelector('.node-select-grid');",
    "    if(!container)return;",
    "    var checkboxes=container.querySelectorAll('input[type=checkbox]');",
    "    if(checkboxes.length!==items.length){",
    "      rebuildSubSelect(container, items.length, labels);",
    "    }else{",
    "      checkboxes.forEach(function(cb,idx){",
    "        var label=cb.closest('label');",
    "        if(label && idx<labels.length){",
    "          var textNode=label.childNodes[label.childNodes.length-1];",
    "          if(textNode)textNode.textContent=labels[idx];",
    "        }",
    "      });",
    "    }",
    "  });",
    "}",

    "function rebuildSubSelect(container, count, labels){",
    "  container.innerHTML='';",
    "  for(var i=0;i<count;i++){",
    "    var div=document.createElement('div');",
    "    div.className='node-select-item';",
    "    var cb=document.createElement('input');",
    "    cb.type='checkbox';",
    "    cb.value=i;",
    "    cb.checked=true;",
    "    var label=document.createElement('label');",
    "    var idxSpan=document.createElement('span');",
    "    idxSpan.className='node-idx';",
    "    idxSpan.textContent='#'+(i+1);",
    "    label.appendChild(idxSpan);",
    "    var textNode=document.createTextNode(labels[i]||'（空）');",
    "    label.appendChild(textNode);",
    "    div.appendChild(cb);",
    "    div.appendChild(label);",
    "    container.appendChild(div);",
    "  }",
    "}",

    "function genRandomToken(length){",
    "  var chars='ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';",
    "  var t='';for(var i=0;i<length;i++)t+=chars[Math.floor(Math.random()*chars.length)];",
    "  return t;",
    "}",

    "function updateExpiryStatus(input){",
    "  var item=input.closest('.sub-item');",
    "  var statusSpan=item.querySelector('.sub-expiry-status');",
    "  var val=input.value.trim();",
    "  if(!val){",
    "    statusSpan.className='sub-expiry-status none';",
    "    statusSpan.textContent='永久有效';",
    "    return;",
    "  }",
    "  var now=new Date();now.setHours(0,0,0,0);",
    "  var exp=new Date(val);exp.setHours(0,0,0,0);",
    "  var diff=Math.round((exp-now)/(86400000));",
    "  if(diff<0){",
    "    statusSpan.className='sub-expiry-status expired';",
    "    statusSpan.textContent='已过期 '+(diff*-1)+' 天';",
    "  }else if(diff===0){",
    "    statusSpan.className='sub-expiry-status warning';",
    "    statusSpan.textContent='今天到期';",
    "  }else if(diff<=7){",
    "    statusSpan.className='sub-expiry-status warning';",
    "    statusSpan.textContent=diff+' 天后到期';",
    "  }else{",
    "    statusSpan.className='sub-expiry-status active';",
    "    statusSpan.textContent=diff+' 天后到期';",
    "  }",
    "}",

    "function addSubItem(id, name, token, selectedIndices, expiry, traffic){",
    "  var container=document.getElementById('sublist-container');",
    "  var div=document.createElement('div');",
    "  div.className='sub-item';",
    "  div.dataset.id=id||Date.now()+'_'+Math.random().toString(36).substr(2,4);",
    "  var items=document.querySelectorAll('.node-item');",
    "  var labels=getNodeLabels();",
    "  var checkboxesHtml='';",
    "  var selSet=new Set(selectedIndices||[]);",
    "  for(var i=0;i<items.length;i++){",
    "    var checked=selSet.has(i);",
    "    checkboxesHtml+='<div class=\"node-select-item\">'",
    "      +'<input type=\"checkbox\" value=\"'+i+'\"'+(checked?' checked':'')+'>'",
    "      +'<label><span class=\"node-idx\">#'+(i+1)+'</span>'+escapeHtml(labels[i]||'（空）')+'</label>'",
    "      +'</div>';",
    "  }",
    "  var subToken=token||genRandomToken(24);",
    "  var baseUrl='" + subUrl + "';",
    "  var fullUrl=baseUrl+'?token='+subToken;",
    "  var expiryVal=expiry||'';",
    "  var statusText='永久有效';",
    "  var statusClass='none';",
    "  if(expiryVal){",
    "    var now=new Date();now.setHours(0,0,0,0);",
    "    var exp=new Date(expiryVal);exp.setHours(0,0,0,0);",
    "    var diff=Math.round((exp-now)/(86400000));",
    "    if(diff<0){statusText='已过期 '+(diff*-1)+' 天';statusClass='expired';}",
    "    else if(diff===0){statusText='今天到期';statusClass='warning';}",
    "    else if(diff<=7){statusText=diff+' 天后到期';statusClass='warning';}",
    "    else{statusText=diff+' 天后到期';statusClass='active';}",
    "  }",
    "  var t=traffic||{};",
    "  div.innerHTML='<div class=\"sub-item-header\">'",
    "    +'<input class=\"sub-name\" type=\"text\" placeholder=\"订阅名称\" value=\"'+escapeHtml(name||'')+'\">'",
    "    +'<input class=\"sub-token-input\" type=\"text\" placeholder=\"Token（自定义）\" value=\"'+subToken+'\" oninput=\"updateSubUrlFromInput(this)\">'",
    "    +'<div class=\"sub-expiry-row\">'",
    "    +'<input class=\"sub-expiry-input\" type=\"date\" value=\"'+expiryVal+'\" oninput=\"updateExpiryStatus(this)\">'",
    "    +'<span class=\"sub-expiry-status '+statusClass+'\">'+statusText+'</span>'",
    "    +'</div>'",
    "    +'<div class=\"sub-actions\">'",
    "    +'<button onclick=\"genTokenForSub(this)\" class=\"gen-token-btn\" title=\"生成随机 Token\">🎲</button>'",
    "    +'<button onclick=\"deleteSub(this)\" class=\"del\" title=\"删除\">✕</button>'",
    "    +'</div>'",
    "    +'</div>'",
    "    +'<div class=\"sub-traffic-section\">'",
    "    +'<div class=\"sub-traffic-grid\">'",
    "    +'<div><span class=\"traffic-label\">已上传</span><input class=\"sub-traffic-upload\" type=\"text\" placeholder=\"例如 53G\" value=\"'+escapeHtml(t.upload||'')+'\"></div>'",
    "    +'<div><span class=\"traffic-label\">已下载</span><input class=\"sub-traffic-download\" type=\"text\" placeholder=\"例如 93G\" value=\"'+escapeHtml(t.download||'')+'\"></div>'",
    "    +'<div><span class=\"traffic-label\">总流量</span><input class=\"sub-traffic-total\" type=\"text\" placeholder=\"例如 5T\" value=\"'+escapeHtml(t.total||'')+'\"></div>'",
    "    +'</div>'",
    "    +'</div>'",
    "    +'<div class=\"node-select-grid\">'+checkboxesHtml+'</div>'",
    "    +'<div class=\"sub-url-box\">'",
    "    +'<span class=\"sub-url\">'+fullUrl+'</span>'",
    "    +'<button class=\"copy-btn\" onclick=\"copySubUrl(this)\">复制</button>'",
    "    +'</div>';",
    "  container.appendChild(div);",
    "}",

    "function updateSubUrlFromInput(input){",
    "  var item=input.closest('.sub-item');",
    "  var token=input.value.trim();",
    "  var urlSpan=item.querySelector('.sub-url');",
    "  var baseUrl='" + subUrl + "';",
    "  if(token){",
    "    urlSpan.textContent=baseUrl+'?token='+encodeURIComponent(token);",
    "  }else{",
    "    urlSpan.textContent='（请设置 Token）';",
    "  }",
    "}",

    "function deleteSub(btn){",
    "  var item=btn.closest('.sub-item');",
    "  if(item){item.remove();}",
    "}",

    "function genTokenForSub(btn){",
    "  var item=btn.closest('.sub-item');",
    "  var tokenInput=item.querySelector('.sub-token-input');",
    "  var newToken=genRandomToken(24);",
    "  tokenInput.value=newToken;",
    "  updateSubUrlFromInput(tokenInput);",
    "  toast('Token 已重新生成 ✓');",
    "}",

    "function copySubUrl(btn){",
    "  var url=btn.closest('.sub-url-box').querySelector('.sub-url').textContent;",
    "  if(!url || url==='（请设置 Token）'){toast('请先设置 Token',true);return;}",
    "  navigator.clipboard.writeText(url).then(function(){toast('已复制 ✓');});",
    "}",

    "function getSubListData(){",
    "  var subItems=document.querySelectorAll('.sub-item');",
    "  var data=[];",
    "  var hasError=false;",
    "  subItems.forEach(function(item){",
    "    var id=item.dataset.id;",
    "    var name=item.querySelector('.sub-name').value.trim();",
    "    var token=item.querySelector('.sub-token-input').value.trim();",
    "    var expiry=item.querySelector('.sub-expiry-input').value.trim();",
    "    var upload=item.querySelector('.sub-traffic-upload').value.trim();",
    "    var download=item.querySelector('.sub-traffic-download').value.trim();",
    "    var total=item.querySelector('.sub-traffic-total').value.trim();",
    "    if(!token){",
    "      toast('订阅 \"'+(name||'未命名')+'\" 缺少 Token',true);",
    "      hasError=true;",
    "      return;",
    "    }",
    "    if(!name){",
    "      toast('订阅缺少名称',true);",
    "      hasError=true;",
    "      return;",
    "    }",
    "    var checkboxes=item.querySelectorAll('.node-select-grid input[type=checkbox]');",
    "    var selectedIndices=[];",
    "    checkboxes.forEach(function(cb){",
    "      if(cb.checked)selectedIndices.push(parseInt(cb.value));",
    "    });",
    "    var traffic={};",
    "    if(upload) traffic.upload=upload;",
    "    if(download) traffic.download=download;",
    "    if(total) traffic.total=total;",
    "    var subData={id:id,name:name,token:token,selectedIndices:selectedIndices};",
    "    if(expiry) subData.expiry=expiry;",
    "    if(Object.keys(traffic).length>0) subData.traffic=traffic;",
    "    data.push(subData);",
    "  });",
    "  if(hasError) return null;",
    "  return data;",
    "}",

    "async function saveSubList(){",
    "  var data=getSubListData();",
    "  if(data===null) return;",
    "  try{",
    "    var r=await fetch('/api/savesublist',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({sublist:data})});",
    "    var d=await r.json();",
    "    if(d.ok){toast('订阅列表已保存 ✓');}else{toast(d.error||'保存失败',true);}",
    "  }catch(e){toast('保存失败',true);}",
    "}",

    "async function loadSubList(){",
    "  try{",
    "    var r=await fetch('/api/getsublist',{credentials:'include'});",
    "    var d=await r.json();",
    "    var container=document.getElementById('sublist-container');",
    "    container.innerHTML='';",
    "    (d.sublist||[]).forEach(function(item){",
    "      addSubItem(item.id, item.name, item.token, item.selectedIndices||[], item.expiry||'', item.traffic||{});",
    "    });",
    "  }catch(e){toast('加载订阅列表失败',true);}",
    "}",

    "async function login(){",
    "  var pw=document.getElementById('pw').value;",
    "  if(!pw){toast('请输入密码',true);return;}",
    "  try{",
    "    var r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});",
    "    var d=await r.json();",
    "    if(d.ok){",
    "      document.getElementById('lbox').style.display='none';",
    "      document.getElementById('main').style.display='block';",
    "      await loadNodes();",
    "      await loadExpiry();",
    "      await loadTraffic();",
    "      await loadSubInfo();",
    "      await loadSubList();",
    "    }else{toast('密码错误',true);document.getElementById('pw').value='';}",
    "  }catch(e){toast('网络错误',true);}",
    "}",

    "async function loadNodes(){",
    "  try{",
    "    var r=await fetch('/api/list',{credentials:'include'});",
    "    var d=await r.json();",
    "    var container=document.getElementById('nodes-container');",
    "    container.innerHTML='';",
    "    (d.nodes||[]).forEach(function(item){",
    "      if(typeof item==='string'){",
    "        addNodeRow(item,'',true);",
    "      }else{",
    "        addNodeRow(item.url||'',item.remark||'',item.enabled);",
    "      }",
    "    });",
    "    stat();",
    "    await loadSubList();",
    "  }catch(e){toast('加载失败',true);}",
    "}",

    "async function saveNodes(){",
    "  var items=document.querySelectorAll('.node-item');",
    "  var nodes=[];",
    "  items.forEach(function(item){",
    "    var url=item.querySelector('.node-url').value.trim();",
    "    var remark=item.querySelector('.node-remark').value.trim();",
    "    var enabled=item.dataset.enabled !== 'false';",
    "    if(url){",
    "      nodes.push({url:url, remark:remark, enabled:enabled});",
    "    }",
    "  });",
    "  try{",
    "    await fetch('/api/save',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({nodes:nodes})});",
    "    toast('保存成功 ✓');stat();",
    "  }catch(e){toast('保存失败',true);}",
    "}",

    "async function loadExpiry(){",
    "  try{var r=await fetch('/api/getexpiry',{credentials:'include'});var d=await r.json();var val=d.expiry||'';document.getElementById('expiry-input').value=val;renderExpiryBar(val);updatePreview();}catch(e){}",
    "}",

    "async function saveExpiry(){",
    "  var val=document.getElementById('expiry-input').value;",
    "  try{var r=await fetch('/api/setexpiry',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({expiry:val})});var d=await r.json();if(d.ok){toast('到期时间已保存 ✓');renderExpiryBar(val);updatePreview();}else toast('保存失败',true);}catch(e){toast('保存失败',true);}",
    "}",

    "function clearExpiry(){document.getElementById('expiry-input').value='';saveExpiry();}",

    "async function loadTraffic(){",
    "  try{var r=await fetch('/api/gettraffic',{credentials:'include'});var d=await r.json();var t=d.traffic||{};document.getElementById('t-up').value=t.upload||'';document.getElementById('t-dl').value=t.download||'';document.getElementById('t-tot').value=t.total||'';updatePreview();}catch(e){}",
    "}",

    "async function saveTraffic(){",
    "  var traffic={upload:document.getElementById('t-up').value,download:document.getElementById('t-dl').value,total:document.getElementById('t-tot').value};",
    "  try{var r=await fetch('/api/settraffic',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({traffic:traffic})});var d=await r.json();if(d.ok)toast('流量信息已保存 ✓');else toast('保存失败',true);}catch(e){toast('保存失败',true);}",
    "}",

    "async function loadSubInfo(){",
    "  try{",
    "    var r=await fetch('/api/getsubinfo',{credentials:'include'});",
    "    var d=await r.json();",
    "    document.getElementById('inp-subname').value=d.subname||'';",
    "    document.getElementById('inp-token').value=d.subtoken||'';",
    "    updateSubUrl();",
    "  }catch(e){}",
    "}",

    "async function saveSubInfo(){",
    "  var subname=document.getElementById('inp-subname').value.trim();",
    "  var subtoken=document.getElementById('inp-token').value.trim();",
    "  try{",
    "    var r=await fetch('/api/setsubinfo',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({subname:subname,subtoken:subtoken})});",
    "    var d=await r.json();",
    "    if(d.ok){toast('订阅设置已保存 ✓');updateSubUrl();}",
    "    else toast('保存失败',true);",
    "  }catch(e){toast('保存失败',true);}",
    "}",

    "function copyUrl(){",
    "  var url=document.getElementById('sub-url-full').value;",
    "  navigator.clipboard.writeText(url).then(function(){toast('已复制 ✓');});",
    "}",

    "function genGlobalToken(){",
    "  document.getElementById('inp-token').value=genRandomToken(24);",
    "  updateSubUrl();",
    "}",

    "document.getElementById('pw').addEventListener('keydown',function(e){if(e.key==='Enter')login();});",
    "document.getElementById('t-up').addEventListener('input',updatePreview);",
    "document.getElementById('t-dl').addEventListener('input',updatePreview);",
    "document.getElementById('t-tot').addEventListener('input',updatePreview);",
    "document.getElementById('expiry-input').addEventListener('input',function(){renderExpiryBar(this.value);updatePreview();});",
    "document.getElementById('inp-token').addEventListener('input',updateSubUrl);",
    "document.getElementById('inp-subname').addEventListener('input',updateSubUrl);",
    "document.getElementById('add-node-btn').addEventListener('click',function(){addNodeRow('','',true);});",
    "document.getElementById('add-sub-btn').addEventListener('click',function(){",
    "  var items=document.querySelectorAll('.node-item');",
    "  var allIndices=[];",
    "  for(var i=0;i<items.length;i++)allIndices.push(i);",
    "  addSubItem(null,'新订阅',null,allIndices,'',{});",
    "});",
    "document.getElementById('gen-global-token').addEventListener('click',genGlobalToken);"
  ].join("\n");

  const parts = [
    "<!DOCTYPE html>",
    "<html lang=\"zh-CN\">",
    "<head>",
    "<meta charset=\"UTF-8\">",
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
    "<title>订阅管理器</title>",
    "<style>", style, "</style>",
    "</head>",
    "<body>",
    "<div class=\"wrap\">",
    "  <div class=\"hd\"><h1>✦ 订阅管理器</h1><p>集中管理多源订阅，一键合并输出</p></div>",

    "  <div id=\"lbox\" class=\"card\">",
    "    <div class=\"label\">身份验证</div>",
    "    <div class=\"row\">",
    "      <input id=\"pw\" type=\"password\" placeholder=\"输入管理密码\">",
    "      <button class=\"btn pa\" onclick=\"login()\">登 录</button>",
    "    </div>",
    "  </div>",

    "  <div id=\"main\" style=\"display:none\">",

    "    <div class=\"card\">",
    "      <div class=\"label\">主订阅 <span style=\"color:var(--mu);font-weight:400;text-transform:none;font-size:.75rem\">（包含所有启用的节点）</span></div>",
    "      <div class=\"subbox\">",
    "        <div id=\"sub-url-display\" class=\"suburl\">" + subUrl + "</div>",
    "        <button class=\"btn pb sm\" onclick=\"copyUrl()\">复制</button>",
    "      </div>",
    "      <input type=\"hidden\" id=\"sub-url-full\" value=\"" + subUrl + "\">",
    "      <div style=\"display:flex;align-items:center;gap:12px;margin-top:8px\">",
    "        <div id=\"token-badge\" class=\"token-badge token-none\">🔓 未设置主订阅 Token，直接访问 /sub 即可</div>",
    "        <span id=\"sub-status\" class=\"status-warn\">公开访问</span>",
    "      </div>",
    "    </div>",

    "    <div class=\"card\">",
    "      <div class=\"label\">自定义订阅列表 <span style=\"color:var(--mu);font-weight:400;text-transform:none;font-size:.75rem\">（每个订阅通过不同的 Token 访问，可单独设置过期时间和流量）</span></div>",
    "      <div id=\"sublist-container\" class=\"sublist-container\">",
    "      </div>",
    "      <div id=\"add-sub-btn\" class=\"add-sub-btn\">＋ 添加自定义订阅</div>",
    "      <div class=\"foot\" style=\"margin-top:12px\">",
    "        <div></div>",
    "        <button class=\"btn pa\" onclick=\"saveSubList()\">保存订阅列表</button>",
    "      </div>",
    "    </div>",

    "    <div class=\"card\">",
    "      <div class=\"label\">全局设置</div>",
    "      <div class=\"grid2\">",
    "        <div class=\"field\">",
    "          <label>订阅备注名（Shadowrocket 显示的名称）</label>",
    "          <input id=\"inp-subname\" type=\"text\" placeholder=\"例如：我的机场\">",
    "        </div>",
    "        <div class=\"field\">",
    "          <label>主订阅 Token <span class=\"warning-text\">（留空则公开访问 /sub）</span></label>",
    "          <div class=\"row\">",
    "            <input id=\"inp-token\" type=\"text\" placeholder=\"留空表示公开访问\">",
    "            <button class=\"btn pc sm\" id=\"gen-global-token\">随机</button>",
    "          </div>",
    "        </div>",
    "      </div>",
    "      <div class=\"row\" style=\"justify-content:flex-end\">",
    "        <button class=\"btn pa sm\" onclick=\"saveSubInfo()\">保存设置</button>",
    "      </div>",
    "    </div>",

    "    <div class=\"card\">",
    "      <div class=\"label\">全局订阅信息（Shadowrocket 显示内容）<span class=\"info-text\">（自定义订阅可单独设置，会覆盖全局设置）</span></div>",
    "      <div class=\"field\" style=\"margin-bottom:12px\">",
    "        <label>到期时间</label>",
    "        <div class=\"row\">",
    "          <input id=\"expiry-input\" type=\"date\">",
    "          <button class=\"btn pa sm\" onclick=\"saveExpiry()\">保存</button>",
    "          <button class=\"btn pc sm\" onclick=\"clearExpiry()\">清除</button>",
    "        </div>",
    "        <div id=\"expiry-bar\" class=\"expiry-bar expiry-none\">📅 未设置到期时间</div>",
    "      </div>",
    "      <div class=\"label\" style=\"margin-top:4px\">流量信息（支持 G / T / M，例如 53G、1.5T）</div>",
    "      <div class=\"grid3\">",
    "        <div class=\"field\"><label>已上传</label><input id=\"t-up\" type=\"text\" placeholder=\"例如 53G\"></div>",
    "        <div class=\"field\"><label>已下载</label><input id=\"t-dl\" type=\"text\" placeholder=\"例如 93G\"></div>",
    "        <div class=\"field\"><label>总流量</label><input id=\"t-tot\" type=\"text\" placeholder=\"例如 5T\"></div>",
    "      </div>",
    "      <div class=\"row\" style=\"justify-content:flex-end\">",
    "        <button class=\"btn pa sm\" onclick=\"saveTraffic()\">保存流量</button>",
    "      </div>",
    "      <div id=\"header-preview\" class=\"preview\">（未填写任何字段，不输出 header）</div>",
    "    </div>",

    "    <div class=\"card\">",
    "      <div class=\"label\">节点 / 订阅链接 <span style=\"color:var(--mu);font-weight:400;text-transform:none;font-size:.75rem\">（开关控制是否在订阅中生成）</span></div>",
    "      <div id=\"nodes-container\" class=\"nodes-container\">",
    "      </div>",
    "      <div id=\"add-node-btn\" class=\"add-node-btn\">＋ 添加节点或订阅链接</div>",
    "      <div class=\"foot\">",
    "        <div class=\"stats\">",
    "          <span class=\"stat\">共 <b id=\"s1\">0</b> 行</span>",
    "          <span class=\"stat\">订阅 <b id=\"s2\">0</b></span>",
    "          <span class=\"stat\">节点 <b id=\"s3\">0</b></span>",
    "          <span class=\"stat\">启用 <b class=\"enabled-count\" id=\"s4\">0</b></span>",
    "          <span class=\"stat\">禁用 <b class=\"disabled-count\" id=\"s5\">0</b></span>",
    "        </div>",
    "        <div class=\"row\">",
    "          <button class=\"btn pc sm\" onclick=\"loadNodes()\">↺ 刷新</button>",
    "          <button class=\"btn pa\" onclick=\"saveNodes()\">保存</button>",
    "        </div>",
    "      </div>",
    "    </div>",

    "    <div class=\"tip\"><strong>访问规则：</strong><br>",
    "    • <strong>未设置主 Token</strong>：访问 <code>/sub</code> 返回所有启用节点（公开）<br>",
    "    • <strong>已设置主 Token</strong>：访问 <code>/sub</code> 会提示 <code>Missing token parameter</code>，必须使用 <code>/sub?token=主Token</code><br>",
    "    • <strong>自定义订阅</strong>：始终需要 Token 访问，格式为 <code>/sub?token=自定义Token</code><br>",
    "    • <strong>到期时间</strong>：自定义订阅可单独设置到期时间，过期后访问返回 <code>Subscription expired</code><br>",
    "    • <strong>流量信息</strong>：自定义订阅可单独设置流量（上传/下载/总量），在 <code>Subscription-Userinfo</code> 头中显示</div>",
    "  </div>",
    "</div>",
    "<div id=\"toast\"></div>",
    "<script>", script, "<\/script>",
    "</body></html>"
  ];

  return new Response(parts.join("\n"), {
    headers: { "Content-Type": "text/html;charset=utf-8" }
  });
}
