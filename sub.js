const KV_KEY = "nodes";
const KV_EXPIRY = "expiry";
const KV_TRAFFIC = "traffic";
const KV_SUBNAME = "subname";
const KV_SUBTOKEN = "subtoken";

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
  const nodes = (body.nodes || []).map(s => s.trim()).filter(Boolean);
  await env.KV.put(KV_KEY, JSON.stringify(nodes));
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

// 新增：获取订阅备注名 + token
async function handleGetSubInfo(request, env) {
  if (!authed(request)) return err("unauthorized", 401);
  const subname = await env.KV.get(KV_SUBNAME) || "";
  const subtoken = await env.KV.get(KV_SUBTOKEN) || "";
  return ok({ subname, subtoken });
}

// 新增：保存订阅备注名 + token
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

// 把 "53G" / "1.5T" / "512M" 这类字符串转成字节数
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
  // Token 校验
  const storedToken = await env.KV.get(KV_SUBTOKEN) || "";
  if (storedToken) {
    const reqToken = url.searchParams.get("token") || "";
    if (reqToken !== storedToken) {
      return new Response("Forbidden", { status: 403 });
    }
  }

  let raw = [];
  try { raw = JSON.parse(await env.KV.get(KV_KEY) || "[]"); } catch {}

  const out = [];
  await Promise.all(raw.map(async line => {
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

  const encoded = btoa(unescape(encodeURIComponent(out.join("\n"))));

  const expiryStr = await env.KV.get(KV_EXPIRY) || "";
  let trafficObj = { upload: "", download: "", total: "" };
  try { trafficObj = JSON.parse(await env.KV.get(KV_TRAFFIC) || "{}"); } catch {}

  // 订阅备注名
  const subname = await env.KV.get(KV_SUBNAME) || "";
  const filename = subname ? encodeURIComponent(subname) + ".txt" : "sub.txt";

  const parts = [];
  if (trafficObj.upload)   parts.push("upload="   + parseBytes(trafficObj.upload));
  if (trafficObj.download) parts.push("download=" + parseBytes(trafficObj.download));
  if (trafficObj.total)    parts.push("total="    + parseBytes(trafficObj.total));
  if (expiryStr)           parts.push("expire="   + Math.floor(new Date(expiryStr).getTime() / 1000));

  const headers = {
    "Content-Type": "text/plain; charset=utf-8",
    "Profile-Update-Interval": "24",
    "Content-Disposition": "attachment; filename*=UTF-8''" + filename
  };
  if (parts.length > 0) {
    headers["Subscription-Userinfo"] = parts.join("; ");
  }

  return new Response(encoded, { headers });
}

function handleAdmin(origin) {
  const subUrl = origin + "/sub";

  const style = [
    "*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}",
    ":root{--bg:#0d0e14;--sur:#13151e;--bor:#1f2130;--a:#7c6ef5;--b:#5de7b4;--tx:#dde1f0;--mu:#6b7097;--red:#f56e6e;--warn:#f5a623;--r:12px}",
    "body{background:var(--bg);color:var(--tx);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}",
    ".wrap{width:100%;max-width:740px}",
    ".hd{text-align:center;margin-bottom:32px}",
    ".hd h1{font-size:1.7rem;font-weight:700;background:linear-gradient(135deg,var(--a),var(--b));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}",
    ".hd p{color:var(--mu);margin-top:6px;font-size:.9rem}",
    ".card{background:var(--sur);border:1px solid var(--bor);border-radius:var(--r);padding:24px;margin-bottom:16px}",
    ".label{font-size:.75rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--mu);margin-bottom:14px}",
    ".row{display:flex;gap:10px;align-items:center}",
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
    "textarea{width:100%;background:var(--bg);border:1px solid var(--bor);border-radius:8px;color:var(--tx);padding:12px 14px;font-family:monospace;font-size:.85rem;line-height:1.6;height:300px;resize:vertical;outline:none;transition:border-color .2s}",
    "textarea:focus{border-color:var(--a)}",
    ".foot{display:flex;align-items:center;justify-content:space-between;margin-top:12px;gap:10px;flex-wrap:wrap}",
    ".stats{display:flex;gap:16px}",
    ".stat{font-size:.82rem;color:var(--mu)}",
    ".stat b{color:var(--tx);font-weight:600}",
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
    "  var v=document.getElementById('ta').value;",
    "  var ls=v.split('\\n').map(function(x){return x.trim();}).filter(Boolean);",
    "  var u=ls.filter(function(x){return x.indexOf('http')=== 0;});",
    "  document.getElementById('s1').textContent=ls.length;",
    "  document.getElementById('s2').textContent=u.length;",
    "  document.getElementById('s3').textContent=ls.length-u.length;",
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

    // 更新订阅地址显示（含 token）
    "function updateSubUrl(){",
    "  var tok=document.getElementById('inp-token').value.trim();",
    "  var base='" + subUrl + "';",
    "  var full=tok?base+'?token='+encodeURIComponent(tok):base;",
    "  document.getElementById('sub-url-display').textContent=full;",
    "  document.getElementById('sub-url-full').value=full;",
    "  var badge=document.getElementById('token-badge');",
    "  if(tok){badge.className='token-badge';badge.textContent='🔒 已启用 Token 保护';}",
    "  else{badge.className='token-badge token-none';badge.textContent='🔓 未启用 Token（订阅链接公开可访问）';}",
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
    "      loadNodes();loadExpiry();loadTraffic();loadSubInfo();",
    "    }else{toast('密码错误',true);document.getElementById('pw').value='';}",
    "  }catch(e){toast('网络错误',true);}",
    "}",

    "async function loadNodes(){",
    "  try{var r=await fetch('/api/list',{credentials:'include'});var d=await r.json();document.getElementById('ta').value=d.nodes.join('\\n');stat();}catch(e){toast('加载失败',true);}",
    "}",

    "async function saveNodes(){",
    "  var nodes=document.getElementById('ta').value.split('\\n').map(function(x){return x.trim();}).filter(Boolean);",
    "  try{await fetch('/api/save',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({nodes:nodes})});toast('保存成功 ✓');stat();}catch(e){toast('保存失败',true);}",
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

    // 新增：加载订阅备注名 + token
    "async function loadSubInfo(){",
    "  try{",
    "    var r=await fetch('/api/getsubinfo',{credentials:'include'});",
    "    var d=await r.json();",
    "    document.getElementById('inp-subname').value=d.subname||'';",
    "    document.getElementById('inp-token').value=d.subtoken||'';",
    "    updateSubUrl();",
    "  }catch(e){}",
    "}",

    // 新增：保存订阅备注名 + token
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

    "function genToken(){",
    "  var chars='ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';",
    "  var t='';for(var i=0;i<24;i++)t+=chars[Math.floor(Math.random()*chars.length)];",
    "  document.getElementById('inp-token').value=t;",
    "  updateSubUrl();",
    "}",

    "document.getElementById('pw').addEventListener('keydown',function(e){if(e.key==='Enter')login();});",
    "document.getElementById('ta').addEventListener('input',stat);",
    "document.getElementById('t-up').addEventListener('input',updatePreview);",
    "document.getElementById('t-dl').addEventListener('input',updatePreview);",
    "document.getElementById('t-tot').addEventListener('input',updatePreview);",
    "document.getElementById('expiry-input').addEventListener('input',function(){renderExpiryBar(this.value);updatePreview();});",
    "document.getElementById('inp-token').addEventListener('input',updateSubUrl);",
    "document.getElementById('inp-subname').addEventListener('input',updateSubUrl);"
  ].join("\n");

  const parts = [
    "<!DOCTYPE html>",
    "<html lang=\"zh-CN\">",
    "<head>",
    "<meta charset=\"UTF-8\">",
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
    "<title>订阅管理</title>",
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

    // 订阅地址卡片（动态显示完整 URL）
    "    <div class=\"card\">",
    "      <div class=\"label\">订阅地址</div>",
    "      <div class=\"subbox\">",
    "        <div id=\"sub-url-display\" class=\"suburl\">" + subUrl + "</div>",
    "        <button class=\"btn pb sm\" onclick=\"copyUrl()\">复制</button>",
    "      </div>",
    "      <input type=\"hidden\" id=\"sub-url-full\" value=\"" + subUrl + "\">",
    "      <div id=\"token-badge\" class=\"token-badge token-none\">🔓 未启用 Token（订阅链接公开可访问）</div>",
    "    </div>",

    // 新增：订阅备注名 + Token 卡片
    "    <div class=\"card\">",
    "      <div class=\"label\">订阅设置</div>",
    "      <div class=\"grid2\">",
    "        <div class=\"field\">",
    "          <label>订阅备注名（Shadowrocket 显示的名称）</label>",
    "          <input id=\"inp-subname\" type=\"text\" placeholder=\"例如：我的机场\">",
    "        </div>",
    "        <div class=\"field\">",
    "          <label>访问 Token（留空则不启用保护）</label>",
    "          <div class=\"row\">",
    "            <input id=\"inp-token\" type=\"text\" placeholder=\"留空表示公开访问\">",
    "            <button class=\"btn pc sm\" onclick=\"genToken()\">随机</button>",
    "          </div>",
    "        </div>",
    "      </div>",
    "      <div class=\"row\" style=\"justify-content:flex-end\">",
    "        <button class=\"btn pa sm\" onclick=\"saveSubInfo()\">保存设置</button>",
    "      </div>",
    "    </div>",

    // 到期时间 + 流量卡片
    "    <div class=\"card\">",
    "      <div class=\"label\">订阅信息（Shadowrocket 显示内容）</div>",
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

    // 节点卡片
    "    <div class=\"card\">",
    "      <div class=\"label\">节点 / 订阅链接</div>",
    "      <textarea id=\"ta\" placeholder=\"每行一条&#10;订阅链接 (http/https) → 自动拉取展开&#10;vmess:// vless:// trojan:// ss:// → 直接透传\"></textarea>",
    "      <div class=\"foot\">",
    "        <div class=\"stats\">",
    "          <span class=\"stat\">共 <b id=\"s1\">0</b> 行</span>",
    "          <span class=\"stat\">订阅 <b id=\"s2\">0</b></span>",
    "          <span class=\"stat\">节点 <b id=\"s3\">0</b></span>",
    "        </div>",
    "        <div class=\"row\">",
    "          <button class=\"btn pc sm\" onclick=\"loadNodes()\">↺ 刷新</button>",
    "          <button class=\"btn pa\" onclick=\"saveNodes()\">保存</button>",
    "        </div>",
    "      </div>",
    "    </div>",

    "    <div class=\"tip\"><strong>说明：</strong>每行一条。http/https 开头的订阅链接会在输出时自动拉取并展开节点；vmess/vless/trojan/ss 等协议链接直接透传；两种可混合使用。</div>",
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
