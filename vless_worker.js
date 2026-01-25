// ============================================
// 主要功能:
// VLESS Cloudflare Workers 代理脚本
// 替换 let proxyIP = '路径内容' 可修改 proxyIP
// 替换 let yourUUID = '路径内容' 可修改 UUID
// 订阅方式:你的访问地址 /UUID 进入订阅中心
// ============================================

import { connect } from 'cloudflare:sockets';

// ============ 配置区域 ============
let subPath = 'sub';
let proxyIP = 'proxy.xxxxxxxx.tk:50001';
let yourUUID = '757e052c-4159-491d-bc5d-1b6bd866d980';

let cfip = [
    'proxyip.us.cmliussss.net:443#US',
	'proxyip.jp.cmliussss.net:443#JP'
];

// ============ 核心工具函数 ============
const closeSocketQuietly = (socket) => {
    try {
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close();
        }
    } catch {}
};

const formatUUID = (arr, offset = 0) => {
    const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
};

const base64ToArray = (str) => {
    if (!str) return { earlyData: null, error: null };
    try {
        const binary = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return { earlyData: bytes.buffer, error: null };
    } catch (error) {
        return { earlyData: null, error };
    }
};

// ============ 代理地址解析 ============
const parseProxy = (str) => {
    if (!str) return null;
    str = str.trim();

    // SOCKS5
    if (str.startsWith('socks://') || str.startsWith('socks5://')) {
        try {
            const url = new URL(str.replace(/^socks:\/\//, 'socks5://'));
            return {
                type: 'socks5',
                host: url.hostname,
                port: parseInt(url.port) || 1080,
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch { return null; }
    }

    // HTTP/HTTPS
    if (str.startsWith('http://') || str.startsWith('https://')) {
        try {
            const url = new URL(str);
            return {
                type: 'http',
                host: url.hostname,
                port: parseInt(url.port) || (str.startsWith('https://') ? 443 : 80),
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch { return null; }
    }

    // IPv6 [host]:port
    if (str.startsWith('[')) {
        const idx = str.indexOf(']:');
        if (idx > 0) {
            const host = str.slice(1, idx);
            const port = parseInt(str.slice(idx + 2)) || 443;
            return { type: 'direct', host, port };
        }
        return { type: 'direct', host: str.slice(1, str.indexOf(']')), port: 443 };
    }

    // host:port
    const idx = str.lastIndexOf(':');
    if (idx > 0) {
        const port = parseInt(str.slice(idx + 1));
        if (port > 0 && port <= 65535) {
            return { type: 'direct', host: str.slice(0, idx), port };
        }
    }

    return { type: 'direct', host: str, port: 443 };
};

// ============ 速度测试网站检测 ============
const speedTestDomains = new Set(['speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com']);
const isSpeedTest = (host) => {
    if (speedTestDomains.has(host)) return true;
    for (const d of speedTestDomains) {
        if (host.endsWith('.' + d)) return true;
    }
    return false;
};

// ============ VLESS 协议处理 ============
async function handleVLESS(request, customProxy) {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();

    let remoteSocket = null;
    let isDNS = false;
    const earlyData = request.headers.get('sec-websocket-protocol') || '';

    makeReadable(server, earlyData).pipeTo(new WritableStream({
        async write(chunk) {
            if (isDNS) return forwardDNS(chunk, server, null);
            
            if (remoteSocket) {
                const w = remoteSocket.writable.getWriter();
                await w.write(chunk);
                w.releaseLock();
                return;
            }

            const parsed = parseVLESS(chunk, yourUUID);
            if (parsed.error) throw new Error(parsed.error);

            if (isSpeedTest(parsed.hostname)) {
                throw new Error('Speedtest blocked');
            }

            if (parsed.isUDP) {
                if (parsed.port === 53) isDNS = true;
                else throw new Error('Only DNS UDP supported');
            }

            const header = new Uint8Array([parsed.version[0], 0]);
            const payload = chunk.slice(parsed.dataIndex);

            if (isDNS) return forwardDNS(payload, server, header);

            remoteSocket = await connectRemote(
                parsed.hostname,
                parsed.port,
                payload,
                server,
                header,
                customProxy
            );
        }
    })).catch(err => console.error('Pipe error:', err.message));

    return new Response(null, { status: 101, webSocket: client });
}

// ============ VLESS 包头解析 ============
function parseVLESS(chunk, uuid) {
    if (chunk.byteLength < 24) return { error: 'Invalid length' };

    const view = new DataView(chunk);
    const version = new Uint8Array(chunk.slice(0, 1));

    if (formatUUID(new Uint8Array(chunk.slice(1, 17))) !== uuid) {
        return { error: 'Invalid UUID' };
    }

    const optLen = view.getUint8(17);
    const cmd = view.getUint8(18 + optLen);
    const isUDP = cmd === 2;
    
    if (cmd !== 1 && cmd !== 2) return { error: 'Invalid command' };

    let pos = 19 + optLen;
    const port = view.getUint16(pos);
    const addrType = view.getUint8(pos + 2);
    pos += 3;

    let hostname = '';
    switch (addrType) {
        case 1: // IPv4
            hostname = `${view.getUint8(pos)}.${view.getUint8(pos+1)}.${view.getUint8(pos+2)}.${view.getUint8(pos+3)}`;
            pos += 4;
            break;
        case 2: // Domain
            const len = view.getUint8(pos++);
            hostname = new TextDecoder().decode(chunk.slice(pos, pos + len));
            pos += len;
            break;
        case 3: // IPv6
            const parts = [];
            for (let i = 0; i < 8; i++, pos += 2) {
                parts.push(view.getUint16(pos).toString(16));
            }
            hostname = parts.join(':');
            break;
        default:
            return { error: 'Invalid address type' };
    }

    return { error: null, hostname, port, isUDP, version, dataIndex: pos };
}

// ============ 远程连接 ============
async function connectRemote(host, port, data, ws, header, customProxy) {
    const directConnect = async () => {
        const sock = connect({ hostname: host, port });
        const w = sock.writable.getWriter();
        await w.write(data);
        w.releaseLock();
        return sock;
    };

    let proxy = parseProxy(customProxy || proxyIP);
    if (!proxy) proxy = { type: 'direct', host: proxyIP, port: 443 };

    const useProxy = ['socks5', 'http', 'https'].includes(proxy.type);

    const viaProxy = async () => {
        let sock;
        if (proxy.type === 'socks5') {
            sock = await connectSOCKS5(proxy, host, port, data);
        } else if (proxy.type === 'http' || proxy.type === 'https') {
            sock = await connectHTTP(proxy, host, port, data);
        } else {
            sock = await directConnect();
        }
        
        sock.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
        pipeStreams(sock, ws, header);
        return sock;
    };

    if (useProxy) {
        return await viaProxy();
    } else {
        try {
            const sock = await directConnect();
            pipeStreams(sock, ws, header);
            return sock;
        } catch (err) {
            console.error('Direct failed, trying proxy:', err.message);
            return await viaProxy();
        }
    }
}

// ============ SOCKS5 连接 ============
async function connectSOCKS5(cfg, host, port, data) {
    const sock = connect({ hostname: cfg.host, port: cfg.port });
    const w = sock.writable.getWriter();
    const r = sock.readable.getReader();

    try {
        await w.write(cfg.username ? new Uint8Array([5, 2, 0, 2]) : new Uint8Array([5, 1, 0]));
        const auth = await r.read();
        const method = new Uint8Array(auth.value)[1];

        if (method === 2) {
            const user = new TextEncoder().encode(cfg.username);
            const pass = new TextEncoder().encode(cfg.password);
            const packet = new Uint8Array([1, user.length, ...user, pass.length, ...pass]);
            await w.write(packet);
            await r.read();
        }

        const hostBytes = new TextEncoder().encode(host);
        const req = new Uint8Array([5, 1, 0, 3, hostBytes.length, ...hostBytes, port >> 8, port & 0xff]);
        await w.write(req);
        await r.read();
        await w.write(data);

        w.releaseLock();
        r.releaseLock();
        return sock;
    } catch (err) {
        w.releaseLock();
        r.releaseLock();
        throw err;
    }
}

// ============ HTTP 代理连接 ============
async function connectHTTP(cfg, host, port, data) {
    const sock = connect({ hostname: cfg.host, port: cfg.port });
    const w = sock.writable.getWriter();
    const r = sock.readable.getReader();

    try {
        let req = `CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n`;
        if (cfg.username && cfg.password) {
            req += `Proxy-Authorization: Basic ${btoa(cfg.username + ':' + cfg.password)}\r\n`;
        }
        req += '\r\n';

        await w.write(new TextEncoder().encode(req));

        let buf = new Uint8Array(0);
        while (true) {
            const { value, done } = await r.read();
            if (done) throw new Error('Connection closed');
            
            const newBuf = new Uint8Array(buf.length + value.length);
            newBuf.set(buf);
            newBuf.set(value, buf.length);
            buf = newBuf;

            const str = new TextDecoder().decode(buf);
            if (str.includes('\r\n\r\n')) {
                const match = str.match(/HTTP\/\d\.\d\s+(\d+)/);
                if (!match || parseInt(match[1]) >= 300) {
                    throw new Error('Proxy failed');
                }
                break;
            }
            if (buf.length > 8192) throw new Error('Invalid response');
        }

        await w.write(data);
        w.releaseLock();
        r.releaseLock();
        return sock;
    } catch (err) {
        try { w.releaseLock(); } catch {}
        try { r.releaseLock(); } catch {}
        throw err;
    }
}

// ============ 流管道 ============
function makeReadable(ws, early) {
    let cancelled = false;
    return new ReadableStream({
        start(ctrl) {
            ws.addEventListener('message', e => !cancelled && ctrl.enqueue(e.data));
            ws.addEventListener('close', () => !cancelled && (closeSocketQuietly(ws), ctrl.close()));
            ws.addEventListener('error', e => ctrl.error(e));

            const { earlyData, error } = base64ToArray(early);
            if (error) ctrl.error(error);
            else if (earlyData) ctrl.enqueue(earlyData);
        },
        cancel() {
            cancelled = true;
            closeSocketQuietly(ws);
        }
    });
}

function pipeStreams(remote, ws, header) {
    let hasHeader = !!header;
    remote.readable.pipeTo(new WritableStream({
        write(chunk) {
            if (ws.readyState !== WebSocket.OPEN) return;
            if (hasHeader) {
                const res = new Uint8Array(header.length + chunk.byteLength);
                res.set(header);
                res.set(chunk, header.length);
                ws.send(res.buffer);
                hasHeader = false;
            } else {
                ws.send(chunk);
            }
        }
    })).catch(() => closeSocketQuietly(ws));
}

// ============ DNS 转发 ============
async function forwardDNS(data, ws, header) {
    try {
        const sock = connect({ hostname: '8.8.4.4', port: 53 });
        const w = sock.writable.getWriter();
        await w.write(data);
        w.releaseLock();
        
        let hasHeader = !!header;
        await sock.readable.pipeTo(new WritableStream({
            write(chunk) {
                if (ws.readyState === WebSocket.OPEN) {
                    if (hasHeader) {
                        const res = new Uint8Array(header.length + chunk.byteLength);
                        res.set(header);
                        res.set(chunk, header.length);
                        ws.send(res.buffer);
                        hasHeader = false;
                    } else {
                        ws.send(chunk);
                    }
                }
            }
        }));
    } catch (err) {
        console.error('DNS error:', err.message);
    }
}

// ============ 页面生成 ============
const simplePage = (host) => new Response(
    `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VLESS</title><style>*{margin:0;padding:0}body{font-family:system-ui;background:linear-gradient(135deg,#667eea,#764ba2);height:100vh;display:flex;align-items:center;justify-content:center}.box{background:#fff;border-radius:20px;padding:40px;box-shadow:0 20px 40px rgba(0,0,0,.2);text-align:center;max-width:500px}.title{font-size:2rem;margin:20px 0;color:#333}.info{color:#666;font-size:1.1rem}.hl{color:#667eea;font-weight:700;background:#f0f0f0;padding:4px 8px;border-radius:4px}.uuid{font-family:monospace;background:#f8f9fa;padding:4px 8px;border-radius:4px;font-size:0.9rem}</style></head><body><div class="box"><h1 class="title">🚀 VLESS Service</h1><p class="info">你的访问地址 <span class="hl">/UUID</span> 进入订阅中心</p></div></body></html>`,
    { headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-cache' } }
);

const homePage = (host, base) => new Response(
    `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VLESS Manager</title><style>*{margin:0;padding:0}body{font-family:system-ui;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;padding:20px;display:flex;align-items:center;justify-content:center}.box{background:#fff;border-radius:20px;padding:30px;max-width:800px;width:100%;box-shadow:0 20px 60px rgba(0,0,0,.3)}.title{font-size:1.8rem;color:#333;margin-bottom:20px;text-align:center}.card{background:#f7f9fc;border-radius:12px;padding:20px;margin:20px 0;border-left:4px solid #667eea}.row{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #e0e0e0;gap:10px}.row:last-child{border:0}.label{font-weight:600;color:#555;flex-shrink:0}.val{color:#333;font-family:monospace;background:#e8eaf0;padding:4px 8px;border-radius:4px;font-size:.85rem;word-break:break-all;flex:1;text-align:right}.uuid{color:#667eea;font-weight:600;font-size:0.95rem}.btns{display:flex;gap:10px;flex-wrap:wrap}.btn{flex:1;min-width:150px;padding:12px;border:0;border-radius:8px;background:linear-gradient(45deg,#667eea,#764ba2);color:#fff;font-weight:600;cursor:pointer;transition:.3s}.btn:hover{transform:translateY(-2px);box-shadow:0 10px 20px rgba(0,0,0,.2)}.toast{position:fixed;top:20px;right:20px;background:#fff;border-left:4px solid #48bb78;border-radius:8px;padding:12px 16px;box-shadow:0 4px 12px rgba(0,0,0,.2);display:none;z-index:999}.toast.show{display:block;animation:slide .3s}@keyframes slide{from{transform:translateX(100%)}to{transform:translateX(0)}}@media(max-width:768px){.row{flex-direction:column;gap:5px}.val{text-align:left}.btns{flex-direction:column}.btn{width:100%}}</style></head><body><div class="box"><h1 class="title">🚀 VLESS 管理面板</h1><div class="card"><div class="row"><span class="label">主机:</span><span class="val">${host}</span></div><div class="row"><span class="label">UUID:</span><span class="val"><span class="uuid">${yourUUID}</span></span></div><div class="row"><span class="label">V2rayN:</span><span class="val">${base}/${subPath}</span></div><div class="row"><span class="label">Clash:</span><span class="val">https://sublink.eooce.com/clash?config=${base}/${subPath}</span></div><div class="row"><span class="label">Singbox:</span><span class="val">https://sublink.eooce.com/singbox?config=${base}/${subPath}</span></div></div><div class="btns"><button onclick="cp('${base}/${subPath}','V2rayN')" class="btn">复制 V2rayN</button><button onclick="cp('https://sublink.eooce.com/clash?config=${base}/${subPath}','Clash')" class="btn">复制 Clash</button><button onclick="cp('https://sublink.eooce.com/singbox?config=${base}/${subPath}','Singbox')" class="btn">复制 Singbox</button></div></div><div class="toast" id="t"></div><script>function cp(s,n){navigator.clipboard.writeText(s).then(()=>{let e=document.getElementById('t');e.textContent='✓ '+n+' 已复制';e.classList.add('show');setTimeout(()=>e.classList.remove('show'),2000)}).catch(()=>{let e=document.createElement('textarea');e.value=s;document.body.appendChild(e);e.select();document.execCommand('copy');document.body.removeChild(e)})}</script></body></html>`,
    { headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-cache' } }
);

// ============ 主处理函数 ============
export default {
    async fetch(request, env) {
        try {
            if (env.PROXYIP || env.proxyip || env.proxyIP) {
                proxyIP = (env.PROXYIP || env.proxyip || env.proxyIP).split(',')[0].trim();
            }
            subPath = env.SUB_PATH || env.subpath || subPath;
            yourUUID = env.UUID || env.uuid || yourUUID;

            subPath = env.SUB_PATH || 'sub';

            const url = new URL(request.url);
            const path = url.pathname;
            const host = url.hostname;

            // ProxyIP 设置
            if (path.startsWith('/proxyip=')) {
                const ip = decodeURIComponent(path.slice(9)).trim();
                if (ip && !request.headers.get('Upgrade')) {
                    proxyIP = ip;
                    return new Response(`ProxyIP set to: ${ip}\n`, {
                        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
                    });
                }
            }

            // WebSocket 升级
            if (request.headers.get('Upgrade') === 'websocket') {
                const customProxy = path.startsWith('/proxyip=')
                    ? decodeURIComponent(path.slice(9)).trim()
                    : url.searchParams.get('proxyip') || request.headers.get('proxyip');
                
                return await handleVLESS(request, customProxy);
            }

            // HTTP 请求
            if (request.method === 'GET') {
                if (path === '/') return simplePage(host);
                
                // 通过 /UUID 进入订阅中心（实际还是用真实的UUID）
                if (path.toLowerCase() === `/${yourUUID.toLowerCase()}`) {
                    return homePage(host, `https://${host}`);
                }

                // 订阅
                if (path.toLowerCase().includes(`/${subPath.toLowerCase()}`)) {
                    const links = cfip.map(item => {
                        const [addr, name] = item.includes('#') ? item.split('#') : [item, 'CF'];
                        let h, p = 443;
                        
                        if (addr.startsWith('[') && addr.includes(']:')) {
                            const i = addr.indexOf(']:');
                            h = addr.slice(0, i + 1);
                            p = parseInt(addr.slice(i + 2)) || 443;
                        } else if (addr.includes(':')) {
                            [h, p] = addr.split(':');
                            p = parseInt(p) || 443;
                        } else {
                            h = addr;
                        }

                        return `vless://${yourUUID}@${h}:${p}?encryption=none&security=tls&sni=${host}&fp=firefox&type=ws&host=${host}&path=%2F%3Fed%3D2560#${name}`;
                    });

                    return new Response(btoa(unescape(encodeURIComponent(links.join('\n')))), {
                        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
                    });
                }
            }

            return new Response('Not Found', { status: 404 });
        } catch (err) {
            console.error('Error:', err);
            return new Response('Internal Error', { status: 500 });
        }
    }
};
