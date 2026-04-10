import { connect } from 'cloudflare:sockets';
const FIXED_UUID = '757e052c-4159-491d-bc5d-1b6bd866d980';
const IP_SOURCE = 'https://raw.githubusercontent.com/hanhande221/node-Cloudflare/main/ip.txt';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase();
    const contentType = (request.headers.get('content-type') || '').toLowerCase();
    const pathname = url.pathname;

    // ★ 从查询参数中提取 proxyip
    const proxyIP = url.searchParams.get('proxyip') || null;

    if (pathname === '/sub') {
      return await handleSub(url, env);
    }
    if (upgradeHeader === 'websocket') {
      return await handleWS(request, FIXED_UUID, url, proxyIP);
    }
    if (request.method === 'POST') {
      const referer = request.headers.get('Referer') || '';
      if (!referer.includes('x_padding') && contentType.startsWith('application/grpc')) {
        return await handleGRPC(request, FIXED_UUID, proxyIP);
      }
      return await handleXHTTP(request, FIXED_UUID, proxyIP);
    }
    return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8' } });
  }
};

// ==================== 订阅处理 ====================
async function handleSub(url, env) {
  const host = url.hostname;
  let ipList = [];
  try {
    const res = await fetch(IP_SOURCE);
    const text = await res.text();
    ipList = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  } catch (e) {
    ipList = ['104.16.0.0:443#CF优选'];
  }
  const nodes = ipList.map(line => {
    const hashIdx = line.indexOf('#');
    const addr = hashIdx > -1 ? line.slice(0, hashIdx) : line;
    const remark = hashIdx > -1 ? line.slice(hashIdx + 1) : addr;
    const [nodeAddr, nodePort = '443'] = splitAddrPort(addr);
    const path = `/?proxyip=${nodeAddr}`;
    return `vless://${FIXED_UUID}@${nodeAddr}:${nodePort}?security=tls&type=ws&host=${host}&path=${encodeURIComponent(path)}&sni=${host}&fp=chrome&encryption=none#${encodeURIComponent(remark)}`;
  });
  const content = btoa(nodes.join('\n'));
  return new Response(content, {
    headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

function splitAddrPort(addr) {
  if (addr.startsWith('[')) {
    const idx = addr.indexOf(']:');
    if (idx > -1) return [addr.slice(0, idx + 1), addr.slice(idx + 2)];
    return [addr, '443'];
  }
  const idx = addr.lastIndexOf(':');
  if (idx > -1 && /^\d+$/.test(addr.slice(idx + 1))) return [addr.slice(0, idx), addr.slice(idx + 1)];
  return [addr, '443'];
}

// ==================== XHTTP ====================
async function handleXHTTP(request, uuid, proxyIP) {  // ★ 接收 proxyIP
  if (!request.body) return new Response('Bad Request', { status: 400 });
  const reader = request.body.getReader();
  const first = await parseXHTTPFirstPacket(reader, uuid);
  if (!first) return new Response('Invalid request', { status: 400 });
  if (isBlocked(first.hostname)) return new Response('Forbidden', { status: 403 });
  if (first.isUDP && first.port !== 53) return new Response('UDP not supported', { status: 400 });
  const conn = { socket: null, connectingPromise: null, retryConnect: null };
  let curSocket = null, curWriter = null;
  const releaseWriter = () => {
    if (curWriter) { try { curWriter.releaseLock() } catch (e) { } curWriter = null; }
    curSocket = null;
  };
  const getWriter = () => {
    const s = conn.socket;
    if (!s) return null;
    if (s !== curSocket) { releaseWriter(); curSocket = s; curWriter = s.writable.getWriter(); }
    return curWriter;
  };
  const headers = new Headers({ 'Content-Type': 'application/octet-stream', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store' });
  return new Response(new ReadableStream({
    async start(controller) {
      let closed = false;
      let udpRespHeader = first.respHeader;
      const bridge = {
        readyState: WebSocket.OPEN,
        send(data) {
          if (closed) return;
          try {
            const chunk = data instanceof Uint8Array ? data : data instanceof ArrayBuffer ? new Uint8Array(data) : ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data);
            controller.enqueue(chunk);
          } catch (e) { closed = true; this.readyState = WebSocket.CLOSED; }
        },
        close() {
          if (closed) return;
          closed = true; this.readyState = WebSocket.CLOSED;
          try { controller.close() } catch (e) { }
        }
      };
      const writeRemote = async (payload, retry = true) => {
        const w = getWriter();
        if (!w) return false;
        try { await w.write(payload); return true; }
        catch (e) {
          releaseWriter();
          if (retry && conn.retryConnect) { await conn.retryConnect(); return writeRemote(payload, false); }
          throw e;
        }
      };
      try {
        if (first.isUDP) {
          if (first.rawData?.byteLength) { await fwdUDP(first.rawData, bridge, udpRespHeader); udpRespHeader = null; }
        } else {
          // ★ 传入 proxyIP
          await fwdTCP(first.hostname, first.port, first.rawData, bridge, first.respHeader, conn, uuid, proxyIP);
        }
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (!value?.byteLength) continue;
          if (first.isUDP) { await fwdUDP(value, bridge, udpRespHeader); udpRespHeader = null; }
          else if (!await writeRemote(value)) throw new Error('Remote not ready');
        }
        if (!first.isUDP) { const w = getWriter(); if (w) try { await w.close() } catch (e) { } }
      } catch (e) { closeQuiet(bridge); }
      finally { releaseWriter(); try { reader.releaseLock() } catch (e) { } }
    },
    cancel() { releaseWriter(); try { conn.socket?.close() } catch (e) { } try { reader.releaseLock() } catch (e) { } }
  }), { status: 200, headers });
}

async function parseXHTTPFirstPacket(reader, token) {
  const decoder = new TextDecoder();
  const sha224pwd = sha224(token);
  const sha224bytes = new TextEncoder().encode(sha224pwd);
  const tryVLESS = (data) => {
    const len = data.byteLength;
    if (len < 18) return { s: 'need' };
    if (fmtId(data.subarray(1, 17)) !== token) return { s: 'invalid' };
    const optLen = data[17], cmdIdx = 18 + optLen;
    if (len < cmdIdx + 1) return { s: 'need' };
    const cmd = data[cmdIdx];
    if (cmd !== 1 && cmd !== 2) return { s: 'invalid' };
    const portIdx = cmdIdx + 1;
    if (len < portIdx + 3) return { s: 'need' };
    const port = (data[portIdx] << 8) | data[portIdx + 1];
    const addrType = data[portIdx + 2], addrIdx = portIdx + 3;
    let headerLen = -1, hostname = '';
    if (addrType === 1) {
      if (len < addrIdx + 4) return { s: 'need' };
      hostname = `${data[addrIdx]}.${data[addrIdx+1]}.${data[addrIdx+2]}.${data[addrIdx+3]}`;
      headerLen = addrIdx + 4;
    } else if (addrType === 2) {
      if (len < addrIdx + 1) return { s: 'need' };
      const dl = data[addrIdx];
      if (len < addrIdx + 1 + dl) return { s: 'need' };
      hostname = decoder.decode(data.subarray(addrIdx + 1, addrIdx + 1 + dl));
      headerLen = addrIdx + 1 + dl;
    } else if (addrType === 3) {
      if (len < addrIdx + 16) return { s: 'need' };
      const v6 = []; for (let i = 0; i < 8; i++) v6.push(((data[addrIdx+i*2]<<8)|data[addrIdx+i*2+1]).toString(16));
      hostname = v6.join(':'); headerLen = addrIdx + 16;
    } else return { s: 'invalid' };
    if (!hostname) return { s: 'invalid' };
    return { s: 'ok', result: { hostname, port, isUDP: cmd === 2, rawData: data.subarray(headerLen), respHeader: new Uint8Array([data[0], 0]) } };
  };
  const tryTrojan = (data) => {
    const len = data.byteLength;
    if (len < 58) return { s: 'need' };
    if (data[56] !== 0x0d || data[57] !== 0x0a) return { s: 'invalid' };
    for (let i = 0; i < 56; i++) if (data[i] !== sha224bytes[i]) return { s: 'invalid' };
    const socksStart = 58;
    if (len < socksStart + 2) return { s: 'need' };
    if (data[socksStart] !== 1) return { s: 'invalid' };
    const atype = data[socksStart + 1];
    let cursor = socksStart + 2, hostname = '';
    if (atype === 1) {
      if (len < cursor + 4) return { s: 'need' };
      hostname = `${data[cursor]}.${data[cursor+1]}.${data[cursor+2]}.${data[cursor+3]}`; cursor += 4;
    } else if (atype === 3) {
      if (len < cursor + 1) return { s: 'need' };
      const dl = data[cursor]; cursor++;
      if (len < cursor + dl) return { s: 'need' };
      hostname = decoder.decode(data.subarray(cursor, cursor + dl)); cursor += dl;
    } else if (atype === 4) {
      if (len < cursor + 16) return { s: 'need' };
      const v6 = []; for (let i = 0; i < 8; i++) v6.push(((data[cursor+i*2]<<8)|data[cursor+i*2+1]).toString(16));
      hostname = v6.join(':'); cursor += 16;
    } else return { s: 'invalid' };
    if (!hostname || len < cursor + 4) return { s: 'need' };
    const port = (data[cursor] << 8) | data[cursor + 1];
    if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { s: 'invalid' };
    return { s: 'ok', result: { hostname, port, isUDP: false, rawData: data.subarray(cursor + 4), respHeader: null } };
  };
  let buffer = new Uint8Array(1024), offset = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) { if (offset === 0) return null; break; }
    const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
    if (offset + chunk.byteLength > buffer.byteLength) {
      const nb = new Uint8Array(Math.max(buffer.byteLength * 2, offset + chunk.byteLength));
      nb.set(buffer.subarray(0, offset)); buffer = nb;
    }
    buffer.set(chunk, offset); offset += chunk.byteLength;
    const cur = buffer.subarray(0, offset);
    const tr = tryTrojan(cur); if (tr.s === 'ok') return { ...tr.result, reader };
    const vr = tryVLESS(cur); if (vr.s === 'ok') return { ...vr.result, reader };
    if (tr.s === 'invalid' && vr.s === 'invalid') return null;
  }
  const final = buffer.subarray(0, offset);
  const tr2 = tryTrojan(final); if (tr2.s === 'ok') return { ...tr2.result, reader };
  const vr2 = tryVLESS(final); if (vr2.s === 'ok') return { ...vr2.result, reader };
  return null;
}

// ==================== gRPC ====================
async function handleGRPC(request, uuid, proxyIP) {  // ★ 接收 proxyIP
  if (!request.body) return new Response('Bad Request', { status: 400 });
  const reader = request.body.getReader();
  const conn = { socket: null, connectingPromise: null, retryConnect: null };
  let isDNS = false, isTrojan = null, curSocket = null, curWriter = null;
  const FLUSH_LIMIT = 64 * 1024, FLUSH_INTERVAL = 20;
  const headers = new Headers({ 'Content-Type': 'application/grpc', 'grpc-status': '0', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store' });
  return new Response(new ReadableStream({
    async start(controller) {
      let closed = false, queue = [], queueBytes = 0, timer = null;
      const bridge = {
        readyState: WebSocket.OPEN,
        send(data) {
          if (closed) return;
          const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
          const lenArr = []; let rem = chunk.byteLength >>> 0;
          while (rem > 127) { lenArr.push((rem & 0x7f) | 0x80); rem >>>= 7; } lenArr.push(rem);
          const lenBytes = new Uint8Array(lenArr);
          const protoLen = 1 + lenBytes.length + chunk.byteLength;
          const frame = new Uint8Array(5 + protoLen);
          frame[0] = 0; frame[1] = (protoLen>>>24)&0xff; frame[2] = (protoLen>>>16)&0xff; frame[3] = (protoLen>>>8)&0xff; frame[4] = protoLen&0xff;
          frame[5] = 0x0a; frame.set(lenBytes, 6); frame.set(chunk, 6 + lenBytes.length);
          queue.push(frame); queueBytes += frame.byteLength;
          if (queueBytes >= FLUSH_LIMIT) flush();
          else if (!timer) timer = setTimeout(flush, FLUSH_INTERVAL);
        },
        close() { if (this.readyState === WebSocket.CLOSED) return; flush(true); closed = true; this.readyState = WebSocket.CLOSED; try { controller.close() } catch (e) { } }
      };
      const flush = (force = false) => {
        if (timer) { clearTimeout(timer); timer = null; }
        if ((!force && closed) || queueBytes === 0) return;
        const out = new Uint8Array(queueBytes); let off = 0;
        for (const item of queue) { out.set(item, off); off += item.byteLength; }
        queue = []; queueBytes = 0;
        try { controller.enqueue(out); } catch (e) { closed = true; bridge.readyState = WebSocket.CLOSED; }
      };
      const releaseWriter = () => {
        if (curWriter) { try { curWriter.releaseLock() } catch (e) { } curWriter = null; } curSocket = null;
      };
      const writeRemote = async (payload, retry = true) => {
        const s = conn.socket; if (!s) return false;
        if (s !== curSocket) { releaseWriter(); curSocket = s; curWriter = s.writable.getWriter(); }
        try { await curWriter.write(payload); return true; }
        catch (e) { releaseWriter(); if (retry && conn.retryConnect) { await conn.retryConnect(); return writeRemote(payload, false); } throw e; }
      };
      try {
        let pending = new Uint8Array(0);
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (!value?.byteLength) continue;
          const cur = value instanceof Uint8Array ? value : new Uint8Array(value);
          const merged = new Uint8Array(pending.length + cur.length); merged.set(pending); merged.set(cur, pending.length); pending = merged;
          while (pending.byteLength >= 5) {
            const grpcLen = ((pending[1]<<24)>>>0)|(pending[2]<<16)|(pending[3]<<8)|pending[4];
            const frameSize = 5 + grpcLen;
            if (pending.byteLength < frameSize) break;
            let payload = pending.slice(5, frameSize); pending = pending.slice(frameSize);
            if (!payload.byteLength) continue;
            if (payload.byteLength >= 2 && payload[0] === 0x0a) {
              let shift = 0, off2 = 1, varintOk = false;
              while (off2 < payload.length) { const c = payload[off2++]; if ((c & 0x80) === 0) { varintOk = true; break; } shift += 7; if (shift > 35) break; }
              if (varintOk) payload = payload.slice(off2);
            }
            if (!payload.byteLength) continue;
            if (isDNS) { await fwdUDP(payload, bridge, null); continue; }
            if (conn.socket) { if (!await writeRemote(payload)) throw new Error('Remote not ready'); continue; }
            const bytes = new Uint8Array(payload instanceof ArrayBuffer ? payload : payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength));
            if (isTrojan === null) isTrojan = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a;
            if (isTrojan) {
              const r = parseTrojan(payload.buffer instanceof ArrayBuffer ? payload.buffer : new Uint8Array(payload).buffer, uuid);
              if (r?.hasError) throw new Error(r.message);
              if (isBlocked(r.hostname)) throw new Error('Blocked');
              // ★ 传入 proxyIP
              await fwdTCP(r.hostname, r.port, r.rawClientData, bridge, null, conn, uuid, proxyIP);
            } else {
              const r = parseVLESS(payload.buffer instanceof ArrayBuffer ? payload.buffer : new Uint8Array(payload).buffer, uuid);
              if (r?.hasError) throw new Error(r.message);
              if (isBlocked(r.hostname)) throw new Error('Blocked');
              if (r.isUDP) { if (r.port !== 53) throw new Error('UDP not supported'); isDNS = true; }
              const respHeader = new Uint8Array([r.version[0], 0]);
              bridge.send(respHeader);
              const rawData = payload.buffer instanceof ArrayBuffer ? payload.buffer.slice(r.rawIndex) : new Uint8Array(payload).buffer.slice(r.rawIndex);
              if (isDNS) await fwdUDP(rawData, bridge, null);
              // ★ 传入 proxyIP
              else await fwdTCP(r.hostname, r.port, rawData, bridge, null, conn, uuid, proxyIP);
            }
          }
          flush();
        }
      } catch (e) { }
      finally { releaseWriter(); flush(true); closed = true; bridge.readyState = WebSocket.CLOSED; if (timer) clearTimeout(timer); try { reader.releaseLock() } catch (e) { } try { conn.socket?.close() } catch (e) { } try { controller.close() } catch (e) { } }
    },
    cancel() { try { conn.socket?.close() } catch (e) { } try { reader.releaseLock() } catch (e) { } }
  }), { status: 200, headers });
}

// ==================== WebSocket ====================
async function handleWS(request, uuid, url, proxyIP) {  // ★ 接收 proxyIP
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept(); server.binaryType = 'arraybuffer';
  const conn = { socket: null, connectingPromise: null, retryConnect: null };
  let isDNS = false, proto = null, curSocket = null, curWriter = null;
  const earlyData = request.headers.get('sec-websocket-protocol') || '';
  let cancelled = false, streamClosed = false;
  const readable = new ReadableStream({
    start(ctrl) {
      const isClosedErr = (e) => { const m = e?.message||`${e||''}`; return m.includes('ReadableStream is closed')||m.includes('already closed'); };
      const enqueue = (d) => { if (cancelled || streamClosed) return; try { ctrl.enqueue(d); } catch (e) { streamClosed = true; if (!isClosedErr(e)) try { ctrl.error(e) } catch (_) { } } };
      const close = () => { if (cancelled || streamClosed) return; streamClosed = true; try { ctrl.close(); } catch (e) { if (!isClosedErr(e)) try { ctrl.error(e) } catch (_) { } } };
      server.addEventListener('message', e => enqueue(e.data));
      server.addEventListener('close', () => { closeQuiet(server); close(); });
      server.addEventListener('error', e => { streamClosed = true; try { ctrl.error(e) } catch (_) { } closeQuiet(server); });
      if (earlyData) { try { const b = atob(earlyData.replace(/-/g,'+').replace(/_/g,'/')); const bytes = new Uint8Array(b.length); for (let i=0;i<b.length;i++) bytes[i]=b.charCodeAt(i); enqueue(bytes.buffer); } catch (e) { streamClosed=true; try{ctrl.error(e)}catch(_){} } }
    },
    cancel() { cancelled = true; streamClosed = true; closeQuiet(server); }
  });
  const releaseWriter = () => { if (curWriter) { try { curWriter.releaseLock() } catch (e) { } curWriter = null; } curSocket = null; };
  const writeRemote = async (chunk, retry = true) => {
    const s = conn.socket; if (!s) return false;
    if (s !== curSocket) { releaseWriter(); curSocket = s; curWriter = s.writable.getWriter(); }
    try { await curWriter.write(chunk); return true; }
    catch (e) { releaseWriter(); if (retry && conn.retryConnect) { await conn.retryConnect(); return writeRemote(chunk, false); } throw e; }
  };
  readable.pipeTo(new WritableStream({
    async write(chunk) {
      if (isDNS) { await fwdUDP(chunk, server, null); return; }
      if (await writeRemote(chunk)) return;
      if (proto === null) {
        const bytes = new Uint8Array(chunk);
        proto = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a ? 'trojan' : 'vless';
      }
      if (await writeRemote(chunk)) return;
      if (proto === 'trojan') {
        const r = parseTrojan(chunk, uuid);
        if (r?.hasError) throw new Error(r.message);
        if (isBlocked(r.hostname)) throw new Error('Blocked');
        // ★ 传入 proxyIP
        await fwdTCP(r.hostname, r.port, r.rawClientData, server, null, conn, uuid, proxyIP);
      } else {
        const r = parseVLESS(chunk, uuid);
        if (r?.hasError) throw new Error(r.message);
        if (isBlocked(r.hostname)) throw new Error('Blocked');
        if (r.isUDP) { if (r.port === 53) isDNS = true; else throw new Error('UDP not supported'); }
        const respHeader = new Uint8Array([r.version[0], 0]);
        const rawData = chunk.slice(r.rawIndex);
        if (isDNS) return fwdUDP(rawData, server, respHeader);
        // ★ 传入 proxyIP
        await fwdTCP(r.hostname, r.port, rawData, server, respHeader, conn, uuid, proxyIP);
      }
    },
    close() { releaseWriter(); },
    abort() { releaseWriter(); }
  })).catch(() => { releaseWriter(); closeQuiet(server); });
  return new Response(null, { status: 101, webSocket: client });
}

// ==================== 协议解析 ====================
function parseTrojan(buffer, pwd) {
  const sha = sha224(pwd);
  if (buffer.byteLength < 56) return { hasError: true, message: 'too short' };
  if (new Uint8Array(buffer.slice(56,57))[0]!==0x0d||new Uint8Array(buffer.slice(57,58))[0]!==0x0a) return { hasError: true, message: 'bad header' };
  if (new TextDecoder().decode(buffer.slice(0,56)) !== sha) return { hasError: true, message: 'bad password' };
  const s = buffer.slice(58); if (s.byteLength < 6) return { hasError: true, message: 'bad socks5' };
  const dv = new DataView(s); if (dv.getUint8(0) !== 1) return { hasError: true, message: 'not TCP' };
  const atype = dv.getUint8(1); let ai = 2, al = 0, addr = '';
  switch (atype) {
    case 1: al = 4; addr = new Uint8Array(s.slice(ai, ai+al)).join('.'); break;
    case 3: al = new Uint8Array(s.slice(ai,ai+1))[0]; ai++; addr = new TextDecoder().decode(s.slice(ai,ai+al)); break;
    case 4: al = 16; { const dv2=new DataView(s.slice(ai,ai+al)),v6=[]; for(let i=0;i<8;i++) v6.push(dv2.getUint16(i*2).toString(16)); addr=v6.join(':'); } break;
    default: return { hasError: true, message: 'bad atype' };
  }
  if (!addr) return { hasError: true, message: 'no addr' };
  const pi = ai + al; const port = new DataView(s.slice(pi,pi+2)).getUint16(0);
  return { hasError: false, port, hostname: addr, rawClientData: s.slice(pi+4) };
}

function parseVLESS(chunk, token) {
  if (chunk.byteLength < 24) return { hasError: true, message: 'too short' };
  const version = new Uint8Array(chunk.slice(0,1));
  if (fmtId(new Uint8Array(chunk.slice(1,17))) !== token) return { hasError: true, message: 'bad uuid' };
  const optLen = new Uint8Array(chunk.slice(17,18))[0], cmd = new Uint8Array(chunk.slice(18+optLen,19+optLen))[0];
  let isUDP = false;
  if (cmd === 1) {} else if (cmd === 2) { isUDP = true; } else return { hasError: true, message: 'bad cmd' };
  const pi = 19 + optLen, port = new DataView(chunk.slice(pi,pi+2)).getUint16(0);
  let ai = pi+2, av = ai+1, al = 0, hostname = '';
  const atype = new Uint8Array(chunk.slice(ai,av))[0];
  switch (atype) {
    case 1: al=4; hostname=new Uint8Array(chunk.slice(av,av+al)).join('.'); break;
    case 2: al=new Uint8Array(chunk.slice(av,av+1))[0]; av++; hostname=new TextDecoder().decode(chunk.slice(av,av+al)); break;
    case 3: al=16; { const dv=new DataView(chunk.slice(av,av+al)),v6=[]; for(let i=0;i<8;i++) v6.push(dv.getUint16(i*2).toString(16)); hostname=v6.join(':'); } break;
    default: return { hasError: true, message: 'bad atype' };
  }
  if (!hostname) return { hasError: true, message: 'no addr' };
  return { hasError: false, port, hostname, isUDP, rawIndex: av+al, version };
}

// ==================== TCP/UDP转发 ====================
// ★★★ 核心修复：fwdTCP 加入 proxyIP 参数，实现直连失败后走 ProxyIP 的回退逻辑 ★★★
async function fwdTCP(host, port, rawData, ws, respHeader, conn, uuid, proxyIP) {
  const TIMEOUT = 5000;

  const waitOpen = (sock, ms = TIMEOUT) =>
    Promise.race([sock.opened, new Promise((_, r) => setTimeout(() => r(new Error('connect timeout')), ms))]);

  // 尝试建立一条 TCP 连接，connectHost/connectPort 是实际连接目标
  const tryConnect = async (connectHost, connectPort) => {
    const sock = connect({ hostname: connectHost, port: connectPort });
    await waitOpen(sock);
    return sock;
  };

  // 写入初始数据
  const writeInit = async (sock) => {
    if (rawData && (rawData.byteLength ?? rawData.length ?? 0) > 0) {
      const w = sock.writable.getWriter();
      await w.write(rawData instanceof ArrayBuffer ? new Uint8Array(rawData) : rawData);
      w.releaseLock();
    }
  };

  // 解析 proxyIP，支持 host:port 格式，默认端口 443
  let proxyHost = null, proxyPort = 443;
  if (proxyIP) {
    const [ph, pp] = splitAddrPort(proxyIP);
    proxyHost = ph;
    proxyPort = parseInt(pp, 10) || 443;
  }

  let sock = null;

  try {
    // 第一步：先尝试直连目标
    sock = await tryConnect(host, port);
  } catch (e) {
    // 直连失败，如果有 proxyIP 则尝试走代理
    if (proxyHost) {
      try {
        sock = await tryConnect(proxyHost, proxyPort);
      } catch (e2) {
        closeQuiet(ws);
        return;
      }
    } else {
      closeQuiet(ws);
      return;
    }
  }

  // 设置重试逻辑：重试时优先用 proxyIP
  conn.retryConnect = async () => {
    if (conn.connectingPromise) { await conn.connectingPromise; return; }
    const task = (async () => {
      let retrySock = null;
      // 优先用 proxyIP 重试，其次回退直连
      const attempts = proxyHost
        ? [{ h: proxyHost, p: proxyPort }, { h: host, p: port }]
        : [{ h: host, p: port }];
      for (const { h, p } of attempts) {
        try { retrySock = await tryConnect(h, p); break; } catch (e) { }
      }
      if (!retrySock) { closeQuiet(ws); return; }
      conn.socket = retrySock;
      retrySock.closed.catch(() => {}).finally(() => closeQuiet(ws));
      pipeRemote(retrySock, ws, null, null);
    })();
    conn.connectingPromise = task;
    try { await task; } finally { if (conn.connectingPromise === task) conn.connectingPromise = null; }
  };

  conn.socket = sock;
  await writeInit(sock);
  sock.closed.catch(() => {}).finally(() => closeQuiet(ws));

  // 如果直连成功但没有数据返回，自动用 proxyIP 重试
  pipeRemote(sock, ws, respHeader, proxyHost ? async () => {
    if (conn.socket !== sock) return;
    // 直连无数据，尝试 proxyIP
    let proxySock = null;
    try { proxySock = await tryConnect(proxyHost, proxyPort); } catch (e) { return; }
    conn.socket = proxySock;
    await writeInit(proxySock);
    proxySock.closed.catch(() => {}).finally(() => closeQuiet(ws));
    pipeRemote(proxySock, ws, respHeader, null);
  } : null);
}

async function fwdUDP(chunk, ws, respHeader) {
  try {
    const sock = connect({ hostname: '8.8.4.4', port: 53 });
    let header = respHeader;
    const w = sock.writable.getWriter();
    await w.write(chunk); w.releaseLock();
    await sock.readable.pipeTo(new WritableStream({
      async write(c) {
        if (ws.readyState === WebSocket.OPEN) {
          if (header) { const merged = new Uint8Array(header.length + c.byteLength); merged.set(header); merged.set(c, header.length); await wsSend(ws, merged.buffer); header = null; }
          else await wsSend(ws, c);
        }
      }
    }));
  } catch (e) { }
}

async function pipeRemote(remoteSock, ws, headerData, retryFn) {
  let header = headerData, hasData = false;
  const send = async (chunk) => {
    if (ws.readyState !== WebSocket.OPEN) throw new Error('ws closed');
    if (header) { const m = new Uint8Array(header.length + chunk.byteLength); m.set(header); m.set(chunk, header.length); await wsSend(ws, m.buffer); header = null; }
    else await wsSend(ws, chunk);
  };
  let reader;
  try { reader = remoteSock.readable.getReader({ mode: 'byob' }); }
  catch (e) { reader = remoteSock.readable.getReader(); }
  try {
    while (true) {
      let res;
      try {
        if (reader.constructor.name === 'ReadableStreamBYOBReader') {
          res = await reader.read(new Uint8Array(64 * 1024));
        } else { res = await reader.read(); }
      } catch (e) { break; }
      if (res.done) break;
      if (!res.value?.byteLength) continue;
      hasData = true;
      await send(res.value instanceof Uint8Array ? res.value : new Uint8Array(res.value));
    }
  } catch (e) { closeQuiet(ws); }
  finally { try { reader.cancel() } catch (e) { } try { reader.releaseLock() } catch (e) { } }
  if (!hasData && retryFn) await retryFn();
}

// ==================== 工具函数 ====================
function fmtId(arr, off=0) {
  const hex = [...arr.slice(off, off+16)].map(b=>b.toString(16).padStart(2,'0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

async function wsSend(ws, data) {
  const r = ws.send(data);
  if (r && typeof r.then === 'function') await r;
}

function closeQuiet(sock) {
  try { if (sock.readyState === WebSocket.OPEN || sock.readyState === WebSocket.CLOSING) sock.close(); } catch (e) { }
}

function isBlocked(host) {
  return ['speed.cloudflare.com'].some(d => host === d || host.endsWith('.' + d));
}

function sha224(s) {
  const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const r=(n,b)=>((n>>>b)|(n<<(32-b)))>>>0;
  s=unescape(encodeURIComponent(s));
  const l=s.length*8; s+=String.fromCharCode(0x80);
  while((s.length*8)%512!==448) s+=String.fromCharCode(0);
  const h=[0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4];
  const hi=Math.floor(l/0x100000000),lo=l&0xFFFFFFFF;
  s+=String.fromCharCode((hi>>>24)&0xFF,(hi>>>16)&0xFF,(hi>>>8)&0xFF,hi&0xFF,(lo>>>24)&0xFF,(lo>>>16)&0xFF,(lo>>>8)&0xFF,lo&0xFF);
  const w=[]; for(let i=0;i<s.length;i+=4) w.push((s.charCodeAt(i)<<24)|(s.charCodeAt(i+1)<<16)|(s.charCodeAt(i+2)<<8)|s.charCodeAt(i+3));
  for(let i=0;i<w.length;i+=16){
    const x=new Array(64).fill(0);
    for(let j=0;j<16;j++) x[j]=w[i+j];
    for(let j=16;j<64;j++){const s0=r(x[j-15],7)^r(x[j-15],18)^(x[j-15]>>>3),s1=r(x[j-2],17)^r(x[j-2],19)^(x[j-2]>>>10);x[j]=(x[j-16]+s0+x[j-7]+s1)>>>0;}
    let [a,b,c,d,e,f,g,h0]=h;
    for(let j=0;j<64;j++){const S1=r(e,6)^r(e,11)^r(e,25),ch=(e&f)^(~e&g),t1=(h0+S1+ch+K[j]+x[j])>>>0,S0=r(a,2)^r(a,13)^r(a,22),maj=(a&b)^(a&c)^(b&c),t2=(S0+maj)>>>0;h0=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;}
    for(let j=0;j<8;j++) h[j]=(h[j]+(j===0?a:j===1?b:j===2?c:j===3?d:j===4?e:j===5?f:j===6?g:h0))>>>0;
  }
  let hex=''; for(let i=0;i<7;i++) for(let j=24;j>=0;j-=8) hex+=((h[i]>>>j)&0xFF).toString(16).padStart(2,'0');
  return hex;
}

async function nginx() {
  return `<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p><p><em>Thank you for using nginx.</em></p></body></html>`;
}
