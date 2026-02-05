// 如需要使用环境变量,将462至468行取消注释
import { connect } from 'cloudflare:sockets';

let subPath = 'usb';     // 节点订阅路径,不修改将使用UUID作为订阅路径
let proxyIP = 'proxy.xxxxxxxx.tk:50001';  // 默认proxyIP，可选
let password = '757e052c-4159-491d-bc5d-1b6bd866d980';  // 节点UUID
let SSpath = '';          // 路径验证，为空则使用UUID作为验证路径

// ==================== 优选IP配置 ====================
// 格式: 优选IP:端口#备注名称
// 注意: 每个优选IP都作为proxyIP使用
let cfip = [ 
    '112.119.8.12:443#HK',
    '149.104.30.17:443#HK', 
    '153.121.45.101:443#JP'
];  // 可以随时修改这里的优选IP

// ==================== 工具函数 ====================
function closeSocketQuietly(socket) {
    try { 
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close(); 
        }
    } catch (error) {} 
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try { 
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { earlyData: bytes.buffer, error: null }; 
    } catch (error) { 
        return { error }; 
    }
}

// 解析proxyIP地址
function parsePryAddress(serverStr) {
    if (!serverStr) return null;
    serverStr = serverStr.trim();
    
    // 处理socks5代理
    if (serverStr.startsWith('socks://') || serverStr.startsWith('socks5://')) {
        const urlStr = serverStr.replace(/^socks:\/\//, 'socks5://');
        try {
            const url = new URL(urlStr);
            return {
                type: 'socks5',
                host: url.hostname,
                port: parseInt(url.port) || 1080,
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    
    // 处理HTTP/HTTPS代理
    if (serverStr.startsWith('http://') || serverStr.startsWith('https://')) {
        try {
            const url = new URL(serverStr);
            return {
                type: 'http',
                host: url.hostname,
                port: parseInt(url.port) || (serverStr.startsWith('https://') ? 443 : 80),
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    
    // 处理IPv6地址
    if (serverStr.startsWith('[')) {
        const closeBracket = serverStr.indexOf(']');
        if (closeBracket > 0) {
            const host = serverStr.substring(1, closeBracket);
            const rest = serverStr.substring(closeBracket + 1);
            if (rest.startsWith(':')) {
                const port = parseInt(rest.substring(1), 10);
                if (!isNaN(port) && port > 0 && port <= 65535) {
                    return { type: 'direct', host, port };
                }
            }
            return { type: 'direct', host, port: 443 };
        }
    }
    
    // 处理host:port格式
    const lastColonIndex = serverStr.lastIndexOf(':');
    if (lastColonIndex > 0) {
        const host = serverStr.substring(0, lastColonIndex);
        const portStr = serverStr.substring(lastColonIndex + 1);
        const port = parseInt(portStr, 10);
        if (!isNaN(port) && port > 0 && port <= 65535) {
            return { type: 'direct', host, port };
        }
    }
    
    // 默认443端口
    return { type: 'direct', host: serverStr, port: 443 };
}

// 解析优选IP条目，返回 {host, port, name}
function parseCFIPItem(cfipItem) {
    let host = '', port = 443, name = '';
    
    if (cfipItem.includes('#')) {
        const parts = cfipItem.split('#');
        cfipItem = parts[0];
        name = parts[1];
    }
    
    if (cfipItem.includes(':')) {
        const colonIndex = cfipItem.lastIndexOf(':');
        host = cfipItem.substring(0, colonIndex);
        const portStr = cfipItem.substring(colonIndex + 1);
        port = parseInt(portStr) || 443;
    } else {
        host = cfipItem;
    }
    
    return { host, port, name };
}

function isSpeedTestSite(hostname) {
    const speedTestDomains = ['speedtest.net','fast.com','speedtest.cn','speed.cloudflare.com', 'ovo.speedtestcustom.com'];
    if (speedTestDomains.includes(hostname)) {
        return true;
    }
    for (const domain of speedTestDomains) {
        if (hostname.endsWith('.' + domain) || hostname === domain) {
            return true;
        }
    }
    return false;
}

// ==================== WebSocket处理器 ====================
async function handleSSRequest(request, customProxyIP) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);
    
    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            const { hasError, message, addressType, port, hostname, rawIndex } = parseSSPacketHeader(chunk);
            if (hasError) throw new Error(message);

            if (isSpeedTestSite(hostname)) {
                throw new Error('Speedtest site is blocked');
            }
            if (addressType === 2) { 
                if (port === 53) isDnsQuery = true;
                else throw new Error('UDP is not supported');
            }
            const rawData = chunk.slice(rawIndex);
            if (isDnsQuery) return forwardataudp(rawData, serverSock, null);
            await forwardataTCP(hostname, port, rawData, serverSock, null, remoteConnWrapper, customProxyIP);
        },
    })).catch((err) => {
        // console.error('Readable pipe error:', err);
    });
    
    return new Response(null, { status: 101, webSocket: clientSock });
}

function parseSSPacketHeader(chunk) {
    if (chunk.byteLength < 7) return { hasError: true, message: 'Invalid data' };
    try {
        const view = new Uint8Array(chunk);
        const addressType = view[0];
        let addrIdx = 1, addrLen = 0, addrValIdx = addrIdx, hostname = '';
        switch (addressType) {
            case 1: // IPv4
                addrLen = 4; 
                hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.'); 
                addrValIdx += addrLen;
                break;
            case 3: // Domain
                addrLen = view[addrIdx];
                addrValIdx += 1; 
                hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen)); 
                addrValIdx += addrLen;
                break;
            case 4: // IPv6
                addrLen = 16; 
                const ipv6 = []; 
                const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen)); 
                for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16)); 
                hostname = ipv6.join(':'); 
                addrValIdx += addrLen;
                break;
            default: 
                return { hasError: true, message: `Invalid address type: ${addressType}` };
        }
        if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
        const port = new DataView(chunk.slice(addrValIdx, addrValIdx + 2)).getUint16(0);
        return { hasError: false, addressType, port, hostname, rawIndex: addrValIdx + 2 };
    } catch (e) {
        return { hasError: true, message: 'Failed to parse SS packet header' };
    }
}

async function connect2Socks5(proxyConfig, targetHost, targetPort, initialData) {
    const { host, port, username, password } = proxyConfig;
    const socket = connect({ hostname: host, port: port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    
    try {
        const authMethods = username && password ? 
            new Uint8Array([0x05, 0x02, 0x00, 0x02]) :
            new Uint8Array([0x05, 0x01, 0x00]); 
        
        await writer.write(authMethods);
        const methodResponse = await reader.read();
        if (methodResponse.done || methodResponse.value.byteLength < 2) {
            throw new Error('S5 method selection failed');
        }
        
        const selectedMethod = new Uint8Array(methodResponse.value)[1];
        if (selectedMethod === 0x02) {
            if (!username || !password) {
                throw new Error('S5 requires authentication');
            }
            
            const userBytes = new TextEncoder().encode(username);
            const passBytes = new TextEncoder().encode(password);
            const authPacket = new Uint8Array(3 + userBytes.length + passBytes.length);
            authPacket[0] = 0x01; 
            authPacket[1] = userBytes.length;
            authPacket.set(userBytes, 2);
            authPacket[2 + userBytes.length] = passBytes.length;
            authPacket.set(passBytes, 3 + userBytes.length);
            
            await writer.write(authPacket);
            const authResponse = await reader.read();
            if (authResponse.done || new Uint8Array(authResponse.value)[1] !== 0x00) {
                throw new Error('S5 authentication failed');
            }
        } else if (selectedMethod !== 0x00) {
            throw new Error(`S5 unsupported auth method: ${selectedMethod}`);
        }
        
        const hostBytes = new TextEncoder().encode(targetHost);
        const connectPacket = new Uint8Array(7 + hostBytes.length);
        connectPacket[0] = 0x05;
        connectPacket[1] = 0x01;
        connectPacket[2] = 0x00; 
        connectPacket[3] = 0x03; 
        connectPacket[4] = hostBytes.length;
        connectPacket.set(hostBytes, 5);
        new DataView(connectPacket.buffer).setUint16(5 + hostBytes.length, targetPort, false);
        
        await writer.write(connectPacket);
        const connectResponse = await reader.read();
        if (connectResponse.done || new Uint8Array(connectResponse.value)[1] !== 0x00) {
            throw new Error('S5 connection failed');
        }
        
        await writer.write(initialData);
        writer.releaseLock();
        reader.releaseLock();
        return socket;
        
    } catch (error) {
        writer.releaseLock();
        reader.releaseLock();
        throw error;
    }
}

async function connect2Http(proxyConfig, targetHost, targetPort, initialData) {
    const { host, port, username, password } = proxyConfig;
    const socket = connect({ hostname: host, port: port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    
    try {
        let connectRequest = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
        connectRequest += `Host: ${targetHost}:${targetPort}\r\n`;
        
        if (username && password) {
            const auth = btoa(`${username}:${password}`);
            connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
        }
        
        connectRequest += `User-Agent: Mozilla/5.0\r\n`;
        connectRequest += `Connection: keep-alive\r\n`;
        connectRequest += '\r\n';
        
        await writer.write(new TextEncoder().encode(connectRequest));
        
        let responseBuffer = new Uint8Array(0);
        let headerEndIndex = -1;
        let bytesRead = 0;
        const maxHeaderSize = 8192;
        
        while (headerEndIndex === -1 && bytesRead < maxHeaderSize) {
            const { done, value } = await reader.read();
            if (done) {
                throw new Error('Connection closed before receiving HTTP response');
            }
            
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;
            bytesRead = responseBuffer.length;
            
            for (let i = 0; i < responseBuffer.length - 3; i++) {
                if (responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a &&
                    responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a) {
                    headerEndIndex = i + 4;
                    break;
                }
            }
        }
        
        if (headerEndIndex === -1) {
            throw new Error('Invalid HTTP response');
        }
        
        const headerText = new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex));
        const statusLine = headerText.split('\r\n')[0];
        const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
        if (!statusMatch) {
            throw new Error(`Invalid response: ${statusLine}`);
        }
        
        const statusCode = parseInt(statusMatch[1]);
        if (statusCode < 200 || statusCode >= 300) {
            throw new Error(`Connection failed: ${statusLine}`);
        }
        
        await writer.write(initialData);
        writer.releaseLock();
        reader.releaseLock();
        return socket;
        
    } catch (error) {
        try { writer.releaseLock(); } catch (e) {}
        try { reader.releaseLock(); } catch (e) {}
        try { socket.close(); } catch (e) {}
        throw error;
    }
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, customProxyIP) {
    async function connectDirect(address, port, data) {
        const remoteSock = connect({ hostname: address, port: port });
        const writer = remoteSock.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
        return remoteSock;
    }
    
    let proxyConfig = null;
    let shouldUseProxy = false;
    
    if (customProxyIP) {
        proxyConfig = parsePryAddress(customProxyIP);
        if (proxyConfig && (proxyConfig.type === 'socks5' || proxyConfig.type === 'http' || proxyConfig.type === 'https')) {
            shouldUseProxy = true;
        } else if (!proxyConfig) {
            proxyConfig = parsePryAddress(proxyIP) || { type: 'direct', host: proxyIP, port: 443 };
        }
    } else {
        proxyConfig = parsePryAddress(proxyIP) || { type: 'direct', host: proxyIP, port: 443 };
        if (proxyConfig.type === 'socks5' || proxyConfig.type === 'http' || proxyConfig.type === 'https') {
            shouldUseProxy = true;
        }
    }
    
    async function connecttoPry() {
        let newSocket;
        if (proxyConfig.type === 'socks5') {
            newSocket = await connect2Socks5(proxyConfig, host, portNum, rawData);
        } else if (proxyConfig.type === 'http' || proxyConfig.type === 'https') {
            newSocket = await connect2Http(proxyConfig, host, portNum, rawData);
        } else {
            newSocket = await connectDirect(proxyConfig.host, proxyConfig.port, rawData);
        }
        
        remoteConnWrapper.socket = newSocket;
        newSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
        connectStreams(newSocket, ws, respHeader, null);
    }
    
    if (shouldUseProxy) {
        try {
            await connecttoPry();
        } catch (err) {
            throw err;
        }
    } else {
        try {
            const initialSocket = await connectDirect(host, portNum, rawData);
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, respHeader, connecttoPry);
        } catch (err) {
            await connecttoPry();
        }
    }
}

function makeReadableStr(socket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            socket.addEventListener('message', (event) => { 
                if (!cancelled) controller.enqueue(event.data); 
            });
            socket.addEventListener('close', () => { 
                if (!cancelled) { 
                    closeSocketQuietly(socket); 
                    controller.close(); 
                } 
            });
            socket.addEventListener('error', (err) => controller.error(err));
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) controller.error(error); 
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() { 
            cancelled = true; 
            closeSocketQuietly(socket); 
        }
    });
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
    let header = headerData, hasData = false;
    
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                hasData = true;
                if (webSocket.readyState !== WebSocket.OPEN) controller.error('wsreadyState not open');
                if (header) { 
                    const response = new Uint8Array(header.length + chunk.byteLength);
                    response.set(header, 0);
                    response.set(chunk, header.length);
                    webSocket.send(response.buffer); 
                    header = null; 
                } else { 
                    webSocket.send(chunk); 
                }
            },
            abort() {},
        })
    ).catch((err) => { 
        closeSocketQuietly(webSocket); 
    });
    
    if (!hasData && retryFunc) {
        await retryFunc();
    }
}

async function forwardataudp(udpChunk, webSocket, respHeader) {
    try {
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        let vlessHeader = respHeader;
        const writer = tcpSocket.writable.getWriter();
        
        await writer.write(udpChunk);
        writer.releaseLock();
        
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WebSocket.OPEN) {
                    if (vlessHeader) { 
                        const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
                        response.set(vlessHeader, 0);
                        response.set(chunk, vlessHeader.length);
                        webSocket.send(response.buffer);
                        vlessHeader = null; 
                    } else { 
                        webSocket.send(chunk); 
                    }
                }
            },
        }));
    } catch (error) {
        // console.error('UDP forward error:', error);
    }
}

// ==================== 页面生成 ====================
function getSimplePage(request) {
    const url = request.headers.get('Host');
    const baseUrl = `https://${url}`;
    
    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Shadowsocks Cloudflare Service</title><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#7dd3ca 0%,#a17ec4 100%);height:100vh;display:flex;align-items:center;justify-content:center;color:#333;margin:0;padding:0;overflow:hidden;}.container{background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);border-radius:20px;padding:40px;box-shadow:0 20px 40px rgba(0,0,0,0.1);max-width:800px;width:95%;text-align:center;}.logo{margin-bottom:-20px;}.title{font-size:2rem;margin-bottom:30px;color:#2d3748;}.tip-card{background:#fff3cd;border-radius:12px;padding:20px;margin:20px 0;text-align:center;border-left:4px solid #ffc107;}.tip-title{font-weight:600;color:#856404;margin-bottom:10px;}.tip-content{color:#856404;font-size:1rem;}.highlight{font-weight:bold;color:#000;background:#fff;padding:2px 6px;border-radius:4px;}@media (max-width:768px){.container{padding:20px;}}</style></head><body><div class="container"><div class="logo"><img src="https://img.icons8.com/color/96/cloudflare.png" alt="Logo" width="96" height="96"></div><h1 class="title">Hello Shadowsocks！</h1><div class="tip-content">访问 <span class="highlight">${baseUrl}/${password}</span> 进入订阅中心</div></div></div></body></html>`;
    
    return new Response(html, {
        status: 200,
        headers: {
            'Content-Type': 'text/html;charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
    });
}

// ==================== 主入口 ====================
export default {
    async fetch(request, env) {
        try {
            // 如需使用环境变量，取消注释下面代码
            // if (env.PROXYIP || env.proxyip || env.proxyIP) {
            //     const servers = (env.PROXYIP || env.proxyip || env.proxyIP).split(',').map(s => s.trim());
            //     // proxyIP = servers[0];
            // }
            // password = env.PASSWORD || env.password || env.uuid || env.UUID || password;
            // subPath = env.SUB_PATH || env.subpath || subPath;
            // SSpath = env.SSPATH || env.sspath || SSpath;
            
            // 路径配置
            if (subPath === 'link' || subPath === '') {
                subPath = password;
            }
            if (SSpath === '') {
                SSpath = password;
            }
            
            const validPath = `/${SSpath}`;
            const servers = proxyIP.split(',').map(s => s.trim());
            proxyIP = servers[0];
            const method = 'none';
            const url = new URL(request.url);
            const pathname = url.pathname;
            
            // 处理proxyIP设置请求
            if (pathname.startsWith('/proxyip=')) {
                try {
                    const pathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
                    if (pathProxyIP && !request.headers.get('Upgrade')) {
                        proxyIP = pathProxyIP;
                        return new Response(`set proxyIP to: ${proxyIP}\n\n`, {
                            headers: { 
                                'Content-Type': 'text/plain; charset=utf-8',
                                'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                            },
                        });
                    }
                } catch (e) {
                    // 忽略错误
                }
            }
            
            // 处理WebSocket升级请求
            if (request.headers.get('Upgrade') === 'websocket') {
                if (!pathname.toLowerCase().startsWith(validPath.toLowerCase())) {
                    return new Response('Unauthorized', { status: 401 });
                }
                
                let wsPathProxyIP = null;
                if (pathname.startsWith('/proxyip=')) {
                    try {
                        wsPathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
                    } catch (e) {
                        // 忽略错误
                    }
                }
                
                const customProxyIP = wsPathProxyIP || url.searchParams.get('proxyip') || request.headers.get('proxyip');
                return await handleSSRequest(request, customProxyIP);
            }
            
            // 处理HTTP GET请求
            if (request.method === 'GET') {
                // 首页
                if (url.pathname === '/') {
                    return getSimplePage(request);
                }
                
                // UUID详情页面
                if (url.pathname.toLowerCase() === `/${password.toLowerCase()}`) {
                    const sheader = 's' + 's';
                    const typelink = 'c'+ 'l'+ 'a'+ 's'+ 'h';
                    const currentDomain = url.hostname;
                    const baseUrl = `https://${currentDomain}`;
                    const vUrl = `${baseUrl}/sub/${subPath}`;
                    const qxConfig = `shadowsocks=mfa.gov.ua:443,method=none,password=${password},obfs=wss,obfs-host=${currentDomain},obfs-uri=/${SSpath}/?ed=2560,fast-open=true, udp-relay=true,tag=SS`;
                    const claLink = `https://sub.ssss.xx.kg/${typelink}?config=${vUrl}`;
                    
                    // 生成优选IP列表
                    const nodeListHTML = cfip.map(item => {
                        const { host, port, name } = parseCFIPItem(item);
                        return `<tr>
                            <td>${name || '节点'}</td>
                            <td>${host}:${port}</td>
                            <td><a href="/${SSpath}/?ed=2560&proxyip=${host}:${port}">使用此IP</a></td>
                        </tr>`;
                    }).join('');
                    
                    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Shadowsocks 订阅中心</title><style>
                        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;padding:20px;background:linear-gradient(135deg,#7dd3ca 0%,#a17ec4 100%);color:#333}
                        .container{max-width:800px;margin:0 auto}
                        .header{margin-bottom:30px}
                        .header h1{text-align:center;color:#007fff;border-bottom:2px solid #3498db;padding-bottom:10px}
                        .section{margin-bottom:20px}
                        .section h2{color:#b33ce7;margin-bottom:10px;font-size:1.2em}
                        .link-box{background:#f0fffa;border:1px solid #ddd;border-radius:8px;padding:15px;margin-bottom:15px}
                        .lintext{word-break:break-all;font-family:monospace;color:#2980b9;margin:10px 0;}
                        .button-group{display:flex;gap:10px;margin-top:10px}
                        .copy-btn{background:#27aea2;color:white;border:none;padding:8px 15px;border-radius:4px;cursor:pointer}
                        .copy-btn:hover{background:#219652}
                        .node-table{width:100%;border-collapse:collapse;margin:15px 0}
                        .node-table th, .node-table td{padding:10px;border:1px solid #ddd;text-align:left}
                        .node-table th{background:#f0f0f0}
                    </style></head><body>
                    <div class="container">
                        <div class="header"><h1>Shadowsocks 订阅中心</h1></div>
                        
                        <div class="section">
                            <h2>📱 订阅链接</h2>
                            <div class="link-box">
                                <div class="lintext">${vUrl}</div>
                                <div class="button-group">
                                    <button class="copy-btn" onclick="copyToClipboard('${vUrl}')">复制订阅链接</button>
                                </div>
                            </div>
                        </div>
                        
                        <div class="section">
                            <h2>🌍 优选IP列表（每个都是proxyIP）</h2>
                            <table class="node-table">
                                <thead><tr><th>地区</th><th>IP:端口</th><th>操作</th></tr></thead>
                                <tbody>${nodeListHTML}</tbody>
                            </table>
                            <p>说明：每个优选IP既作为节点地址，也作为proxyIP使用。</p>
                        </div>
                        
                        <div class="section">
                            <h2>🔧 Quantumult X配置</h2>
                            <div class="link-box">
                                <div class="lintext" style="white-space:pre-wrap;background:#f8f9fa;padding:10px;">${qxConfig}</div>
                                <div class="button-group">
                                    <button class="copy-btn" onclick="copyToClipboard(\`${qxConfig}\`)">复制配置</button>
                                </div>
                            </div>
                        </div>
                        
                        <div class="section">
                            <h2>⚡ 连接信息</h2>
                            <div class="link-box">
                                <p><strong>UUID:</strong> ${password}</p>
                                <p><strong>当前proxyIP:</strong> ${proxyIP}</p>
                                <p><strong>WebSocket路径:</strong> /${SSpath}/?ed=2560</p>
                                <p><strong>自定义连接:</strong> /${SSpath}/?ed=2560&proxyip=你的IP</p>
                            </div>
                        </div>
                    </div>
                    
                    <script>
                    function copyToClipboard(text) {
                        const textarea = document.createElement('textarea');
                        textarea.value = text;
                        document.body.appendChild(textarea);
                        textarea.select();
                        document.execCommand('copy');
                        document.body.removeChild(textarea);
                        alert('已复制到剪贴板！');
                    }
                    </script>
                    </body></html>`;
                    
                    return new Response(html, {
                        status: 200,
                        headers: {
                            'Content-Type': 'text/html;charset=utf-8',
                            'Cache-Control': 'no-cache, no-store, must-revalidate',
                        },
                    });
                }
                
                // 订阅页面
                if (url.pathname.toLowerCase() === `/sub/${subPath.toLowerCase()}` || url.pathname.toLowerCase() === `/sub/${subPath.toLowerCase()}/`) {
                    const currentDomain = url.hostname;
                    const ssHeader = 's'+'s';
                    
                    // 生成订阅链接 - 关键修改部分
                    const ssLinks = cfip.map(cfipItem => {
                        const { host, port, name } = parseCFIPItem(cfipItem);
                        const ssConfig = `${method}:${password}`;
                        const encodedConfig = btoa(ssConfig);
                        const nodeName = name || '节点'; // 只显示地区名称，不显示SS-前缀
                        
                        // 关键：使用当前优选IP作为proxyip参数
                        const proxyipParam = `${host}:${port}`;
                        
                        return `${ssHeader}://${encodedConfig}@${host}:${port}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${currentDomain};path%3D${validPath}/?ed%3D2560%26proxyip%3D${encodeURIComponent(proxyipParam)};tls;sni%3D${currentDomain};skip-cert-verify%3Dtrue;mux%3D0#${nodeName}`;
                    });
                    
                    const linksText = ssLinks.join('\n');
                    const base64Content = btoa(unescape(encodeURIComponent(linksText)));
                    
                    return new Response(base64Content, {
                        headers: { 
                            'Content-Type': 'text/plain; charset=utf-8',
                            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                        },
                    });
                }
            }
            
            return new Response('Not Found', { status: 404 });
            
        } catch (err) {
            return new Response('Internal Server Error', { status: 500 });
        }
    },
};
