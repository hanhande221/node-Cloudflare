import { connect } from 'cloudflare:sockets';

export default {
	async fetch(req, env) {
		// ========== 配置区域 ==========
		const UUID = env.UUID || '757e052c-4159-491d-bc5d-1b6bd866d980';
		
		const PREFERRED_IPS = [
			'104.18.5.101:443#一元机场',
			'141.193.213.21:443#邀请30%返利',
			'104.194.64.142:443#US',
			'207.148.99.230:443#JP',
			'43.160.202.33:443#SG',
			'112.119.8.12:443#HK',
			'221.158.168.29:50001#KR'
		];
		
		// ========== 订阅生成处理 ==========
		const url = new URL(req.url);
		if (url.pathname === '/sub') {
			return generateSubscription(req, UUID, PREFERRED_IPS);
		}

		// ========== WebSocket 连接处理 ==========
		if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
			const [client, ws] = Object.values(new WebSocketPair());
			ws.accept();

			const u = new URL(req.url);

			// 处理 URL 编码的查询参数
			if (u.pathname.includes('%3F')) {
				const decoded = decodeURIComponent(u.pathname);
				const queryIndex = decoded.indexOf('?');
				if (queryIndex !== -1) {
					u.search = decoded.substring(queryIndex);
					u.pathname = decoded.substring(0, queryIndex);
				}
			}

			// ========== 解析连接参数 ==========
			const mode = u.searchParams.get('mode') || 'auto';
			const s5Param = u.searchParams.get('s5');
			const proxyParam = u.searchParams.get('proxyip');
			const path = s5Param ? s5Param : u.pathname.slice(1);

			// ========== 解析 SOCKS5 配置 ==========
			const socks5 = path.includes('@') ? (() => {
				const [cred, server] = path.split('@');
				const [user, pass] = cred.split(':');
				const [host, port = 443] = server.split(':');
				return { user, pass, host, port: +port };
			})() : null;

			// ========== 解析 ProxyIP 配置 ==========
			const PROXY_IP = proxyParam ? String(proxyParam) : null;

			// ========== 确定连接顺序 ==========
			const getOrder = () => {
				if (mode === 'proxy') return ['direct', 'proxy'];
				if (mode !== 'auto') return [mode];
				
				const order = [];
				const searchStr = u.search.slice(1);
				for (const pair of searchStr.split('&')) {
					const key = pair.split('=')[0];
					if (key === 'direct') order.push('direct');
					else if (key === 's5') order.push('s5');
					else if (key === 'proxyip') order.push('proxy');
				}
				return order.length ? order : ['direct'];
			};

			// ========== 连接状态变量 ==========
			let remote = null;
			let udpWriter = null;
			let isDNS = false;

			// ========== SOCKS5 连接函数 ==========
			const socks5Connect = async (targetHost, targetPort) => {
				const sock = connect({
					hostname: socks5.host,
					port: socks5.port
				});
				await sock.opened;

				const w = sock.writable.getWriter();
				const r = sock.readable.getReader();

				await w.write(new Uint8Array([5, 2, 0, 2]));
				const auth = (await r.read()).value;

				if (auth[1] === 2 && socks5.user) {
					const user = new TextEncoder().encode(socks5.user);
					const pass = new TextEncoder().encode(socks5.pass);
					await w.write(new Uint8Array([1, user.length, ...user, pass.length, ...pass]));
					await r.read();
				}

				const domain = new TextEncoder().encode(targetHost);
				await w.write(new Uint8Array([
					5, 1, 0, 3, domain.length, ...domain,
					targetPort >> 8, targetPort & 0xff
				]));
				await r.read();

				w.releaseLock();
				r.releaseLock();
				return sock;
			};

			// ========== WebSocket 数据流处理 ==========
			new ReadableStream({
				start(ctrl) {
					ws.addEventListener('message', e => ctrl.enqueue(e.data));
					ws.addEventListener('close', () => {
						remote?.close();
						ctrl.close();
					});
					ws.addEventListener('error', () => {
						remote?.close();
						ctrl.error();
					});

					const early = req.headers.get('sec-websocket-protocol');
					if (early) {
						try {
							ctrl.enqueue(Uint8Array.from(
								atob(early.replace(/-/g, '+').replace(/_/g, '/')),
								c => c.charCodeAt(0)
							).buffer);
						} catch {}
					}
				}
			}).pipeTo(new WritableStream({
				async write(data) {
					// ========== DNS 请求处理 ==========
					if (isDNS) return udpWriter?.write(data);

					// ========== 已建立连接的数据转发 ==========
					if (remote) {
						const w = remote.writable.getWriter();
						await w.write(data);
						w.releaseLock();
						return;
					}

					// ========== 新连接建立 ==========
					if (data.byteLength < 24) return;

					// UUID 验证
					const uuidBytes = new Uint8Array(data.slice(1, 17));
					const expectedUUID = UUID.replace(/-/g, '');
					for (let i = 0; i < 16; i++) {
						if (uuidBytes[i] !== parseInt(expectedUUID.substr(i * 2, 2), 16)) return;
					}

					// ========== 解析 VLESS 协议头 ==========
					const view = new DataView(data);
					const optLen = view.getUint8(17);
					const cmd = view.getUint8(18 + optLen);
					if (cmd !== 1 && cmd !== 2) return;

					let pos = 19 + optLen;
					const port = view.getUint16(pos);
					const type = view.getUint8(pos + 2);
					pos += 3;

					let addr = '';
					if (type === 1) {
						addr = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
						pos += 4;
					} else if (type === 2) {
						const len = view.getUint8(pos++);
						addr = new TextDecoder().decode(data.slice(pos, pos + len));
						pos += len;
					} else if (type === 3) {
						const ipv6 = [];
						for (let i = 0; i < 8; i++, pos += 2) {
							ipv6.push(view.getUint16(pos).toString(16));
						}
						addr = ipv6.join(':');
					} else return;

					const header = new Uint8Array([data[0], 0]);
					const payload = data.slice(pos);

					// ========== UDP DNS 请求处理 ==========
					if (cmd === 2) {
						if (port !== 53) return;
						isDNS = true;
						let sent = false;

						const { readable, writable } = new TransformStream({
							transform(chunk, ctrl) {
								for (let i = 0; i < chunk.byteLength;) {
									const len = new DataView(chunk.slice(i, i + 2)).getUint16(0);
									ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
									i += 2 + len;
								}
							}
						});

						readable.pipeTo(new WritableStream({
							async write(query) {
								try {
									const resp = await fetch('https://1.1.1.1/dns-query', {
										method: 'POST',
										headers: { 'content-type': 'application/dns-message' },
										body: query
									});
									if (ws.readyState === 1) {
										const result = new Uint8Array(await resp.arrayBuffer());
										ws.send(new Uint8Array([
											...(sent ? [] : header),
											result.length >> 8,
											result.length & 0xff,
											...result
										]));
										sent = true;
									}
								} catch {}
							}
						}));

						udpWriter = writable.getWriter();
						return udpWriter.write(payload);
					}

					// ========== TCP 连接建立 ==========
					let sock = null;
					for (const method of getOrder()) {
						try {
							if (method === 'direct') {
								sock = connect({ hostname: addr, port });
								await sock.opened;
								break;
							} else if (method === 's5' && socks5) {
								sock = await socks5Connect(addr, port);
								break;
							} else if (method === 'proxy' && PROXY_IP) {
								const [ph, pp = port] = PROXY_IP.split(':');
								sock = connect({
									hostname: ph,
									port: +pp || port
								});
								await sock.opened;
								break;
							}
						} catch {}
					}

					if (!sock) return;
					remote = sock;

					const w = sock.writable.getWriter();
					await w.write(payload);
					w.releaseLock();

					// ========== 数据转发（远程 -> WebSocket）==========
					let sent = false;
					sock.readable.pipeTo(new WritableStream({
						write(chunk) {
							if (ws.readyState === 1) {
								ws.send(sent ? chunk : new Uint8Array([...header, ...new Uint8Array(chunk)]));
								sent = true;
							}
						},
						close: () => ws.readyState === 1 && ws.close(),
						abort: () => ws.readyState === 1 && ws.close()
					})).catch(() => {});
				}
			})).catch(() => {});

			return new Response(null, {
				status: 101,
				webSocket: client
			});
		}

		// ========== 默认请求处理 ==========
		url.hostname = 'example.com';
		return fetch(new Request(url, req));
	}
};

// ========== 订阅生成函数 ==========
function generateSubscription(req, uuid, preferredIPs) {
	const url = new URL(req.url);
	const host = url.hostname;
	
	const nodes = [];
	
	preferredIPs.forEach(ipConfig => {
		const [ipPort, remark] = ipConfig.split('#');
		const [ip, port] = ipPort.split(':');
		
		const vlessLink = `vless://${uuid}@${ip}:${port}?` +
			`encryption=none` +
			`&security=tls` +
			`&sni=${host}` +
			`&type=ws` +
			`&host=${host}` +
			`&path=${encodeURIComponent('/?mode=auto&direct&proxyip=' + ipPort)}` +
			`#${encodeURIComponent(remark || ip)}`;
		
		nodes.push(vlessLink);
	});
	
	const subscriptionContent = nodes.join('\n');
	const base64Content = btoa(subscriptionContent);
	
	// ========== 订阅信息配置（便于修改）==========
	const GB = 1024 * 1024 * 1024; // 1GB 的字节数
	const uploadGB = 9.9;           // 上传流量（GB）
	const downloadGB = 13.0;        // 下载流量（GB）
	const totalGB = 100;            // 总流量（GB）
	const expireDate = '2026-11-13'; // 过期日期
	
	const expireTimestamp = Math.floor(new Date(expireDate).getTime() / 1000);
	
	return new Response(base64Content, {
		headers: {
			'Content-Type': 'text/plain;charset=utf-8',
			'Profile-Update-Interval': '24',
			'Subscription-Userinfo': `upload=${Math.floor(uploadGB * GB)}; download=${Math.floor(downloadGB * GB)}; total=${totalGB * GB}; expire=${expireTimestamp}`,
		}
	});
}
