import { connect } from 'cloudflare:sockets';

export default {
	async fetch(req, env) {
		// ========== 基础配置 ==========
		const UUID = env.UUID || '757e052c-4159-491d-bc5d-1b6bd866d980';

		const url = new URL(req.url);

		// ========== 订阅生成 ==========
		if (url.pathname === '/sub') {
			let preferredIPs = [];
			try {
				preferredIPs = await loadPreferredIPs();
			} catch (e) {
				return new Response('Failed to load IP list', { status: 500 });
			}
			return generateSubscription(req, UUID, preferredIPs);
		}

		// ========== WebSocket 处理 ==========
		if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
			const [client, ws] = Object.values(new WebSocketPair());
			ws.accept();

			const u = new URL(req.url);

			if (u.pathname.includes('%3F')) {
				const decoded = decodeURIComponent(u.pathname);
				const idx = decoded.indexOf('?');
				if (idx !== -1) {
					u.search = decoded.slice(idx);
					u.pathname = decoded.slice(0, idx);
				}
			}

			const mode = u.searchParams.get('mode') || 'auto';
			const s5Param = u.searchParams.get('s5');
			const proxyParam = u.searchParams.get('proxyip');
			const path = s5Param ? s5Param : u.pathname.slice(1);

			const socks5 = path.includes('@') ? (() => {
				const [cred, server] = path.split('@');
				const [user, pass] = cred.split(':');
				const [host, port = 443] = server.split(':');
				return { user, pass, host, port: +port };
			})() : null;

			const PROXY_IP = proxyParam ? String(proxyParam) : null;

			const getOrder = () => {
				if (mode === 'proxy') return ['direct', 'proxy'];
				if (mode !== 'auto') return [mode];
				const order = [];
				for (const p of u.search.slice(1).split('&')) {
					const k = p.split('=')[0];
					if (k === 'direct') order.push('direct');
					else if (k === 's5') order.push('s5');
					else if (k === 'proxyip') order.push('proxy');
				}
				return order.length ? order : ['direct'];
			};

			let remote = null;
			let udpWriter = null;
			let isDNS = false;

			const socks5Connect = async (host, port) => {
				const sock = connect({ hostname: socks5.host, port: socks5.port });
				await sock.opened;
				const w = sock.writable.getWriter();
				const r = sock.readable.getReader();

				await w.write(new Uint8Array([5, 2, 0, 2]));
				const auth = (await r.read()).value;

				if (auth[1] === 2 && socks5.user) {
					const u = new TextEncoder().encode(socks5.user);
					const p = new TextEncoder().encode(socks5.pass);
					await w.write(new Uint8Array([1, u.length, ...u, p.length, ...p]));
					await r.read();
				}

				const d = new TextEncoder().encode(host);
				await w.write(new Uint8Array([5, 1, 0, 3, d.length, ...d, port >> 8, port & 0xff]));
				await r.read();

				w.releaseLock();
				r.releaseLock();
				return sock;
			};

			new ReadableStream({
				start(ctrl) {
					ws.onmessage = e => ctrl.enqueue(e.data);
					ws.onclose = () => { remote?.close(); ctrl.close(); };
					ws.onerror = () => { remote?.close(); ctrl.error(); };

					const early = req.headers.get('sec-websocket-protocol');
					if (early) {
						try {
							ctrl.enqueue(Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)));
						} catch {}
					}
				}
			}).pipeTo(new WritableStream({
				async write(data) {
					if (isDNS) return udpWriter?.write(data);
					if (remote) {
						const w = remote.writable.getWriter();
						await w.write(data);
						w.releaseLock();
						return;
					}
					if (data.byteLength < 24) return;

					const uuidBytes = new Uint8Array(data.slice(1, 17));
					const uuidHex = UUID.replace(/-/g, '');
					for (let i = 0; i < 16; i++) {
						if (uuidBytes[i] !== parseInt(uuidHex.substr(i * 2, 2), 16)) return;
					}

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
						addr = `${view.getUint8(pos)}.${view.getUint8(pos+1)}.${view.getUint8(pos+2)}.${view.getUint8(pos+3)}`;
						pos += 4;
					} else if (type === 2) {
						const len = view.getUint8(pos++);
						addr = new TextDecoder().decode(data.slice(pos, pos + len));
						pos += len;
					} else return;

					const header = new Uint8Array([data[0], 0]);
					const payload = data.slice(pos);

					let sock = null;
					for (const m of getOrder()) {
						try {
							if (m === 'direct') {
								sock = connect({ hostname: addr, port });
								await sock.opened;
								break;
							}
							if (m === 's5' && socks5) {
								sock = await socks5Connect(addr, port);
								break;
							}
							if (m === 'proxy' && PROXY_IP) {
								const [h, p = port] = PROXY_IP.split(':');
								sock = connect({ hostname: h, port: +p || port });
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

					let sent = false;
					sock.readable.pipeTo(new WritableStream({
						write(chunk) {
							ws.readyState === 1 &&
								ws.send(sent ? chunk : new Uint8Array([...header, ...new Uint8Array(chunk)]));
							sent = true;
						}
					})).catch(() => {});
				}
			}));

			return new Response(null, { status: 101, webSocket: client });
		}

		url.hostname = 'example.com';
		return fetch(new Request(url, req));
	}
};

// ========== 从 GitHub 读取 IP ==========
async function loadPreferredIPs() {
	const res = await fetch(
		'https://raw.githubusercontent.com/hanhande221/node-Cloudflare/main/ip.txt',
		{ headers: { 'cache-control': 'no-cache' } }
	);
	if (!res.ok) throw new Error('IP list load failed');
	return (await res.text())
		.split('\n')
		.map(l => l.trim())
		.filter(l => l && !l.startsWith('//') && !l.startsWith('#'));
}

// ========== 订阅生成 ==========
function generateSubscription(req, uuid, ips) {
	const host = new URL(req.url).hostname;
	const nodes = ips.map(cfg => {
		const [ipPort, tag] = cfg.split('#');
		const [ip, port] = ipPort.split(':');
		return `vless://${uuid}@${ip}:${port}?encryption=none&security=tls&type=ws&host=${host}&path=${encodeURIComponent('/?mode=auto&direct&proxyip=' + ipPort)}#${encodeURIComponent(tag || ip)}`;
	});
	return new Response(btoa(nodes.join('\n')), {
		headers: {
			'Content-Type': 'text/plain;charset=utf-8',
			'Profile-Update-Interval': '24'
		}
	});
}
