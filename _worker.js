import { connect } from 'cloudflare:sockets';

export default {
	async fetch(req, env) {
		// ========== 配置区域 ==========
		// UUID 配置（从环境变量读取，或使用默认值）
		const UUID = env.UUID || '757e052c-4159-491d-bc5d-1b6bd866d980';
		
		// 优选 IP 列表（格式：IP:端口#地区标识）
		// 这些 IP 可以用作 ProxyIP，也会出现在订阅中
		const PREFERRED_IPS = [
			'proxyip.us.cmliussss.net:443#US',
			'proxyip.jp.cmliussss.net:443#JP',
			'proxyip.hk.cmliussss.net:443#HK'
			// 可以继续添加更多优选IP
			// '1.2.3.4:443#HKG',
			// '5.6.7.8:2096#SIN',
		];
		
		// ========== 订阅生成处理 ==========
		// 检查是否访问 /sub 路径，生成订阅内容
		const url = new URL(req.url);
		if (url.pathname === '/sub') {
			return generateSubscription(req, UUID, PREFERRED_IPS);
		}

		// ========== WebSocket 连接处理 ==========
		// 检查是否是 WebSocket 升级请求
		if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
			// 创建 WebSocket 对
			const [client, ws] = Object.values(new WebSocketPair());
			ws.accept();

			const u = new URL(req.url);

			// 修复处理 URL 编码的查询参数
			// 处理类似 /path%3Fkey=value 这样的编码URL
			if (u.pathname.includes('%3F')) {
				const decoded = decodeURIComponent(u.pathname);
				const queryIndex = decoded.indexOf('?');
				if (queryIndex !== -1) {
					u.search = decoded.substring(queryIndex);
					u.pathname = decoded.substring(0, queryIndex);
				}
			}

			// ========== 解析连接参数 ==========
			// mode: 连接模式（auto/direct/s5/proxy）
			const mode = u.searchParams.get('mode') || 'auto';
			// s5: SOCKS5 代理参数
			const s5Param = u.searchParams.get('s5');
			// proxyip: ProxyIP 参数（可以使用优选IP）
			const proxyParam = u.searchParams.get('proxyip');
			// 从路径或s5参数获取配置
			const path = s5Param ? s5Param : u.pathname.slice(1);

			// ========== 解析 SOCKS5 配置 ==========
			// 格式：username:password@host:port
			const socks5 = path.includes('@') ? (() => {
				const [cred, server] = path.split('@');
				const [user, pass] = cred.split(':');
				const [host, port = 443] = server.split(':');
				return {
					user,
					pass,
					host,
					port: +port
				};
			})() : null;

			// ========== 解析 ProxyIP 配置 ==========
			// ProxyIP 可以是普通IP或优选IP
			const PROXY_IP = proxyParam ? String(proxyParam) : null;

			// ========== 确定连接顺序 ==========
			// auto 模式：按 URL 参数顺序尝试连接
			// proxy 模式：先 direct 后 proxy
			// 其他模式：单一模式
			const getOrder = () => {
				if (mode === 'proxy') return ['direct', 'proxy'];
				if (mode !== 'auto') return [mode];
				
				const order = [];
				const searchStr = u.search.slice(1);
				// 按参数出现顺序添加连接方式
				for (const pair of searchStr.split('&')) {
					const key = pair.split('=')[0];
					if (key === 'direct') order.push('direct');
					else if (key === 's5') order.push('s5');
					else if (key === 'proxyip') order.push('proxy');
				}
				// 没有参数时默认 direct
				return order.length ? order : ['direct'];
			};

			// ========== 连接状态变量 ==========
			let remote = null;      // 远程连接对象
			let udpWriter = null;   // UDP 写入器（用于DNS）
			let isDNS = false;      // 是否是 DNS 请求

			// ========== SOCKS5 连接函数 ==========
			const socks5Connect = async (targetHost, targetPort) => {
				// 连接到 SOCKS5 服务器
				const sock = connect({
					hostname: socks5.host,
					port: socks5.port
				});
				await sock.opened;

				const w = sock.writable.getWriter();
				const r = sock.readable.getReader();

				// 发送认证方法（支持无认证和用户名密码）
				await w.write(new Uint8Array([5, 2, 0, 2]));
				const auth = (await r.read()).value;

				// 如果需要用户名密码认证
				if (auth[1] === 2 && socks5.user) {
					const user = new TextEncoder().encode(socks5.user);
					const pass = new TextEncoder().encode(socks5.pass);
					await w.write(new Uint8Array([1, user.length, ...user, pass.length, ...pass]));
					await r.read();
				}

				// 发送连接请求（域名类型）
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
			// 创建可读流，接收 WebSocket 消息
			new ReadableStream({
				start(ctrl) {
					// 监听 WebSocket 消息
					ws.addEventListener('message', e => ctrl.enqueue(e.data));
					// 监听 WebSocket 关闭
					ws.addEventListener('close', () => {
						remote?.close();
						ctrl.close();
					});
					// 监听 WebSocket 错误
					ws.addEventListener('error', () => {
						remote?.close();
						ctrl.error();
					});

					// 处理早期数据（通过 sec-websocket-protocol 头传递）
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
					// 检查数据长度
					if (data.byteLength < 24) return;

					// UUID 验证（确保请求来自授权客户端）
					const uuidBytes = new Uint8Array(data.slice(1, 17));
					const expectedUUID = UUID.replace(/-/g, '');
					for (let i = 0; i < 16; i++) {
						if (uuidBytes[i] !== parseInt(expectedUUID.substr(i * 2, 2), 16)) return;
					}

					// ========== 解析 VLESS 协议头 ==========
					const view = new DataView(data);
					const optLen = view.getUint8(17);           // 附加选项长度
					const cmd = view.getUint8(18 + optLen);     // 命令类型（1=TCP, 2=UDP）
					if (cmd !== 1 && cmd !== 2) return;

					// 解析目标地址和端口
					let pos = 19 + optLen;
					const port = view.getUint16(pos);           // 目标端口
					const type = view.getUint8(pos + 2);        // 地址类型（1=IPv4, 2=域名, 3=IPv6）
					pos += 3;

					let addr = '';
					if (type === 1) {
						// IPv4 地址
						addr = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
						pos += 4;
					} else if (type === 2) {
						// 域名
						const len = view.getUint8(pos++);
						addr = new TextDecoder().decode(data.slice(pos, pos + len));
						pos += len;
					} else if (type === 3) {
						// IPv6 地址
						const ipv6 = [];
						for (let i = 0; i < 8; i++, pos += 2) {
							ipv6.push(view.getUint16(pos).toString(16));
						}
						addr = ipv6.join(':');
					} else return;

					// 构造响应头和负载数据
					const header = new Uint8Array([data[0], 0]);
					const payload = data.slice(pos);

					// ========== UDP DNS 请求处理 ==========
					if (cmd === 2) {
						// 只处理 DNS 请求（端口 53）
						if (port !== 53) return;
						isDNS = true;
						let sent = false;

						// 创建转换流处理 DNS 消息
						const { readable, writable } = new TransformStream({
							transform(chunk, ctrl) {
								// 解析 DNS 消息（前2字节是长度）
								for (let i = 0; i < chunk.byteLength;) {
									const len = new DataView(chunk.slice(i, i + 2)).getUint16(0);
									ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
									i += 2 + len;
								}
							}
						});

						// 使用 Cloudflare DoH 处理 DNS 查询
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
					// 按顺序尝试不同的连接方式
					for (const method of getOrder()) {
						try {
							if (method === 'direct') {
								// 直连模式
								sock = connect({ hostname: addr, port });
								await sock.opened;
								break;
							} else if (method === 's5' && socks5) {
								// SOCKS5 代理模式
								sock = await socks5Connect(addr, port);
								break;
							} else if (method === 'proxy' && PROXY_IP) {
								// ProxyIP 模式（使用优选IP或自定义IP）
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

					// 如果所有方式都失败，放弃连接
					if (!sock) return;

					// 保存远程连接
					remote = sock;

					// 发送初始负载数据
					const w = sock.writable.getWriter();
					await w.write(payload);
					w.releaseLock();

					// ========== 数据转发（远程 -> WebSocket）==========
					let sent = false;
					sock.readable.pipeTo(new WritableStream({
						write(chunk) {
							if (ws.readyState === 1) {
								// 第一个包需要加上响应头
								ws.send(sent ? chunk : new Uint8Array([...header, ...new Uint8Array(chunk)]));
								sent = true;
							}
						},
						close: () => ws.readyState === 1 && ws.close(),
						abort: () => ws.readyState === 1 && ws.close()
					})).catch(() => {});
				}
			})).catch(() => {});

			// 返回 WebSocket 响应
			return new Response(null, {
				status: 101,
				webSocket: client
			});
		}

		// ========== 默认请求处理 ==========
		// 非 WebSocket 请求转发到示例站点
		url.hostname = 'example.com';
		return fetch(new Request(url, req));
	}
};

// ========== 订阅生成函数 ==========
function generateSubscription(req, uuid, preferredIPs) {
	const url = new URL(req.url);
	const host = url.hostname;
	
	// 生成订阅节点列表
	const nodes = [];
	
	// 为每个优选IP生成节点配置
	preferredIPs.forEach(ipConfig => {
		const [ipPort, remark] = ipConfig.split('#');
		const [ip, port] = ipPort.split(':');
		
		// 生成 VLESS 链接
		// 格式：vless://UUID@IP:PORT?参数#备注
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
	
	// 将订阅内容编码为 Base64
	const subscriptionContent = nodes.join('\n');
	const base64Content = btoa(subscriptionContent);
	
	// 返回订阅内容
	return new Response(base64Content, {
		headers: {
			'Content-Type': 'text/plain;charset=utf-8',
			'Profile-Update-Interval': '24',
			'Subscription-Userinfo': `upload=0; download=0; total=10737418240; expire=0`,
		}
	});
}
