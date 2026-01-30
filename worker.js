import { connect } from 'cloudflare:sockets';

// ==================== 配置区 ====================
const CONFIG = {
	uuid: '757e052c-4159-491d-bc5d-1b6bd866d980',
	
	// ProxyIP 中转服务器
	proxyIP: 'proxy.xxxxxxxx.tk:50001',
	
	// SOCKS5 代理服务器（格式: 'user:pass@host:port' 或 'host:port'）
	socks5: '107.182.173.176:1080',
	
	dnsServer: 'https://1.1.1.1/dns-query',
	
	// 优选IP列表 - 支持多节点
	proxyNodes: [
		{ ip: '103.238.129.84', port: 8443, name: 'JP' },
		{ ip: '141.193.213.21', port: 443, name: 'HK' },
		{ ip: '199.34.228.41', port: 443, name: 'SB' }
	],
	
	// 默认连接顺序：优选IP直连 → ProxyIP → SOCKS5
	defaultConnectionOrder: ['direct', 'proxy', 's5']
};

// ==================== 订阅生成器 ====================
class SubscriptionGenerator {
	constructor(hostname, config) {
		this.hostname = hostname;
		this.config = config;
	}

	generateVlessConfig(node) {
		const params = new URLSearchParams({
			encryption: 'none',
			type: 'ws',
			host: this.hostname,
			path: this.buildPath(node),
			security: 'tls',
			sni: this.hostname,
			fp: 'chrome',
			alpn: 'h2,http/1.1'
		});

		const vlessUrl = `vless://${this.config.uuid}@${node.ip}:${node.port}?${params.toString()}#${encodeURIComponent(node.name)}`;
		
		return vlessUrl;
	}

	buildPath(node) {
		const params = new URLSearchParams();
		params.set('mode', 'auto');
		
		// 按照默认连接顺序添加参数
		// 优选IP直连
		params.set('proxyip', `${node.ip}:${node.port}`);
		
		// ProxyIP（如果配置）
		if (this.config.proxyIP) {
			// ProxyIP 作为第二选择，已通过proxyip参数设置
		}
		
		// SOCKS5（如果配置）
		if (this.config.socks5) {
			params.set('s5', this.config.socks5);
		}
		
		// 直连标记
		params.set('direct', '');
		
		return `/?${params.toString()}`;
	}

	generateAll() {
		const vlessConfigs = this.config.proxyNodes.map(node => 
			this.generateVlessConfig(node)
		);
		
		// 将所有节点配置合并，用换行符分隔，然后 Base64 编码
		return btoa(vlessConfigs.join('\n'));
	}

	generateSingle(nodeName) {
		const node = this.config.proxyNodes.find(n => n.name === nodeName);
		if (!node) return null;
		
		return btoa(this.generateVlessConfig(node));
	}
}

// ==================== 连接管理器 ====================
class ConnectionManager {
	constructor(config) {
		this.config = config;
		this.socks5Config = this.parseSocks5(config.socks5);
		this.proxyConfig = this.parseProxy(config.proxyIP);
	}

	parseSocks5(s5String) {
		if (!s5String) return null;
		
		// 移除 socks5:// 前缀（如果有）
		const cleaned = s5String.replace(/^socks5:\/\//, '');
		
		// 支持两种格式：
		// 1. user:pass@host:port （带认证）
		// 2. host:port （无认证）
		if (cleaned.includes('@')) {
			const [credentials, server] = cleaned.split('@');
			const [user, pass] = credentials.split(':');
			const [host, port = '1080'] = server.split(':');
			return { user, pass, host, port: parseInt(port) };
		} else {
			const [host, port = '1080'] = cleaned.split(':');
			return { user: null, pass: null, host, port: parseInt(port) };
		}
	}

	parseProxy(proxyString) {
		if (!proxyString) return null;
		
		const [host, port = '443'] = proxyString.split(':');
		return { host, port: parseInt(port) };
	}

	async connectSocks5(targetHost, targetPort) {
		if (!this.socks5Config) throw new Error('SOCKS5 not configured');
		
		const socket = connect({
			hostname: this.socks5Config.host,
			port: this.socks5Config.port
		});
		
		await socket.opened;
		
		const writer = socket.writable.getWriter();
		const reader = socket.readable.getReader();
		
		// 认证协商（支持无认证和用户名密码认证）
		const authMethods = this.socks5Config.user ? [5, 2, 0, 2] : [5, 1, 0];
		await writer.write(new Uint8Array(authMethods));
		const authResponse = (await reader.read()).value;
		
		// 用户名密码认证（如果需要）
		if (authResponse[1] === 2 && this.socks5Config.user) {
			const userBytes = new TextEncoder().encode(this.socks5Config.user);
			const passBytes = new TextEncoder().encode(this.socks5Config.pass);
			await writer.write(new Uint8Array([
				1, 
				userBytes.length, ...userBytes, 
				passBytes.length, ...passBytes
			]));
			await reader.read();
		}
		
		// 连接请求
		const domainBytes = new TextEncoder().encode(targetHost);
		await writer.write(new Uint8Array([
			5, 1, 0, 3, 
			domainBytes.length, ...domainBytes,
			targetPort >> 8, targetPort & 0xff
		]));
		await reader.read();
		
		writer.releaseLock();
		reader.releaseLock();
		
		return socket;
	}

	async connectDirect(host, port) {
		const socket = connect({ hostname: host, port });
		await socket.opened;
		return socket;
	}

	async connectProxy(targetHost, targetPort) {
		if (!this.proxyConfig) throw new Error('Proxy not configured');
		
		const socket = connect({
			hostname: this.proxyConfig.host,
			port: this.proxyConfig.port
		});
		await socket.opened;
		return socket;
	}

	async connect(host, port, methods) {
		for (const method of methods) {
			try {
				switch (method) {
					case 'direct':
						return await this.connectDirect(host, port);
					case 's5':
						if (this.socks5Config) {
							return await this.connectSocks5(host, port);
						}
						break;
					case 'proxy':
						if (this.proxyConfig) {
							return await this.connectProxy(host, port);
						}
						break;
				}
			} catch (error) {
				continue; // 尝试下一个方法
			}
		}
		return null;
	}
}

// ==================== 协议处理器 ====================
class ProtocolHandler {
	constructor(websocket, connectionManager, uuid) {
		this.ws = websocket;
		this.cm = connectionManager;
		this.uuid = uuid;
		this.remote = null;
		this.udpWriter = null;
		this.isDNS = false;
	}

	verifyUUID(data) {
		const uuidBytes = new Uint8Array(data.slice(1, 17));
		const expectedUUID = this.uuid.replace(/-/g, '');
		
		for (let i = 0; i < 16; i++) {
			const expected = parseInt(expectedUUID.substr(i * 2, 2), 16);
			if (uuidBytes[i] !== expected) return false;
		}
		
		return true;
	}

	parseAddress(data, view, position) {
		const addressType = view.getUint8(position + 2);
		let pos = position + 3;
		let address = '';

		switch (addressType) {
			case 1: // IPv4
				address = [0, 1, 2, 3]
					.map(i => view.getUint8(pos + i))
					.join('.');
				pos += 4;
				break;
			
			case 2: // Domain
				const domainLength = view.getUint8(pos++);
				address = new TextDecoder().decode(data.slice(pos, pos + domainLength));
				pos += domainLength;
				break;
			
			case 3: // IPv6
				const ipv6Parts = [];
				for (let i = 0; i < 8; i++, pos += 2) {
					ipv6Parts.push(view.getUint16(pos).toString(16));
				}
				address = ipv6Parts.join(':');
				break;
			
			default:
				return null;
		}

		return { address, nextPosition: pos };
	}

	async handleDNS(port, payload, header) {
		if (port !== 53) return;
		
		this.isDNS = true;
		let headerSent = false;

		const { readable, writable } = new TransformStream({
			transform(chunk, controller) {
				let offset = 0;
				while (offset < chunk.byteLength) {
					const length = new DataView(chunk.slice(offset, offset + 2)).getUint16(0);
					controller.enqueue(chunk.slice(offset + 2, offset + 2 + length));
					offset += 2 + length;
				}
			}
		});

		readable.pipeTo(new WritableStream({
			async write(query) {
				try {
					const response = await fetch(CONFIG.dnsServer, {
						method: 'POST',
						headers: { 'content-type': 'application/dns-message' },
						body: query
					});

					if (this.ws.readyState === 1) {
						const result = new Uint8Array(await response.arrayBuffer());
						const packet = new Uint8Array([
							...(headerSent ? [] : header),
							result.length >> 8,
							result.length & 0xff,
							...result
						]);
						this.ws.send(packet);
						headerSent = true;
					}
				} catch (error) {
					// 静默处理DNS错误
				}
			}
		}));

		this.udpWriter = writable.getWriter();
		return this.udpWriter.write(payload);
	}

	async handleTCP(address, port, payload, header, connectionMethods) {
		const socket = await this.cm.connect(address, port, connectionMethods);
		
		if (!socket) return;

		this.remote = socket;
		
		// 发送初始数据
		const writer = socket.writable.getWriter();
		await writer.write(payload);
		writer.releaseLock();

		// 处理响应数据
		let headerSent = false;
		socket.readable.pipeTo(new WritableStream({
			write: (chunk) => {
				if (this.ws.readyState === 1) {
					const packet = headerSent 
						? chunk 
						: new Uint8Array([...header, ...new Uint8Array(chunk)]);
					this.ws.send(packet);
					headerSent = true;
				}
			},
			close: () => this.ws.readyState === 1 && this.ws.close(),
			abort: () => this.ws.readyState === 1 && this.ws.close()
		})).catch(() => {});
	}

	async processData(data, connectionMethods) {
		// UDP DNS 处理
		if (this.isDNS) {
			return this.udpWriter?.write(data);
		}

		// 已建立连接的数据转发
		if (this.remote) {
			const writer = this.remote.writable.getWriter();
			await writer.write(data);
			writer.releaseLock();
			return;
		}

		// 数据包太小，忽略
		if (data.byteLength < 24) return;

		// UUID 验证
		if (!this.verifyUUID(data)) return;

		// 解析请求
		const view = new DataView(data);
		const optionLength = view.getUint8(17);
		const command = view.getUint8(18 + optionLength);

		// 只支持 TCP 和 UDP
		if (command !== 1 && command !== 2) return;

		// 解析地址和端口
		let position = 19 + optionLength;
		const port = view.getUint16(position);
		
		const addressInfo = this.parseAddress(data, view, position);
		if (!addressInfo) return;

		const header = new Uint8Array([data[0], 0]);
		const payload = data.slice(addressInfo.nextPosition);

		// 根据命令类型处理
		if (command === 2) {
			await this.handleDNS(port, payload, header);
		} else {
			await this.handleTCP(addressInfo.address, port, payload, header, connectionMethods);
		}
	}
}

// ==================== 工具函数 ====================
function parseURLParameters(url) {
	const u = new URL(url);
	
	// 处理 URL 编码的查询参数
	if (u.pathname.includes('%3F')) {
		const decoded = decodeURIComponent(u.pathname);
		const queryIndex = decoded.indexOf('?');
		if (queryIndex !== -1) {
			u.search = decoded.substring(queryIndex);
			u.pathname = decoded.substring(0, queryIndex);
		}
	}

	const mode = u.searchParams.get('mode') || 'auto';
	const s5Param = u.searchParams.get('s5');
	const proxyParam = u.searchParams.get('proxyip');
	const pathParam = s5Param || u.pathname.slice(1);

	return { mode, s5Param, proxyParam, pathParam, searchParams: u.searchParams };
}

function getConnectionOrder(mode, searchParams) {
	// 如果指定了proxy模式，使用传统顺序
	if (mode === 'proxy') return ['direct', 'proxy'];
	
	// 如果指定了特定模式，只使用该模式
	if (mode !== 'auto') return [mode];

	// auto模式：检查URL参数来确定顺序
	const order = [];
	const searchString = searchParams.toString();
	
	for (const [key] of searchParams) {
		if (key === 'direct') order.push('direct');
		else if (key === 's5') order.push('s5');
		else if (key === 'proxyip') order.push('proxy');
	}

	// 如果URL中没有指定顺序，使用默认顺序：direct → proxy → s5
	return order.length ? order : CONFIG.defaultConnectionOrder;
}

function decodeEarlyData(protocolHeader) {
	if (!protocolHeader) return null;
	
	try {
		const base64 = protocolHeader.replace(/-/g, '+').replace(/_/g, '/');
		return Uint8Array.from(atob(base64), c => c.charCodeAt(0)).buffer;
	} catch {
		return null;
	}
}

// ==================== 主处理函数 ====================
async function handleWebSocket(request, env) {
	const uuid = env.UUID || CONFIG.uuid;
	const [client, server] = Object.values(new WebSocketPair());
	server.accept();

	const params = parseURLParameters(request.url);
	
	// 获取默认优选IP（第一个节点）
	const defaultNode = CONFIG.proxyNodes[0];
	const defaultProxyIP = `${defaultNode.ip}:${defaultNode.port}`;
	
	// 更新配置
	const runtimeConfig = {
		uuid,
		proxyIP: CONFIG.proxyIP, // 使用配置的 ProxyIP 中转服务器
		socks5: params.s5Param || CONFIG.socks5, // SOCKS5 配置
		proxyNodes: CONFIG.proxyNodes
	};

	const connectionManager = new ConnectionManager(runtimeConfig);
	const protocolHandler = new ProtocolHandler(server, connectionManager, uuid);
	const connectionMethods = getConnectionOrder(params.mode, params.searchParams);

	// 创建数据流
	const incomingStream = new ReadableStream({
		start(controller) {
			server.addEventListener('message', e => controller.enqueue(e.data));
			server.addEventListener('close', () => {
				protocolHandler.remote?.close();
				controller.close();
			});
			server.addEventListener('error', () => {
				protocolHandler.remote?.close();
				controller.error();
			});

			// 处理 early data
			const earlyData = decodeEarlyData(request.headers.get('sec-websocket-protocol'));
			if (earlyData) controller.enqueue(earlyData);
		}
	});

	// 处理数据流
	incomingStream.pipeTo(new WritableStream({
		async write(data) {
			await protocolHandler.processData(data, connectionMethods);
		}
	})).catch(() => {});

	return new Response(null, {
		status: 101,
		webSocket: client
	});
}

function handleSubscription(request) {
	const url = new URL(request.url);
	const generator = new SubscriptionGenerator(url.hostname, CONFIG);
	
	// 支持单节点订阅：/sub?node=HK
	const nodeName = url.searchParams.get('node');
	const subscription = nodeName 
		? generator.generateSingle(nodeName) 
		: generator.generateAll();
	
	if (!subscription) {
		return new Response('节点不存在', { status: 404 });
	}
	
	return new Response(subscription, {
		headers: {
			'Content-Type': 'text/plain;charset=utf-8',
			'Cache-Control': 'no-store',
			'Content-Disposition': 'attachment; filename=vless-subscription.txt'
		}
	});
}

function handleDefault(request) {
	const url = new URL(request.url);
	url.hostname = 'www.cloudflare.com';
	return fetch(new Request(url, request));
}

// ==================== 入口 ====================
export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		
		// 订阅路径
		if (url.pathname === '/sub' || url.pathname === '/subscribe') {
			return handleSubscription(request);
		}
		
		// WebSocket 升级
		if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
			return handleWebSocket(request, env);
		}
		
		// 默认处理
		return handleDefault(request);
	}
};
