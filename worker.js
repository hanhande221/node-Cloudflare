import { connect } from 'cloudflare:sockets';

// ==================== 配置区 ====================
const CONFIG = {
	uuid: '757e052c-4159-491d-bc5d-1b6bd866d980',
	
	// ProxyIP 中转服务器 (可留空表示不使用)
	proxyIP: 'proxyip.us.cmliussss.net:443',
	
	dnsServer: 'https://1.1.1.1/dns-query',
	
	// 优选IP列表 - 支持多节点 (可随时修改)
	proxyNodes: [
		{ ip: '103.238.129.84', port: 8443, name: 'JP' },
		{ ip: '141.193.213.21', port: 443, name: 'HK' },
		{ ip: '199.34.228.41', port: 443, name: 'SB' }
	]
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
			path: '/',
			security: 'tls',
			sni: this.hostname,
			fp: 'random',
			alpn: 'h2,http/1.1'
		});

		const vlessUrl = `vless://${this.config.uuid}@${node.ip}:${node.port}?${params.toString()}#${encodeURIComponent(node.name)}`;
		
		return vlessUrl;
	}

	generateAll() {
		const vlessConfigs = this.config.proxyNodes.map(node => 
			this.generateVlessConfig(node)
		);
		
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
		this.proxyConfig = this.parseProxy(config.proxyIP);
	}

	parseProxy(proxyString) {
		if (!proxyString) return null;
		
		const [host, port = '443'] = proxyString.split(':');
		return { host, port: parseInt(port) };
	}

	async connectDirect(host, port) {
		const socket = connect({ hostname: host, port });
		await socket.opened;
		return socket;
	}

	async connectProxy(targetHost, targetPort) {
		if (!this.proxyConfig) throw new Error('Proxy not configured');
		
		// 通过 ProxyIP 中转连接目标
		const socket = connect({
			hostname: this.proxyConfig.host,
			port: this.proxyConfig.port
		});
		await socket.opened;
		
		// ProxyIP 通常需要发送目标地址信息
		const writer = socket.writable.getWriter();
		const targetInfo = new TextEncoder().encode(`${targetHost}:${targetPort}\r\n`);
		await writer.write(targetInfo);
		writer.releaseLock();
		
		return socket;
	}

	async connect(host, port) {
		// 连接顺序: 直连 → ProxyIP
		const methods = [
			{ name: 'direct', fn: () => this.connectDirect(host, port) },
			{ name: 'proxy', fn: () => this.proxyConfig ? this.connectProxy(host, port) : null }
		];

		for (const method of methods) {
			try {
				const socket = await method.fn();
				if (socket) return socket;
			} catch (error) {
				console.log(`${method.name} failed:`, error.message);
				continue;
			}
		}
		
		throw new Error('All connection methods failed');
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

		const self = this;
		readable.pipeTo(new WritableStream({
			async write(query) {
				try {
					const response = await fetch(CONFIG.dnsServer, {
						method: 'POST',
						headers: { 'content-type': 'application/dns-message' },
						body: query
					});

					if (self.ws.readyState === 1) {
						const result = new Uint8Array(await response.arrayBuffer());
						const packet = new Uint8Array([
							...(headerSent ? [] : header),
							result.length >> 8,
							result.length & 0xff,
							...result
						]);
						self.ws.send(packet);
						headerSent = true;
					}
				} catch (error) {
					// 静默处理DNS错误
				}
			}
		})).catch(() => {});

		this.udpWriter = writable.getWriter();
		return this.udpWriter.write(payload);
	}

	async handleTCP(address, port, payload, header) {
		try {
			const socket = await this.cm.connect(address, port);
			
			if (!socket) return;

			this.remote = socket;
			
			// 发送初始数据
			const writer = socket.writable.getWriter();
			await writer.write(payload);
			writer.releaseLock();

			// 处理响应数据
			let headerSent = false;
			const self = this;
			socket.readable.pipeTo(new WritableStream({
				write: (chunk) => {
					if (self.ws.readyState === 1) {
						const packet = headerSent 
							? chunk 
							: new Uint8Array([...header, ...new Uint8Array(chunk)]);
						self.ws.send(packet);
						headerSent = true;
					}
				},
				close: () => self.ws.readyState === 1 && self.ws.close(),
				abort: () => self.ws.readyState === 1 && self.ws.close()
			})).catch(() => {});
		} catch (error) {
			console.log('TCP connection error:', error.message);
			if (this.ws.readyState === 1) {
				this.ws.close();
			}
		}
	}

	async processData(data) {
		// UDP DNS 处理
		if (this.isDNS) {
			return this.udpWriter?.write(data);
		}

		// 已建立连接的数据转发
		if (this.remote) {
			try {
				const writer = this.remote.writable.getWriter();
				await writer.write(data);
				writer.releaseLock();
			} catch (error) {
				// 连接已关闭
			}
			return;
		}

		// 数据包太小,忽略
		if (data.byteLength < 24) return;

		// UUID 验证
		if (!this.verifyUUID(data)) {
			console.log('UUID verification failed');
			return;
		}

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
			await this.handleTCP(addressInfo.address, port, payload, header);
		}
	}
}

// ==================== 工具函数 ====================
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

	const runtimeConfig = {
		uuid,
		proxyIP: CONFIG.proxyIP,
		proxyNodes: CONFIG.proxyNodes
	};

	const connectionManager = new ConnectionManager(runtimeConfig);
	const protocolHandler = new ProtocolHandler(server, connectionManager, uuid);

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
			await protocolHandler.processData(data);
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
	
	// 支持单节点订阅: /sub?node=HK
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
