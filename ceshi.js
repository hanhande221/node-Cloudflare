const UUID = env.UUID || '757e052c-4159-491d-bc5d-1b6bd866d980';
		
		// 优选 IP 列表（格式：IP:端口#地区标识）
		// 这些 IP 可以用作 ProxyIP，也会出现在订阅中
		const PREFERRED_IPS = [
			'proxyip.us.cmliussss.net:443#US',
			'proxyip.jp.cmliussss.net:443#JP',
			'proxyip.hk.cmliussss.net:443#HK'
