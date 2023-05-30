'use strict';

let ubus = require('ubus');
let fs = require('fs');
let uci = require('uci').cursor();
let config = uci.get_all('uspot');
let nl = require("nl80211");

let file = fs.open('/usr/share/uspot/header', 'r');
let header = file.read('all');
file.close();

file = fs.open('/usr/share/uspot/footer', 'r');
let footer = file.read('all');
file.close();

let header_custom;
let footer_custom;

file = fs.open('/tmp/ucentral/www-uspot/header.html', 'r');
if (file) {
	header_custom = file.read('all');
	file.close();
}

file = fs.open('/tmp/ucentral/www-uspot/footer.html', 'r');
if (file) {
	footer_custom = file.read('all');
	file.close();
}

let devices = {};
uci.foreach('uspot', 'uspot', (d) => {
	function adddev(ifname, sname) {
		if (ifname in devices)
			warn('uspot: ignoring duplicate entry for ifname: "' + ifname + '"\n');
		else
			devices[ifname] = sname;
	}

	if (d[".anonymous"]) {
		warn('uspot: ignoring invalid anonymous section at index ' + d[".index"] + '\n');
		return;
	}

	let spotname = d[".name"];
	if (!d.ifname) {
		warn('uspot: missing ifname in section "' + spotname + '"\n');
		return;
	}

	if (type(d.ifname) == "array") {
		for (let n in d.ifname)
			adddev(n, spotname);
	}
	else
		adddev(d.ifname, spotname);
});

function lookup_station(mac) {
	let wifs = nl.request(nl.const.NL80211_CMD_GET_INTERFACE, nl.const.NLM_F_DUMP);
	for (let wif in wifs) {
		if (!(wif.ifname in devices))
			continue;
		let res = nl.request(nl.const.NL80211_CMD_GET_STATION, nl.const.NLM_F_DUMP, { dev: wif.ifname });
		for (let sta in res) {
			if (sta.mac != lc(mac))
				continue;
			return devices[wif.ifname]
		}
	}
}

function PO(id, english) {
	return english;
}

return {
	fs,
	rtnl: require('rtnl'),
	uam: require('uam'),
	uci,
	config,
	header,
	footer,

	// syslog helper
	syslog: function(ctx, msg) {
		warn('uspot: ' + ctx.env.REMOTE_ADDR + ' - ' + msg + '\n');
	},

	debug: function(ctx, msg) {
		if (+config.def_captive.debug)
			this.syslog(ctx, msg);
	},

	// session id generator
	session_init: function() {
		let math = require('math');
		let sessionid = '';

		for (let i = 0; i < 16; i++)
		        sessionid += sprintf('%d', math.rand() % 10);
		return sessionid;
	},

	// mac re-formater
	format_mac: function(format, mac) {
		switch(format) {
		case 'aabbccddeeff':
		case 'AABBCCDDEEFF':
			mac = replace(mac, ':', '');
			break;
		case 'aa-bb-cc-dd-ee-ff':
		case 'AA-BB-CC-DD-EE-FF':
			mac = replace(mac, ':', '-');
			break;
		}

		switch(format) {
		case 'aabbccddeeff':
		case 'aa-bb-cc-dd-ee-ff':
		case 'aa:bb:cc:dd:ee:ff':
			mac = lc(mac);
			break;
		case 'AABBCCDDEEFF':
		case 'AA:BB:CC:DD:EE:FF':
		case 'AA-BB-CC-DD-EE-FF':
			mac = uc(mac);
			break;
		}

		return mac;
	},

	// wrapper for scraping external tools stdout
	fs_popen: function(cmd) {
		let stdout = fs.popen(cmd);
	        if (!stdout)
			return null;

		let reply = null;
		try {
			reply = json(stdout.read('all'));
		} catch(e) {

		}
		stdout.close();
		return reply;
	},

	// give a client access to the internet
	allow_client: function(ctx, data) {
		this.syslog(ctx, 'allow client to pass traffic');
		ctx.ubus.call('spotfilter', 'client_set', {
			"interface": ctx.spotfilter,
			"address": ctx.mac,
			"state": 1,
			"dns_state": 1,
			"accounting": [ "dl", "ul"],
			"data": {
				... data || {},
				"connect": time(),
			}
		});
		if (ctx.query_string.userurl)
			include('redir.uc', { redir_location: ctx.query_string.userurl });
		else
			include('allow.uc', ctx);
		//data.radius.reply['WISPr-Bandwidth-Max-Up'] = "20000000";
		//data.radius.reply['WISPr-Bandwidth-Max-Down'] = "10000000";
		if (data?.radius?.reply && (+data.radius.reply['WISPr-Bandwidth-Max-Up'] && +data.radius.reply['WISPr-Bandwidth-Max-Down']))
			ctx.ubus.call('ratelimit', 'client_set', {
				device: ctx.device,
				address: ctx.mac,
				rate_egress: sprintf('%s', data.radius.reply['WISPr-Bandwidth-Max-Down']),
				rate_ingress: sprintf('%s', data.radius.reply['WISPr-Bandwidth-Max-Up']),
			 });
	},

	// put a client back into pre-auth state
	logoff: function(ctx, uam) {
		this.syslog(ctx, 'logging client off');
		ctx.ubus.call('spotfilter', 'client_set', {
			interface: ctx.spotfilter,
			address: ctx.mac,
			state: 0,
			dns_state: 1,
			accounting: [],
			data: {
				logoff : 1
			}
		});

		if (uam)
			include('redir.uc', { redir_location: this.uam_url(ctx, 'logoff') });
		else
			include('logoff.uc', ctx);
	},

	// generate the default radius auth payload
	radius_init: function(ctx) {
		if (!ctx.sessionid)
			ctx.sessionid = this.session_init();
		let payload = {
			server: sprintf('%s:%s:%s', ctx.config.auth_server, ctx.config.auth_port, ctx.config.auth_secret),
			acct_server: sprintf('%s:%s:%s', ctx.config.acct_server, ctx.config.acct_port, ctx.config.acct_secret),
			acct_session: ctx.sessionid,
			client_ip: ctx.env.REMOTE_ADDR,
			called_station: ctx.config.nasmac + ':' + ctx.ssid,
			calling_station: ctx.format_mac,
			nas_ip: ctx.env.SERVER_ADDR,
			nas_id: ctx.config.nasid
		};

		if (ctx.config.auth_proxy)
			payload.auth_proxy = ctx.config.auth_proxy;
		if (ctx.config.acct_proxy)
			payload.acct_proxy = ctx.config.acct_proxy;

		return payload;
	},

	// call radius-client with the provided payload and return reply
	radius_call: function(ctx, payload) {
		let path = '/tmp/' + (payload.acct ? 'acct' : 'auth') + ctx.mac + '.json';
		let cfg = fs.open(path, 'w');
		cfg.write(payload);
		cfg.close();

		let reply = this.fs_popen('/usr/bin/radius-client ' + path);

		if (!+config.def_captive.debug)
			fs.unlink(path);

		return reply;
	},

	uam_url: function(ctx, res) {
		let uam_url = ctx.config.uam_server +
			'?res=' + res +
			'&uamip=' + ctx.env.SERVER_ADDR +
			'&uamport=' + ctx.config.uam_port +
			'&challenge=' + this.uam.md5(ctx.config.challenge, ctx.format_mac) +
			'&mac=' + ctx.format_mac +
			'&ip=' + ctx.env.REMOTE_ADDR +
			'&called=' + ctx.config.nasmac +
			'&nasid=' + ctx.config.nasid +
			'&ssid=' + ctx.ssid +
			'&sessionid=' + ctx.sessionid;
		if (ctx.query_string?.redir)
			uam_url += '&userurl=' + ctx.query_string.redir;
		if (ctx.config.uam_secret)
			uam_url += '&md=' + this.uam.md5(uam_url, ctx.config.uam_secret);
		return uam_url;
	},

	handle_request: function(env, uam) {
		let mac;
		let form_data = {};
		let query_string = {};
		let post_data = '';
		let ctx = { env, header: this.header, footer: this.footer, mac, form_data, post_data, query_string, config: this.config, PO };

		// lookup the peers MAC
		let macs = this.rtnl.request(this.rtnl.const.RTM_GETNEIGH, this.rtnl.const.NLM_F_DUMP, { });
		for (let m in macs)
			if (m.dst == env.REMOTE_HOST && m.lladdr)
				ctx.mac = m.lladdr;

		// if the MAC lookup failed, go to the error page
		if (!ctx.mac) {
			this.syslog(ctx, 'failed to look up mac');
			include('error.uc', ctx);
			return NULL;
		}
		ctx.spotfilter = lookup_station(ctx.mac);
		ctx.config = config[ctx.spotfilter] || {};
		ctx.format_mac = this.format_mac(ctx.config.mac_format, ctx.mac);
		if (+ctx.config.web_root) {
			ctx.header = header_custom;
			ctx.footer = footer_custom;
		}

		// check if a client is already connected
		ctx.ubus = ubus.connect();
		let connected;
		connected = ctx.ubus.call('spotfilter', 'client_get', {
			interface: ctx.spotfilter,
			address: ctx.mac,
		});

		if (!uam && connected?.state) {
			include('connected.uc', ctx);
			return;
		}
		if (!connected.data.ssid) {
			let hapd = ctx.ubus.call('hostapd.' + connected.device, 'get_status');
			ctx.ubus.call('spotfilter', 'client_set', {
				interface: ctx.spotfilter,
				address: ctx.mac,
				data: {
					ssid: hapd?.ssid || 'unknown'
				}
			});
			connected.data.ssid = hapd.ssid;
		}
		if (!connected.data.sessionid) {
			let sessionid = this.session_init();
			ctx.ubus.call('spotfilter', 'client_set', {
				interface: ctx.spotfilter,
				address: ctx.mac,
				data: {
					sessionid: sessionid
				}
			});
			connected.data.sessionid = sessionid;
		}
		ctx.device = connected.device;
		ctx.ssid = connected.data.ssid;
		ctx.sessionid = connected.data.sessionid;

		// split QUERY_STRING
		if (env.QUERY_STRING)
			for (let chunk in split(env.QUERY_STRING, '&')) {
				let m = match(chunk, /^([^=]+)=(.*)$/);
				if (!m) continue;
				ctx.query_string[m[1]] = replace(m[2], /%([[:xdigit:]][[:xdigit:]])/g, (m, h) => chr(hex(h) || 0x20));
			}

		// recv POST data
		if (env.CONTENT_LENGTH > 0)
			for (let chunk = uhttpd.recv(64); chunk != null; chunk = uhttpd.recv(64))
				post_data += replace(chunk, /[^[:graph:]]/g, '.');

		// split POST data into an array
		if (post_data)
			for (let chunk in split(post_data, '&')) {
				let var = split(chunk, '=');
				if (length(var) != 2)
					continue;
				ctx.form_data[var[0]] = var[1];
			}
		return ctx;
	}
};
