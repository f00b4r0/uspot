// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022-2023 John Crispin <john@phrozen.org>
// SPDX-FileCopyrightText: 2023 Thibaut Varène <hacks@slashdirt.org>

'use strict';

import { urlencode, ENCODE_FULL } from 'lucihttp';

let ubus = require('ubus');
let uci = require('uci').cursor();
let config = uci.get_all('uspot');
let lib = require('uspotlib');

let header = '/www-uspot/header.html';
let footer = '/www-uspot/footer.html';

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
	if (type(d.ifname) == "array") {
		for (let n in d.ifname)
			adddev(n, spotname);
	}
	else {
		let dev = d.ifname || uci.get('network', d.interface, 'device');	// fallback to interface if ifname not provided
		if (!dev) {
			warn('uspot: neither interface nor ifname provided in section "' + spotname + '"\n');
			return;
		}
		adddev(dev, spotname);
	}
});

function lookup_station(mac) {
	let nl = require("nl80211");
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

function spotfilter_device(uspot, mac)
{
	let uconn = ubus.connect();
	let spot = uconn.call('spotfilter', 'client_get', {
		interface: uspot,
		address: mac,
	});
	return (spot?.device);
}

function _(english) {
	return english;
}

return {
	// syslog helper
	syslog: function(ctx, msg) {
		warn('uspot: ' + ctx.env.REMOTE_ADDR + ' - ' + msg + '\n');
	},

	debug: function(ctx, msg) {
		if (+ctx.config.debug)
			this.syslog(ctx, msg);
	},

	// give a client access to the internet
	allow_client: function(ctx, redir_location) {
		this.debug(ctx, 'allowing client');
		if (redir_location)
			include('templates/redir.ut', { redir_location });
		else
			include('templates/connected.ut', ctx);

		// start accounting
		ctx.ubus.call('uspot', 'client_enable', {
			uspot: ctx.uspot,
			address: ctx.mac,
		});
	},

	// put a client back into pre-auth state
	logoff_client: function(ctx, redir_location) {
		this.debug(ctx, 'logging client off');
		if (redir_location)
			include('templates/redir.ut', { redir_location });
		else
			include('templates/logoff.ut', ctx);

		ctx.ubus.call('uspot', 'client_remove', {
			uspot: ctx.uspot,
			address: ctx.mac,
		});
	},

	// request authentication from uspot backend, return reply 'access-accept': 0 or 1
	uspot_auth: function(ctx, username, password, challenge, extra) {
		let payload = {
			uspot: ctx.uspot,
			address: ctx.mac,
			client_ip: ctx.env.REMOTE_ADDR,
			sessionid: ctx.sessionid,
			reqdata: { ... extra || {} },
		};
		if (ctx.ssid)
			payload.ssid = ctx.ssid;
		if (username)
			payload.username = username;
		if (password)
			payload.password = password;
		if (challenge)
			payload.challenge = challenge;

		return ctx.ubus.call('uspot', 'client_auth', payload);
	},


	uam_url: function(ctx, res) {
		let uam = require('uam');
		let uam_url = ctx.config.uam_server +
			'?res=' + res +
			'&uamip=' + ctx.env.SERVER_ADDR +
			'&uamport=' + ctx.config.uam_port +
			'&challenge=' + uam.md5(ctx.config.challenge, ctx.format_mac) +
			'&mac=' + ctx.format_mac +
			'&ip=' + ctx.env.REMOTE_ADDR +
			'&called=' + ctx.config.nasmac +
			'&nasid=' + ctx.config.nasid +
			'&sessionid=' + ctx.sessionid;
		if (ctx.ssid)
			uam_url += '&ssid=' + ctx.ssid;
		if (ctx.seconds_remaining)
			uam_url += '&timeleft=' + ctx.seconds_remaining;
		if (ctx.config.uam_sslurl)
			uam_url += '&ssl=' + urlencode(ctx.config.uam_sslurl, ENCODE_FULL);
		if (ctx.query_string?.redir)
			uam_url += '&userurl=' + urlencode(ctx.query_string.redir, ENCODE_FULL);
		if (ctx.reply_msg)
			uam_url += '&reply=' + urlencode(ctx.reply_msg, ENCODE_FULL);
		if (ctx.query_string?.lang)
			uam_url += '&lang=' + urlencode(ctx.query_string.lang, ENCODE_FULL);
		if (ctx.config.uam_secret)
			uam_url += '&md=' + uam.md5(uam_url, ctx.config.uam_secret);
		return uam_url;
	},

	handle_request: function(env) {
		let rtnl = require('rtnl');
		let mac;
		let form_data = {};
		let query_string = {};
		let post_data = '';
		let ctx = { env, header, footer, mac, form_data, query_string, _ };
		let dev;

		// lookup the peers MAC
		let neighs = rtnl.request(rtnl.const.RTM_GETNEIGH, rtnl.const.NLM_F_DUMP, { });
		for (let n in neighs) {
			if (n.dst == env.REMOTE_HOST && n.lladdr) {
				ctx.mac = n.lladdr;
				dev = n.dev;
				break;
			}
		}

		// if the MAC lookup failed, go to the error page
		if (!ctx.mac) {
			this.syslog(ctx, 'failed to look up mac');
			include('templates/error.ut', ctx);
			return null;
		}
		ctx.uspot = (+config?.def_captive?.tip_mode && lookup_station(ctx.mac)) || devices[dev];	// fallback to rtnl device
		ctx.config = config[ctx?.uspot] || {};
		ctx.format_mac = lib.format_mac(ctx.config.mac_format, ctx.mac);

		// check if a client is already connected
		ctx.ubus = ubus.connect();
		let cdata = ctx.ubus.call('uspot', 'client_get', {
			uspot: ctx.uspot,
			address: ctx.mac,
		});

		// stop if backend doesn't reply
		if (!cdata) {
			this.syslog(ctx, 'uspot error');
			include('templates/error.ut', ctx);
			return null;
		}
		ctx.connected = !!length(cdata);	// cdata is empty for disconnected clients

		if (+config?.def_captive?.tip_mode && !cdata.ssid) {
			let device = spotfilter_device(ctx.uspot, ctx.mac);
			let hapd = ctx.ubus.call('hostapd.' + device, 'get_status');
			cdata.ssid = hapd?.ssid || 'unknown';
		}
		if (!cdata.sessionid)
			cdata.sessionid = lib.generate_sessionid();

		ctx.ssid = cdata.ssid;
		ctx.sessionid = cdata.sessionid;
		ctx.seconds_remaining = cdata.seconds_remaining;

		// split QUERY_STRING
		if (env.QUERY_STRING) {
			for (let chunk in split(env.QUERY_STRING, '&')) {
				let m = match(chunk, /^([^=]+)=(.*)$/);
				if (!m)
					continue;
				ctx.query_string[m[1]] = replace(m[2], /%([[:xdigit:]][[:xdigit:]])/g, (m, h) => chr(hex(h) || 0x20));
			}
		}

		// recv POST data
		if (env.CONTENT_LENGTH > 0)
			for (let chunk = uhttpd.recv(64); chunk != null; chunk = uhttpd.recv(64))
				post_data += replace(chunk, /[^[:graph:]]/g, '.');

		// split POST data into an array
		if (post_data) {
			for (let chunk in split(post_data, '&')) {
				let var = split(chunk, '=');
				if (length(var) != 2)
					continue;
				ctx.form_data[var[0]] = var[1];
			}
		}

		return ctx;
	}
};
