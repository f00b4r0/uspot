// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022-2023 John Crispin <john@phrozen.org>
// SPDX-FileCopyrightText: 2023 Thibaut Varène <hacks@slashdirt.org>

'use strict';

import { urlencode, urldecode, ENCODE_FULL, DECODE_KEEP_PLUS } from 'lucihttp';

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
	let dev = uci.get('network', d.interface, 'device');
	if (!dev) {
		warn('uspot: interface not provided (or missing device) in section "' + spotname + '"\n');
		return;
	}
	adddev(dev, spotname);
});

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
		ctx.ubus.error();	// XXX REVISIT clear error
		ctx.ubus.call('uspot', 'client_enable', {
			uspot: ctx.uspot,
			address: ctx.mac,
		});

		if (ctx.ubus.error())
			include('templates/error.ut', ctx);
		else if (redir_location)
			include('templates/redir.ut', { redir_location });
		else
			include('templates/connected.ut', ctx);

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

	// request authentication from uspot backend, return reply
	uspot_auth: function(ctx, username, password, challenge, extra) {
		let payload = {
			uspot: ctx.uspot,
			address: ctx.mac,
			client_ip: ctx.env.REMOTE_ADDR,
			sessionid: ctx.sessionid,
			reqdata: { ... extra || {} },
		};
		if (username)
			payload.username = username;
		if (password)
			payload.password = password;
		if (challenge)
			payload.challenge = challenge;

		return ctx.ubus.call('uspot', 'client_auth', payload);
	},


	uam_url: function(ctx, res, reason) {
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
		if (reason)
			uam_url += '&reason=' + reason;
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
		let ctx = { env, header, footer, mac: null, form_data: {}, query_string: {}, _ };

		ctx.ubus = ubus.connect();

		// try fast peer lookup first
		let peer = ctx.ubus.call('uspotfilter', 'peer_lookup', {
			ip: env.REMOTE_ADDR,
		});

		if (length(peer)) {
			ctx.mac = peer.mac;
			ctx.uspot = peer.uspot;
		}
		else {	// fallback to deep lookup if fast lookup failed
			let rtnl = require('rtnl');
			let dev;
			for (let n in rtnl.request(rtnl.const.RTM_GETNEIGH, rtnl.const.NLM_F_DUMP, { })) {
				if (n.dst == env.REMOTE_ADDR && n.lladdr) {
					ctx.mac = n.lladdr;
					dev = n.dev;
					break;
				}
			}

			ctx.uspot = devices[dev];	// rtnl device
		}

		ctx.config = config[ctx.uspot];
		if (!ctx.config) {
			this.syslog(ctx, 'config not found for "' + ctx.uspot + '"');
			include('templates/error.ut', ctx);
			return null;
		}

		// if the MAC lookup failed, go to the error page
		if (!ctx.mac) {
			this.syslog(ctx, 'failed to look up mac');
			include('templates/error.ut', ctx);
			return null;
		}

		ctx.format_mac = lib.format_mac(ctx.config.mac_format, ctx.mac);

		// check if uspot is enabled
		let cdata = ctx.ubus.call('uspot', 'state_get', {
			uspot: ctx.uspot,
		});

		// stop if backend doesn't reply
		if (!cdata) {
			this.syslog(ctx, 'uspot error');
			include('templates/error.ut', ctx);
			return null;
		}
		// if not available, end processing with message
		if (!cdata?.[ctx.uspot]) {
			include('templates/unavailable.ut', ctx);
			return null;
		}


		// check if a client is already connected
		cdata = ctx.ubus.call('uspot', 'client_get', {
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

		if (!cdata.sessionid)
			cdata.sessionid = lib.generate_sessionid();

		ctx.sessionid = cdata.sessionid;
		ctx.seconds_remaining = cdata.seconds_remaining;
		ctx.bytes_remaining = cdata.bytes_remaining;

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
		if (env.CONTENT_LENGTH > 0) {
			let post_data = '';
			for (let chunk = uhttpd.recv(64); chunk != null; chunk = uhttpd.recv(64))
				post_data += replace(chunk, /[^[:graph:]]/g, '.');

			// split POST data into an array
			if (post_data) {
				for (let chunk in split(post_data, '&')) {
					let var = split(chunk, '=');
					if (length(var) != 2)
						continue;
					ctx.form_data[var[0]] = urldecode(var[1], DECODE_KEEP_PLUS);
				}
			}
		}

		return ctx;
	}
};
