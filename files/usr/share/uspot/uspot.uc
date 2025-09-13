#!/usr/bin/ucode
// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022-2023 John Crispin <john@phrozen.org>
// SPDX-FileCopyrightText: 2023-2025 Thibaut Varène <hacks@slashdirt.org>

'use strict';

push(REQUIRE_SEARCH_PATH, "/usr/share/uspot/*.uc");

let fs = require('fs');
let uloop = require('uloop');
let ubus = require('ubus');
let uconn = ubus.connect();
let uci = require('uci').cursor();
let lib = require('uspotlib');
let uacct;
import { ulog_open, ulog, ULOG_SYSLOG, LOG_DAEMON, LOG_DEBUG, ERR, WARN, INFO } from 'log';

let uspots = {};

// setup logging
ulog_open(ULOG_SYSLOG, LOG_DAEMON, "uspot");

let config_valid = true;
let uciload = uci.foreach('uspot', 'uspot', (d) => {
	let device = null;
	if (!d[".anonymous"]) {
		device = uci.get('network', d.interface, 'device');
		let radsec = !!(d.rad_serv_type in ["tls", "dtls"]);
		// enable accounting if radsec and acct_server is set to some (any) value; or if both acct_server and acct_secret are set
		let accounting = !!(d.acct_server && (d.acct_secret || radsec));

		uspots[d[".name"]] = {
		state: 1,	// active by default
		settings: {
			accounting,
			device,
			radsec,
			rad_serv_type: d.rad_serv_type,
			auth_mode: d.auth_mode,
			auth_server: d.auth_server,
			auth_secret: d.auth_secret,
			auth_port: d.auth_port || ((radsec) ? 2083 : 1812),
			auth_server2: d.auth_server2,
			auth_secret2: d.auth_secret2,
			auth_port2: d.auth_port2 || ((radsec) ? 2083 : 1812),
			auth_proxy: d.auth_proxy,
			acct_server: d.acct_server,
			acct_secret: d.acct_secret,
			acct_port: d.acct_port || 1813,
			acct_server2: d.acct_server,
			acct_secret2: d.acct_secret,
			acct_port2: d.acct_port || 1813,
			acct_proxy: d.acct_proxy,
			acct_interval: d.acct_interval,
			swapio: d.swapio,
			nas_id: d.nasid,
			nas_mac: d.nasmac,
			mac_auth: d.mac_auth,
			mac_passwd: d.mac_passwd,
			mac_suffix: d.mac_suffix,
			mac_format: d.mac_format,
			location_name: d.location_name,
			idle_timeout: d.idle_timeout || 600,
			session_timeout: d.session_timeout || 0,
			disconnect_delay: d.disconnect_delay,
			ratelimit_def: d.ratelimit_def,
			counters: d.counters,
			debug: d.debug,
		},
		clients: {},
		};
	}

	// basic validation - first mandatory settings
	if (!(d.auth_mode && d.interface && d.setname)) {
		config_valid = false;
		ERR(d[".name"] + ": missing auth_mode, interface or setname!");
		return;
	}

	if (!device) {
		config_valid = false;
		ERR(d[".name"] + ": missing network device for interface: " + d.interface);
		return;
	}

	if (!(d.auth_mode in ["uam","radius","credentials","click-to-continue"])) {
		config_valid = false;
		ERR(d[".name"] + ": invalid auth_mode: " + d.auth_mode);
		return;
	}

	// common requirements for radius and UAM
	if (d.auth_mode in ["radius","uam"]) {
		if (!(d.auth_server && d.auth_secret && d.nasid && d.nasmac)) {
			config_valid = false;
			ERR(d[".name"] + ": missing auth_server, auth_secret, nasid or nasmac!");
		}

		if (("uam" == d.auth_mode) && !d.uam_server) {
			config_valid = false;
			ERR(d[".name"] + ": missing uam_server!");
		}
	}
});

if (!uciload || !config_valid) {
	let log = 'failed to load config';
	ERR(log);
	warn(log + '\n');
	exit(1);
}

function debug(uspot, msg) {
	if (+uspots[uspot].settings.debug)
		ulog(LOG_DEBUG, `${uspot} ${msg}`);
}

function format_mac(uspot, mac) {
	let format = uspots[uspot].settings.mac_format;
	return lib.format_mac(format, mac);
}

// wrapper for scraping external tools JSON stdout
function json_cmd(cmd, input) {
	let inpipe;

	if (input != null) {
		inpipe = fs.pipe();
		cmd = `exec ${inpipe[1].fileno()}>&-; ${cmd} <&${inpipe[0].fileno()}`;
	}

	let stdout = fs.popen(cmd);
	if (!stdout)
		return null;

	if (inpipe) {
		inpipe[1].write(input);
		inpipe[1].close();
		inpipe[0].close();
	}

	let reply = null;
	try {
		reply = json(stdout.read('all'));
	} catch(e) {
	}
	stdout.close();
	return reply;
}

/**
 * Augment and return RADIUS payload with necessary fields.
 * This function adds to an existing RADIUS payload the necessary Authentication or Accounting requests fields:
 * server, proxy, NAS-ID, and in the case of client accounting, client identification data.
 *
 * @param {string} uspot the target uspot
 * @param {?string} mac the client MAC address (for client accounting)
 * @param {object} payload the RADIUS payload
 * @param {?boolean} auth true for Radius Authentication, else Accounting request.
 * @returns {object) the augmented payload
 */
function radius_init(uspot, mac, payload, auth) {
	let settings = uspots[uspot].settings;

	if (settings.rad_serv_type)
		payload.serv_type = settings.rad_serv_type;

	payload.acct = !auth;

	if (!(auth || settings.radsec)) {	// acct_server is not used in RadSec
		payload.acct_server = sprintf('%s:%s:%s', settings.acct_server, settings.acct_port, settings.acct_secret);
		if (settings.acct_server2)
			payload.acct_server += sprintf(',%s:%s:%s', settings.acct_server2, settings.acct_port2, settings.acct_secret2);
		if (settings.acct_proxy)
			payload.acct_proxy = settings.acct_proxy;
	}
	else {
		payload.server = sprintf('%s:%s:%s', settings.auth_server, settings.auth_port, settings.auth_secret);
		if (settings.auth_server2)
			payload.server += sprintf(',%s:%s:%s', settings.auth_server2, settings.auth_port2, settings.auth_secret2);
		if (settings.auth_proxy)
			payload.auth_proxy = settings.auth_proxy;
	}

	payload['NAS-Identifier'] = settings.nas_id;	// XXX RFC says NAS-IP is not required when NAS-ID is set, but it's added by libradcli anyway
	if (settings.location_name)
		payload['WISPr-Location-Name'] = settings.location_name;

	if (!auth && mac) {
		// dealing with client accounting
		let client = uspots[uspot].clients[mac];
		let radius = client.radius.request;
		for (let key in [ 'Acct-Session-Id', 'Framed-IP-Address', 'Called-Station-Id', 'Calling-Station-Id', 'NAS-IP-Address', 'NAS-Port-Type', 'User-Name', 'WISPr-Location-Name', 'Chargeable-User-Identity' ])
			if (radius[key])
				payload[key] = radius[key];
	}

	return payload;
}

/**
 * Execute "radius-client" with the provided RADIUS payload, return reply.
 *
 * @param {object} payload the RADIUS payload
 * @returns {object} "radius-client" reply
 */
function radius_call(payload) {
	return json_cmd('/usr/bin/radius-client /dev/stdin', payload);
}

// RADIUS Acct-Status-Type attributes
const radat_start = 1;		// Start
const radat_stop = 2;		// Stop
const radat_interim = 3;	// Interim-Update
const radat_accton = 7;		// Accounting-On
const radat_acctoff = 8;	// Accounting-Off

/**
 * Send RADIUS client accounting.
 * This function computes and populates the following RADIUS payload fields:
 * session_time, {input,output}_{octets,gigawords,packets} and class;
 * it then executes a RADIUS Accounting request with these elements.
 *
 * @param {string} uspot the target uspot
 * @param {string} mac the client MAC address
 * @param {object} payload the RADIUS payload
 */
function radius_acct(uspot, mac, payload) {
	let settings = uspots[uspot].settings;

	if (!settings.accounting)
		return;

	let client = uspots[uspot].clients[mac];
	if (!client)
		return;

	payload = radius_init(uspot, mac, payload);

	if (payload.acct_type != radat_start) {
		payload['Acct-Session-Time'] = time() - client.connect;
		let acct_data = +settings.counters ? uacct.client_get(settings.device, mac) : null;
		if (length(acct_data)) {
			if (+settings.swapio) {
				payload['Acct-Output-Packets'] = acct_data.packets_in;
				payload['Acct-Output-Octets'] = acct_data.bytes_in & 0xffffffff;
				payload['Acct-Output-Gigawords'] = acct_data.bytes_in >> 32;
				payload['Acct-Input-Packets'] = acct_data.packets_out;
				payload['Acct-Input-Octets'] = acct_data.bytes_out & 0xffffffff;
				payload['Acct-Input-Gigawords'] = acct_data.bytes_out >> 32;
			} else {
				payload['Acct-Output-Packets'] = acct_data.packets_out;
				payload['Acct-Output-Octets'] = acct_data.bytes_out & 0xffffffff;
				payload['Acct-Output-Gigawords'] = acct_data.bytes_out >> 32;
				payload['Acct-Input-Packets'] = acct_data.packets_in;
				payload['Acct-Input-Octets'] = acct_data.bytes_in & 0xffffffff;
				payload['Acct-Input-Gigawords'] = acct_data.bytes_in >> 32;
			}
		}
	}
	if (client.data?.radius?.reply?.Class)
		payload.Class = client.data.radius.reply.Class;

	radius_call(payload);
}

// RADIUS Acct-Terminate-Cause attributes
const radtc_logout = 1;		// User Logout
const radtc_lostcarrier = 2;	// Lost Carrier
const radtc_idleto = 4;		// Idle Timeout
const radtc_sessionto = 5;	// Session Timeout
const radtc_adminreset = 6;	// Admin Reset

/**
 * Terminate a client RADIUS accounting.
 *
 * @param {string} uspot the target uspot
 * @param {string} mac the client MAC address
 * @param {number} cause the RADIUS Acct-Terminate-Cause value
 */
function radius_terminate(uspot, mac, cause) {
	if (!uspots[uspot].clients[mac].radius)
		return;

	let payload = {
		'Acct-Status-Type': radat_stop,
		'Acct-Terminate-Cause': cause,
	};
	debug(uspot, mac + ' acct terminate: ' + cause);
	radius_acct(uspot, mac, payload);
}

/**
 * Start a client RADIUS accounting.
 *
 * @param {string} uspot the target uspot
 * @param {string} mac the client MAC address
 */
function radius_start(uspot, mac) {
	let payload = {
		'Acct-Status-Type': radat_start,
	};
	debug(uspot, mac + ' acct start');
	if (+uspots[uspot].settings.counters) {
		let retval = uacct.client_add(uspots[uspot].settings.device, mac, true, true);
		if (retval)		// returns null on success, error message on failure
			ERR(`${uspot} failed to add client ${mac} to accounting map: ${retval}`);
	}
	radius_acct(uspot, mac, payload);
}

/**
 * Send interim client RADIUS accounting.
 *
 * @param {string} uspot the target uspot
 * @param {string} mac the client MAC address
 */
function radius_interim(uspot, mac) {
	let payload = {
		'Acct-Status-Type': radat_interim,
	};
	radius_acct(uspot, mac, payload);
	debug(uspot, mac + ' interim acct call');
}

/**
 * Uspot internal client accounting.
 * This function optionally sends interim RADIUS reports if configured
 *
 * @param {string} uspot the target uspot
 * @param {string} mac the client MAC address
 * @param {number} time the UNIX time of the report
 */
function client_interim(uspot, mac, time) {
	let client = uspots[uspot].clients[mac];

	if (!client.interval)
		return;

	if (time >= client.next_interim) {
		radius_interim(uspot, mac);
		client.next_interim += client.interval;
	}
}

/**
 * Apply static or RADIUS-provided client bandwidth limits.
 * This function parses a radius reply for the following attributes:
 * 'WISPr-Bandwidth-Max-{Up,Down}' or 'ChilliSpot-Bandwidth-Max-{Up,Down}'
 * and enforces these limits if present.
 * If a global setting has been configured, the global default is applied.
 *
 * @param {string} uspot the target uspot
 * @param {string} mac the client MAC address
 */
function client_ratelimit(uspot, mac) {
	let client = uspots[uspot].clients[mac];
	let device = uspots[uspot].settings.device;
	let rldef = uspots[uspot].settings.ratelimit_def;
	let maxup, maxdown;

	if (client.radius?.reply) {
		let reply = client.radius.reply;

		// check known attributes - WISPr: bps, ChiliSpot: kbps
		maxup = reply['WISPr-Bandwidth-Max-Up'] || (reply['ChilliSpot-Bandwidth-Max-Up']*1000);
		maxdown = reply['WISPr-Bandwidth-Max-Down'] || (reply['ChilliSpot-Bandwidth-Max-Down']*1000);
	}

	if (!(+maxdown || +maxup || rldef))
		return;

	let rldata = {};
	let args = {
		device,
		address: mac,
	};
	if (+maxdown) {
		args.rate_egress = sprintf('%s', maxdown);
		rldata.maxdown = maxdown/1000;	// in kbps
	}
	if (+maxup) {
		args.rate_ingress = sprintf('%s', maxup);
		rldata.maxup = maxup/1000;	// in kbps
	}
	if (rldef) {
		args.defaults = rldef;
		rldata.defaults = rldef;
	}

	uconn.error();	// XXX REVISIT clear error
	uconn.call('ratelimit', 'client_set', args);
	if (!uconn.error())
		client.data.ratelimit = rldata;
}

/**
 * Apply RADIUS-provided client quota limits.
 * This function parses a radius reply for the following attributes:
 * 'ChilliSpot-Max-Total-Octets', 'ChilliSpot-Max-Total-Gigawords'
 * 'ChilliSpot-Max-Input-Octets', 'ChilliSpot-Max-Input-Gigawords'
 * 'ChilliSpot-Max-Output-Octets' and/or 'ChilliSpot-Max-Output-Gigawords'
 * and enforces these limits if present.
 *
 * @param {string} uspot the target uspot
 * @param {string} mac the client MAC address
 */
function client_quotalimit(uspot, mac) {
	let client = uspots[uspot].clients[mac];
	let device = uspots[uspot].settings.device;
	let counters = +uspots[uspot].settings.counters;
	let swapio = +uspots[uspot].settings.swapio;

	if (!(counters && client.radius?.reply))
		return;

	let reply = client.radius.reply;

	// check known attributes
	let maxup = (+reply['ChilliSpot-Max-Input-Octets'] + (+reply['ChilliSpot-Max-Input-Gigawords'] << 32)) || 0;
	let maxdown = (+reply['ChilliSpot-Max-Output-Octets'] + (+reply['ChilliSpot-Max-Output-Gigawords'] << 32)) || 0;
	let maxtotal = (+reply['ChilliSpot-Max-Total-Octets'] + (+reply['ChilliSpot-Max-Total-Gigawords'] << 32)) || 0;

	if (!(maxdown || maxup || maxtotal))
		return;

	if (swapio) {
		let temp = maxdown;
		maxdown = maxup;
		maxup = temp;
	}

	let tx = (!!maxup || !!maxtotal), rx = (!!maxdown || !!maxtotal);
	if (!length(uacct.client_get(device, mac)))	// don't overide enabled tx/rx counters if radius accounting is on
		uacct.client_add(device, mac, tx, rx);

	debug(uspot, mac + " enabling quota limits on " + (tx ? "tx " : "") + (rx ? "rx" : ""));

	client.maxdown = maxdown;
	client.maxup = maxup;
	client.maxtotal = maxtotal;
}

/**
 * Add an authenticated but not yet validated client to the backend.
 * This function adds a client that passed authentication, but hasn't yet been enabled.
 * If the client isn't subsequently enabled, it will be purged after a 60s grace period.
 *
 * @param {string} uspot the target uspot
 * @param {string} mac the client MAC address
 */
function client_create(uspot, mac, payload)
{
	let client = {
		connect: time(),
		data: {},
		...payload,
		state: 0,
	};

	uspots[uspot].clients[mac] = client;

	debug(uspot, mac + ' creating client');
}

/**
 * Enable an authenticated client to pass traffic.
 * This function authorizes a client, applying RADIUS-provided limits if any:
 * 'Acct-Interim-Interval', 'Session-Timeout', 'Idle-Timeout' and 'ChilliSpot-Max-Total-Octets'.
 * It updates uspotfilter state for authorization, starts RADIUS accounting and ratelimit as needed.
 *
 * @param {string} uspot the target uspot
 * @param {string} mac the client MAC address
 * @returns {boolean} true if success, false otherwise
 */
function client_enable(uspot, mac) {
	let defval = 0;

	let settings = uspots[uspot].settings;
	let accounting = settings.accounting;

	let radius = uspots[uspot].clients[mac]?.radius;

	// RFC: NAS local interval value *must* override RADIUS attribute
	defval = settings.acct_interval;
	let interval = +(defval || radius?.reply?.['Acct-Interim-Interval'] || 0);

	defval = settings.session_timeout;
	let session = +(radius?.reply?.['Session-Timeout'] || defval);

	defval = settings.idle_timeout;
	let idle = +(radius?.reply?.['Idle-Timeout'] || defval);

	let cui = radius?.reply?.['Chargeable-User-Identity'];

	let client = {
		... uspots[uspot].clients[mac] || {},
		state: 1,
		interval,
		session,
		idle,
	};
	if (radius?.request && accounting && interval)
		client.next_interim = time() + interval;
	if (cui)
		client.radius.request['Chargeable-User-Identity'] = cui;

	uconn.error();	// XXX REVISIT clear error
	// tell uspotfilter this client is allowed
	uconn.call('uspotfilter', 'client_set', {
		interface: uspot,
		address: mac,
		state: 1,
		data: { connect: client.connect, },
	});

	if (!uconn.error()) {
		uspots[uspot].clients[mac] = client;
		INFO(`${uspot} ${mac} adding client`);

		// start RADIUS accounting
		if (accounting && radius?.request)
			radius_start(uspot, mac);

		// apply ratelimiting rules, if any
		client_ratelimit(uspot, mac);

		// apply traffic limit/accouting rules, if any
		client_quotalimit(uspot, mac);

		return true;
	}

	return false;
}

/**
 * Remove a client from the system.
 * This function deletes a client from the backend, and removes existing connection flows.
 *
 * @param {string} uspot the target uspot
 * @param {string} mac the client MAC address
 * @param {string} reason the removal reason (for logging purposes)
 */
function client_remove(uspot, mac, reason) {
	INFO(`${uspot} ${mac} removing client: ${reason}`);
	let payload = {
		interface: uspot,
		address: mac,
	};
	let device = uspots[uspot].settings.device;

	uconn.error();	// XXX REVISIT clear error
	uconn.call('uspotfilter', 'client_remove', payload);
	if (uconn.error())
		return;	// if we couldn't remove from uspotfilter, try again at the next round - keep uspot/uspotfilter in sync

	// delete ratelimit rules if any
	uconn.call('ratelimit', 'client_delete', { device, address: mac });

	// delete client from traffic accounting map, if any
	if (uacct)
		uacct.client_del(device, mac);

	delete uspots[uspot].clients[mac];
}

/**
 * Signal beginning of RADIUS accounting for this NAS.
 *
 * @param {string} uspot the target uspot
 */
function radius_accton(uspot)
{
	// assign a global uspot session ID for Accounting-On/Off messages
	let sessionid = lib.generate_sessionid();

	uspots[uspot].sessionid = sessionid;

	let payload = {
		'Acct-Status-Type': radat_accton,
		'Acct-Session-Id': sessionid,
		'Called-Station-Id': uspots[uspot].settings.nas_mac,
	};
	payload = radius_init(uspot, null, payload);
	radius_call(payload);
	debug(uspot, 'acct-on call');
}

/**
 * Signal end of RADIUS accounting for this NAS.
 *
 * @param {string} uspot the target uspot
 */
function radius_acctoff(uspot)
{
	let payload = {
		'Acct-Status-Type': radat_acctoff,
		'Acct-Session-Id': uspots[uspot].sessionid,
		'Called-Station-Id': uspots[uspot].settings.nas_mac,
	};
	payload = radius_init(uspot, null, payload);
	radius_call(payload);
	debug(uspot, 'acct-off call');
}

/**
 * Perform accounting housekeeping for a uspot.
 * This function goes throught the list of known clients and performs:
 * - cleanup authenticated but not enabled clients after 60s grace period;
 * - cleanup when a client is no longer known to uspotfilter;
 * - client termination on idle timeout, session timeout or data budget expiration.
 * - RADIUS interim accounting report
 *
 * @param {string} uspot the target uspot
 */
function accounting(uspot) {
	if (!+uspots[uspot].state)
		return;

	let list = uconn.call('uspotfilter', 'client_list', { interface: uspot });
	let t = time();
	let accounting = uspots[uspot].settings.accounting;
	let disconnect_delay = uspots[uspot].settings.disconnect_delay;
	let device = uspots[uspot].settings.device;
	let counters = +uspots[uspot].settings.counters;

	if (!list) {
		WARN(`${uspot} no client list from uspotfilter!`);
		return;
	}

	for (let mac, client in uspots[uspot].clients) {
		if (!client.state) {
			const stale = 60;	// 60s timeout for (new) unauth clients
			if ((t - client.connect) > stale)
				client_remove(uspot, mac, 'stale client');
			continue;
		}

		if (!list[mac] || !list[mac].state) {
			radius_terminate(uspot, mac, radtc_lostcarrier);
			client_remove(uspot, mac, 'disconnect event');
			continue;
		}

		if (+disconnect_delay && (+list[mac].lost_since && (t - list[mac].lost_since > +disconnect_delay))) {
			radius_terminate(uspot, mac, radtc_lostcarrier);
			client_remove(uspot, mac, 'delayed disconnect event');
			continue;
		}

		if ((+list[mac].idle_since && (t - list[mac].idle_since > +client.idle))) {
			radius_terminate(uspot, mac, radtc_idleto);
			client_remove(uspot, mac, 'idle event');
			continue;
		}
		let timeout = +client.session;
		if (timeout && ((t - client.connect) > timeout)) {
			radius_terminate(uspot, mac, radtc_sessionto);
			client_remove(uspot, mac, 'session timeout');
			continue;
		}

		if (counters) {
			let maxtotal = client.maxtotal, maxup = client.maxup, maxdown = client.maxdown;
			if (maxtotal || maxup || maxdown) {
				let acct_data = uacct.client_get(device, mac);
				if (maxtotal && ((acct_data?.bytes_in || 0) + (acct_data?.bytes_out || 0)) >= maxtotal) {
					radius_terminate(uspot, mac, radtc_sessionto);
					client_remove(uspot, mac, 'max total octets reached');
					continue;
				}
				if (maxup && (acct_data?.bytes_in || 0) >= maxup) {
					radius_terminate(uspot, mac, radtc_sessionto);
					client_remove(uspot, mac, 'max ul octets reached');
					continue;
				}
				if (maxdown && (acct_data?.bytes_out || 0) >= maxdown) {
					radius_terminate(uspot, mac, radtc_sessionto);
					client_remove(uspot, mac, 'max dl octets reached');
					continue;
				}
			}
		}

		if (accounting)
			client_interim(uspot, mac, t);
	}
}

function start()
{
	let seen = {};

	// for each unique uspot/nasid with configured RADIUS, send Accounting-On
	for (let uspot, data in uspots) {
		let server = data.settings.acct_server;
		let nasid = data.settings.nas_id;
		let device = data.settings.device;

		// ensure target device is available
		let count = 10;
		while (--count && !uconn.call('network.device','status', {name: device})) {
			WARN(`${uspot}: cannot find device {$device}, retrying: ${count}`);
			sleep(2000);
		}

		if (!count) {
			ERR(`${uspot}: cannot find device {$device}, giving up!`);
			delete uspots[uspot];
			continue;
		}

		if (+data.settings.counters) {
			uacct = uacct ? uacct : require('uspotbpf');
			let retval = uacct.load(device);	// returns null on success, error message on failure
			if (retval)
				ERR(`${uspot}: failed to load BPF accouting module: ${retval}`);
		}

		// clear ratelimit rules for our device
		uconn.call('ratelimit', 'device_delete', { device: data.settings.device });

		if (!server || !nasid)
			continue;
		if ((server in seen) && (nasid in seen[server]))
			continue;	// avoid sending duplicate requests to the same server for the same nasid
		if (!seen[server])
			seen[server] = {};
		seen[server][nasid] = 1;
		radius_accton(uspot);
	}
}

function stop()
{
	for (let uspot, data in uspots) {
		if (data.sessionid)	// we have previously sent Accounting-On
			radius_acctoff(uspot);

		if (+data.settings.counters)
			uacct.unload(data.settings.device);

		// clear ratelimit rules for our device
		uconn.call('ratelimit', 'device_delete', { device: data.settings.device });
	}
}

function das_match_client(uspot, request)
{
	let match;

	for (let mac, client in uspots[uspot].clients) {
		if (!client.radius?.request)
			continue;

		// ucode does not (yet) support 'continue [label]'
		let fail = false;
		for (let key, val in request) {
			// all request keys must match
			if (client.radius.request[key] != val) {
				fail = true;
				break;
			}
		}

		if (fail)
			continue;

		match = mac;
		break;
	}

	return match;
}

// Retrieve and filter out CoA change requests
function das_coa_filter_changes(request)
{
	let changes = {};

	for (let key in [ 'Session-Timeout', 'Idle-Timeout', 'Acct-Interim-Interval' ]) {
		if (key in request) {
			changes[key] = request[key];
			delete request[key];
		}
	}

	return changes;
}

// update a client with CoA changes
function das_coa_update_client(client, changes)
{
	for (let key, val in changes) {
		switch (key) {
		case 'Acct-Interim-Interval':
			client.interval = val;
			break;
		case 'Session-Timeout':
			client.session = val;
			break;
		case 'Idle-Timeout':
			client.idle = val;
			break;
		}
	}
}

function run_service() {
	uconn.publish("uspot", {
		client_auth: {
			call: function(req) {
				let uspot = req.args.uspot;
				let address = req.args.address;
				let client_ip = req.args.client_ip;
				let username = req.args.username;
				let password = req.args.password;
				let challenge = req.args.challenge;
				let sessionid = req.args.sessionid || lib.generate_sessionid();
				let reqdata = req.args.reqdata;

				let try_macauth = false;

				if (!uspot || !address || !client_ip)
					return { 'access-accept': 0 };

				if (!(uspot in uspots))
					return { 'access-accept': 0 };

				if (!+uspots[uspot].state)
					return { 'access-accept': 0 };

				let settings = uspots[uspot].settings;

				// if client is already created (==authenticated), return early
				if (uspots[uspot].clients[address])
					return { 'access-accept': 2 };

				// prepare client payload
				let payload = {
					data: {
						sessionid,
						username,	// XXX does anything use this? comes from handler.uc radius & credentials auth
						client_ip,	// not used, could be useful
					},
				};

				// click-to-continue: always accept - portal is responsible for checking conditions are met
				if (settings.auth_mode == 'click-to-continue') {
					client_create(uspot, address, payload);
					return { 'access-accept': 1 };
				}

				// credentials
				if (settings.auth_mode == 'credentials') {
					let match = 0;
					uci.foreach('uspot', 'credentials', (d) => {
						// check if the credentials are valid
						if (d.uspot != uspot)
							return;
						if (d.username == username && d.password == password)
							match = 1;
					});
					if (match)
						client_create(uspot, address, payload);
					return { 'access-accept': match };
				}

				// else, radius/uam
				if (!username && !password) {
					if  (!+settings.mac_auth)	// don't try mac-auth if not allowed
						return { 'access-accept': 0 };
					else
						try_macauth = true;
				}

				let fmac = format_mac(uspot, address);

				let request = {
					'User-Name': username,
					'Calling-Station-Id': fmac,
					'Called-Station-Id': settings.nas_mac,
					'Acct-Session-Id': sessionid,
					'Framed-IP-Address': client_ip,
					... reqdata || {},
				};

				if (try_macauth) {
					request['User-Name'] = fmac + (settings.mac_suffix || '');
					request['Password'] = settings.mac_passwd || fmac;
					request['Service-Type'] = 10;	// Call-Check, see https://wiki.freeradius.org/guide/mac-auth#web-auth-safe-mac-auth
				}
				else if (challenge) {
					request['CHAP-Password'] = password;
					request['CHAP-Challenge'] = challenge;
				}
				else
					request['Password'] = password;

				request = radius_init(uspot, address, request, true);

				let radius = radius_call(request);

				if (radius?.['access-accept']) {
					delete request.server;	// don't publish RADIUS server secret
					payload.radius = { reply: radius.reply, request };	// save RADIUS payload for later use
					client_create(uspot, address, payload);
				}

				return radius;
			},
			/*
			 @param uspot: REQUIRED: target uspot
			 @param address: REQUIRED: client MAC address
			 @param client_ip: REQUIRED: client IP
			 @param username: OPTIONAL: client username
			 @param password: OPTIONAL: client password or CHAP password
			 @param challenge: OPTIONAL: client CHAP challenge
			 @param sessionid: OPTIONAL: accounting session ID
			 @param reqdata: OPTIONAL: additional RADIUS request data - to be passed verbatim to radius-client
			 @param return {object} "{"access-accept":N}" where N==1 if auth succeeded, 2 if already auth'd, 0 otherwise. Nothing on RADIUS failure

			 operation:
			  - call with (uspot, address, client_ip) -> click-to-continue or RADIUS MAC authentication
			  - call with (uspot, address, client_ip, username, password) -> credentials or RADIUS password auth
			  - call with (uspot, address, client_ip, username, password, challenge) -> RADIUS CHAP challenge auth
			 */
			args: {
				uspot:"",
				address:"",
				client_ip:"",
				username:"",
				password:"",
				challenge:"",
				sessionid:"",
				reqdata:{},
			}
		},
		client_enable: {
			call: function(req) {
				let uspot = req.args.uspot;
				let address = req.args.address;

				if (!uspot || !address)
					return ubus.STATUS_INVALID_ARGUMENT;
				if (!(uspot in uspots))
					return ubus.STATUS_INVALID_ARGUMENT;

				// enabling clients can only be done for known ones (i.e. those which passed authentication)
				if (!uspots[uspot].clients[address])
					return ubus.STATUS_NOT_FOUND;

				// if client is already enabled, do nothing
				if (!uspots[uspot].clients[address].state)
					return client_enable(uspot, address) ? ubus.STATUS_OK : ubus.STATUS_UNKNOWN_ERROR;

				return ubus.STATUS_OK;
			},
			/*
			 Enable a previously authenticated client to pass traffic.
			 XXX REVIEW: we might want to squash that into client_auth()
			 @param uspot: REQUIRED: target uspot
			 @param address: REQUIRED: client MAC address
			 */
			args: {
				uspot:"",
				address:"",
			}
		},
		client_remove: {
			call: function(req) {
				let uspot = req.args.uspot;
				let address = req.args.address;

				if (!uspot || !address)
					return ubus.STATUS_INVALID_ARGUMENT;
				if (!(uspot in uspots))
					return ubus.STATUS_INVALID_ARGUMENT;

				if (uspots[uspot].clients[address]) {
					radius_terminate(uspot, address, radtc_logout);
					client_remove(uspot, address, 'client_remove event');
				}

				return ubus.STATUS_OK;
			},
			/*
			 Delete a client from the system.
			 @param uspot: REQUIRED: target uspot
			 @param address: REQUIRED: client MAC address
			 */
			args: {
				uspot:"",
				address:"",
			}
		},
		client_get: {
			call: function(req) {
				function client_get_data(client, uspot, address) {
					let acct_data = uacct ? uacct.client_get(uspots[uspot].settings.device, address) : null;
					let data = {
						... client.data || {},
						duration: time() - client.connect,
						... acct_data || {},
						... +uspots[uspot].settings.debug ? client : {},
					};

					let timeout = +client.session;
					if (timeout) {
						data.seconds_remaining = timeout - data.duration;
						// if timeout is exceeded, immediately kick client for consistency's sake
						if (data.seconds_remaining <= 0) {
							radius_terminate(uspot, address, radtc_sessionto);
							client_remove(uspot, address, 'session timeout');
							return {};
						}
					}

					if (acct_data && (client.maxup || client.maxdown || client.maxtotal)) {
						// compute a maximum for API bytes-remaining
						// RFC doesn't distinguish up/down bytes so lets try to come up with something sensible
						let maxtot = max(client.maxtotal, client.maxup + client.maxdown);
						let cur = acct_data.bytes_in + acct_data.bytes_out;
						data.bytes_remaining = maxtot - cur;
					}

					return data;
				}

				let uspot = req.args.uspot;
				let address = req.args.address;

				if (!uspot)
					return ubus.STATUS_INVALID_ARGUMENT;
				if (!(uspot in uspots))
					return ubus.STATUS_INVALID_ARGUMENT;

				if (address) {
					if (!uspots[uspot].clients[address])
						return {};

					let client = uspots[uspot].clients[address];
					return client_get_data(client, uspot, address);
				}
				else {
					let payload = {};
					for (let mac, client in uspots[uspot].clients)
						payload[mac] = client_get_data(client, uspot, mac);
					return payload;
				}
			},
			/*
			 Get a/all client public state.
			 @param uspot: REQUIRED: target uspot
			 @param address: OPTIONAL: client MAC address
			 */
			args: {
				uspot:"",
				address:"",
			}
		},
		client_list: {
			call: function(req) {
				let uspot = req.args.uspot;

				if (uspot && !(uspot in uspots))
					return ubus.STATUS_INVALID_ARGUMENT;

				let payload = {};

				if (uspot)
					payload[uspot] = keys(uspots[uspot].clients);
				else {
					for (uspot in uspots)
						payload[uspot] = keys(uspots[uspot].clients);
				}

				return payload;
			},
			/*
			 List all clients for all / a given uspot.
			 @param uspot: OPTIONAL: target uspot
			 */
			args: {
				uspot:"",
			}
		},
		das_disconnect: {
			call: function(req) {
				let uspot = req.args.uspot;
				let request = req.args.request;

				if (!uspot || !request)
					return ubus.STATUS_INVALID_ARGUMENT;
				if (!(uspot in uspots))
					return ubus.STATUS_INVALID_ARGUMENT;

				let address = das_match_client(uspot, request);

				if (address) {
					radius_terminate(uspot, address, radtc_adminreset);
					client_remove(uspot, address, 'das_disconnect event');
				}

				return { "found": address ? true : false };
			},
			/*
			 Disconnect clients matching request.
			 @param uspot: REQUIRED: target uspot
			 @param request: REQUIRED: any of { 'User-Name', 'NAS-IP-Address', 'Called-Station-Id', 'Calling-Station-Id', 'NAS-Identifier', 'Acct-Session-Id', 'Chargeable-User-Identity' }
			 @return { "found": true } if match found and disconnected
			 */
			args: {
				uspot:"",
				request:{},
			}
		},
		das_coa: {
			call: function(req) {
				let uspot = req.args.uspot;
				let request = req.args.request;

				if (!uspot || !request)
					return ubus.STATUS_INVALID_ARGUMENT;
				if (!(uspot in uspots))
					return ubus.STATUS_INVALID_ARGUMENT;

				let changes = das_coa_filter_changes(request);
				let address = das_match_client(uspot, request);

				if (address) {
					let client = uspots[uspot].clients[address];
					das_coa_update_client(client, changes);
					INFO(`${uspot} ${address} CoA update`);
				}

				return { "found": address ? true : false };
			},
			/*
			 Update clients matching CoA request.
			 @param uspot: REQUIRED: target uspot
			 @param request: REQUIRED: any of { 'User-Name', 'NAS-IP-Address', 'Called-Station-Id', 'Calling-Station-Id', 'NAS-Identifier', 'Acct-Session-Id', 'Chargeable-User-Identity' } + Supported CoA changes
			 @return { "found": true } if match found and updated
			 */
			args: {
				uspot:"",
				request:{},
			}
		},
		state_get: {
			call: function(req) {
				let uspot = req.args.uspot;

				if (uspot && !(uspot in uspots))
					return ubus.STATUS_INVALID_ARGUMENT;

				let payload = {};

				if (uspot)
					payload[uspot] = uspots[uspot].state;
				else {
					for (uspot in uspots)
						payload[uspot] = uspots[uspot].state;
				}

				return payload;
			},
			/*
			 Get all / a given uspot state.
			 @param uspot: OPTIONAL: target uspot (if not provided, all uspots are effected)
			 */
			args: {
				uspot:"",
			}
		},
		state_set: {
			call: function(req) {
				function uspot_enable(uspot) {
					uspots[uspot].state = 1;
				}
				function uspot_disable(uspot) {
					uspots[uspot].state = 0;
					for (let mac, client in uspots[uspot].clients) {
						radius_terminate(uspot, mac, radtc_adminreset);
						client_remove(uspot, mac, 'uspot disabled');
					}
				}
				function uspot_state_update(uspot, state) {
					if (uspots[uspot].state != state) {
						if (state)
							uspot_enable(uspot);
						else
							uspot_disable(uspot);
					}
				}

				let uspot = req.args.uspot;
				let state = !!req.args.state;

				if (req.args.state == null || (uspot && !(uspot in uspots)))
					return ubus.STATUS_INVALID_ARGUMENT;

				if (uspot)
					uspot_state_update(uspot, state);
				else {
					for (uspot in uspots)
						uspot_state_update(uspot, state);
				}

				return ubus.STATUS_OK;
			},
			/*
			 Change all / a given uspot state.
			 @param uspot: OPTIONAL: target uspot (if not provided, all uspots are effected)
			 @param state: REQUIRED: uspot state (false: inactive, true: active)
			 */
			args: {
				uspot:"",
				state:true,
			}
		},
	});

	try {
		start();
		uloop.timer(10000, function() {
			for (let uspot in uspots)
				accounting(uspot);
			this.set(10000);
		});
		uloop.run();
	} catch (e) {
		warn(`Error: ${e}\n${e.stacktrace[0].context}`);
	}

	stop();
}

uloop.init();
run_service();
uloop.done();
