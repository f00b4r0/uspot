#!/usr/bin/ucode
// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023-2024 Thibaut Varène <hacks@slashdirt.org>
// uspotfilter - uspot interface to netfilter

/*
 A stateful wrapper around nftables and rtnl.

 This daemon handles client firewall permissions (allowing/disallowing via a MAC nftables set)
 and monitors netlink neigh updates to update client status (new/stale/gone and ip addresses).

 TODO: IPv6 support
 */

'use strict';

let fs = require('fs');
let uloop = require('uloop');
let ubus = require('ubus');
let uconn = ubus.connect();
let uci = require('uci').cursor();
let rtnl = require('rtnl');
import { ulog_open, ulog, ULOG_SYSLOG, LOG_DAEMON, LOG_DEBUG, ERR } from 'log';

let uspots = {};
let devices = {};

// setup logging
ulog_open(ULOG_SYSLOG, LOG_DAEMON, "uspotfilter");

let uciload = uci.foreach('uspot', 'uspot', (d) => {
	if (!d[".anonymous"]) {
		let device = uci.get('network', d.interface, 'device');

		uspots[d[".name"]] = {
		settings: {
			setname: d.setname,
			device,
			debug: d.debug,
		},
		clients: {},
		neighs: {},
		};

		devices[device] = d[".name"];
	}
});

if (!uciload) {
	let log = 'failed to load config';
	ERR(log);
	warn(log + '\n');
	exit(1);
}

function debug(uspot, msg) {
	if (+uspots[uspot].settings.debug)
		ulog(LOG_DEBUG, `${uspot} ${msg}`);
}

// wrapper for scraping external tools JSON stdout
function json_cmd(cmd) {
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
}

/**
 * Update client firewall state.
 *
 * @param {string} uspot the target uspot
 * @param {string} mac the target client MAC address
 * @param {boolean} state the intended state (true: allowed, false: denied)
 * @returns {number} nft command exit code
 *
 * NB: fw4 does not touch set content when reloading: we don't need to add a reload handler
 */
function client_state(uspot, mac, state)
{
	let settings = uspots[uspot].settings;
	let op = state ? 'add' : 'delete';
	let ret = system(`nft ${op} element inet fw4 ${settings.setname} { ${mac} }`);

	if (!state) {
		let client = uspots[uspot].clients[mac];

		if (!client)
			return ret;

		// purge existing connections
		for (let ipaddr in [client.ip4addr]) {
			if (ipaddr)
				system('conntrack -D -s ' + ipaddr);
		}
	}

	return ret;
}

/**
 * Check if a client is already allowed
 *
 * @param {string} uspot the target uspot
 * @param {string} mac the target client MAC address
 * @returns {number} 1 if client is allowed, 0 otherwise
 */
function client_allowed(uspot, mac)
{
	let settings = uspots[uspot].settings;
	let cmd = `nft -j list set inet fw4 ${settings.setname}`;
	let nft = json_cmd(cmd);
	let elem = nft?.nftables?.[1]?.set?.elem;

	return (lc(mac) in elem) ? 1 : 0;
}

/**
 * Disallow client access to the internet
 *
 * @param {string} uspot the target uspot
 * @param {string} mac the target client MAC address
 */
function client_remove(uspot, mac)
{
	debug(uspot, mac + ' client_remove');

	client_state(uspot, mac, 0);

	delete uspots[uspot].clients[mac];
}

// parse netlink NEIGH messages
function rtnl_neigh_cb(msg)
{
	let cmd = msg.cmd;	// NEIGH command
	msg = msg.msg;		// NEIGH message
	let mac = msg?.lladdr;
	let dev = msg?.dev;
	let dst = msg?.dst;
	let family = msg?.family;

	if (!dst || !dev)
		return;

	switch (family) {
	case rtnl.const.AF_INET:
		break;
	default:
		return;
	}

	let uspot = devices[dev];
	if (!uspot)	// not for us
		return;

	mac = uc(mac);
	let client = uspots[uspot].clients[mac];
	let neigh = uspots[uspot].neighs[dst];

	let state = msg.state;

	function lost_neigh()
	{
		if (neigh) {
			client = uspots[uspot].clients[neigh];
			if (client && (dst == client.ip4addr))
				client_remove(uspot, neigh);
		}
	}

	// new and updated neighs are cmd RTM_NEWNEIGH. Deleted neighs are RTM_DELNEIGH
	if (rtnl.const.RTM_DELNEIGH == cmd) {
		switch (state) {
			case rtnl.const.NUD_FAILED:
				lost_neigh();
				break;
			default:
				// NUD_STALE etc: mark allowed clients as idle, delete others.
				// Linux may aggressively delete neighs to make room even though they are still around
				// allowed idle clients will eventually be purged by uspot - idle_since can only be cleared when neigh is (re)set
				// WARNING: thus the ONLY case where a client may avoid deletion here is IFF it is allowed by uspot
				if (+client?.state)
					client.idle_since ??= time();
				else
					lost_neigh();
				break;
		}
		// we expect to eventually receive DELNEIGH messages for all added neighs
		delete uspots[uspot].neighs[dst];
	}
	else {	// RTM_NEWNEIGH
		// process REACHABLE / STALE / FAILED neighbour states
		switch (state) {
			case rtnl.const.NUD_REACHABLE:
				uspots[uspot].neighs[dst] = mac;
				if (client) {
					delete client.idle_since;
					client.ip4addr = dst;
				}
				else {
					uspots[uspot].clients[mac] = { ip4addr: dst };
				}
				break;
			case rtnl.const.NUD_STALE:
				if (client)
					client.idle_since ??= time();
				break;
			case rtnl.const.NUD_FAILED:
				// lladdr is no longer available in these states
				lost_neigh();
				delete uspots[uspot].neighs[dst];
				break;
		}
	}
}

function flush_nftsets()
{
	for (let name, uspot in uspots) {
		let setname = uspot.settings.setname;
		system(`nft flush set inet fw4 ${setname}`);
	}
}

function start()
{
	flush_nftsets();
	rtnl.listener(rtnl_neigh_cb, null, [ rtnl.const.RTNLGRP_NEIGH ]);
}

function stop()
{
	flush_nftsets();
	// XXX flush conntrack?
}

/*
 "client_set":{"interface":"String","address":"String","id":"String","state":"Integer","dns_state":"Integer","accounting":"Array","data":"Table","flush":"Boolean"}
 "client_remove":{"interface":"String","address":"String"}
 "client_get":{"interface":"String","address":"String"}
 "client_list":{"interface":"String"}
 */

function run_service() {
	uconn.publish("spotfilter", {
	client_get: {
		call: function(req) {
			let uspot = req.args.interface;
			let address = req.args.address;

			if (!uspot || !address)
				return ubus.STATUS_INVALID_ARGUMENT;
			if (!(uspot in uspots))
				return ubus.STATUS_INVALID_ARGUMENT;

			address = uc(address);

			let state = client_allowed(uspot, address);
			let device = uspots[uspot].settings.device;

			return { ... uspots[uspot].clients[address] || {}, state, device, };
		},
		/*
		 Get client data for a given uspot.
		 @param interface: REQUIRED: target uspot
		 @param address: REQUIRED: target client MAC address
		 */
		args: {
			interface:"",
			address:"",
		}
	},
	client_set: {
		call: function(req) {
			let uspot = req.args.interface;
			let address = req.args.address;
			let state = req.args.state || 0;
			let data = req.args.data;
			let flush = !!req.args.flush;

			if (!uspot || !address)
				return ubus.STATUS_INVALID_ARGUMENT;
			if (!(uspot in uspots))
				return ubus.STATUS_INVALID_ARGUMENT;

			address = uc(address);

			if (flush) {
				if (!uspots[uspot].clients[address])
					return 0;
				client_remove(uspot, address);
				return 0;
			}

			let client = {
				... uspots[uspot].clients[address] || {},
				state,
				data,
			};

			if (state)
				delete client.idle_since;	// clear up leftover idle time

			uspots[uspot].clients[address] = client;

			client_state(uspot, address, state);

			return 0;
		},
		/*
		 Set client state in a given uspot.
		 @param interface: REQUIRED: target uspot
		 @param address: REQUIRED: target client MAC address
		 @param id: IGNORED
		 @param state: 1 to allow client, 0 to disallow
		 @param dns_state: IGNORED
		 @param accounting: IGNORED
		 @param data: OPTIONAL client opaque data, stored with client state
		 @param flush: OPTIONAL true to disallow client and delete associated data
		 */
		args: {
			interface:"",
			address:"",
			id:"",
			state:0,
			dns_state:0,
			accounting:[],
			data:{},
			flush:false,
		}
	},
	client_remove: {
		call: function(req) {
			let uspot = req.args.interface;
			let address = req.args.address;

			if (!uspot || !address)
				return ubus.STATUS_INVALID_ARGUMENT;
			if (!(uspot in uspots))
				return ubus.STATUS_INVALID_ARGUMENT;

			address = uc(address);

			if (!uspots[uspot].clients[address])
				return 0;

			client_remove(uspot, address);

			return 0;
		},
		/*
		 Remove client from a given uspot.
		 @param interface: REQUIRED: target uspot
		 @param address: REQUIRED: target client MAC address
		 */
		args: {
			interface:"",
			address:"",
		}
	},
	client_list: {
		call: function(req) {
			let uspot = req.args.interface;

			if (!uspot)
				return ubus.STATUS_INVALID_ARGUMENT;
			if (!(uspot in uspots))
				return ubus.STATUS_INVALID_ARGUMENT;

			let clients = uspots[uspot].clients;

			return clients;
		},
		/*
		 List all clients for a given uspot.
		 @param interface: REQUIRED: target uspot
		 */
		args: {
			interface:"",
		}
	},
	peer_lookup: {
		call: function(req) {
			let ip = req.args.ip;

			if (!ip)
				return ubus.STATUS_INVALID_ARGUMENT;

			for (let uspot, d in uspots) {
				let neigh = d.neighs[ip];
				if (neigh)
					return { mac: lc(neigh), uspot };
			}

			return {};
		},
		/*
		 Lookup a peer IP in internal neigh database to find its MAC and corresponding uspot.
		 @param ip: REQUIRED: IP to lookup
		 */
		args: {
			ip:"",
		}
	},
	});

	try {
		start();
		uloop.run();
	} catch (e) {
		warn(`Error: ${e}\n${e.stacktrace[0].context}`);
	}
}

uloop.init();
run_service();
uloop.done();
stop();
