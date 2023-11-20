#!/usr/bin/ucode
// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Thibaut Varène <hacks@slashdirt.org>
// uspotfilter - uspot interface to netfilter

'use strict';

let fs = require('fs');
let uloop = require('uloop');
let ubus = require('ubus');
let uconn = ubus.connect();
let uci = require('uci').cursor();
let rtnl = require('rtnl');

let uspots = {};
let devices = {};

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
	let log = 'uspotfilter: failed to load config';
	system('logger ' + log);
	warn(log + '\n');
	exit(1);
}

function syslog(uspot, mac, msg) {
	let log = sprintf('uspotfilter: %s %s %s', uspot, mac, msg);

	system('logger \'' + log + '\'');
	warn(log + '\n');
}

function debug(uspot, mac, msg) {
	if (+uspots[uspot].settings.debug)
		syslog(uspot, mac, msg);
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

// NB: fw4 does not touch set content when reloading
function client_state(uspot, mac, state)
{
	let settings = uspots[uspot].settings;
	let op = state ? 'add' : 'delete';
	return system(`nft ${op} element inet fw4 ${settings.setname} { ${mac} }`);
}

function client_allowed(uspot, mac)
{
	let settings = uspots[uspot].settings;
	let cmd = `nft -j list set inet fw4 ${settings.setname}`;
	let nft = json_cmd(cmd);
	let elem = nft?.nftables?.[1]?.set?.elem;

	return (lc(mac) in elem) ? 1 : 0;
}

function client_remove(uspot, mac)
{
	let client = uspots[uspot].clients[mac];

	if (!client)
		return 0;

	debug(uspot, mac, 'client_remove');

	client_state(uspot, mac, 0);

	// purge existing connections
	for (let ipaddr in [client.ip4addr, client.ip6addr]) {
		if (ipaddr) {
			system('conntrack -D -s ' + ipaddr);
			// keep neighs in sync
			delete uspots[uspot].neighs[ipaddr];
		}
	}

	delete uspots[uspot].clients[mac];
}

// parse netlink NEIGH messages
function rtnl_neigh_cb(msg)
{
	let cmd = msg.cmd;
	msg = msg.msg;
	let mac = msg?.lladdr;
	let dev = msg?.dev;
	let dst = msg?.dst;
	let family = msg?.family;

	if (!dst || !dev)
		return;

	switch (family) {
	case rtnl.const.AF_INET6:
		if (substr(dst, 0, 4) == "fe80")
			return;	// ignore link local addresses
		// fallthrough
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

	function del_neigh()
	{
		if (neigh) {
			client = uspots[uspot].clients[neigh];
			if (client) {
				// check dst matches current client ipaddr as ip change could occur (ipv6 privacy randomisation)
				if ((rtnl.const.AF_INET6 == family) && (dst == client.ip6addr))
					delete client.ip6addr;
				else if ((rtnl.const.AF_INET == family) && (dst == client.ip4addr))
					delete client.ip4addr;
				// purge client if both ip4/6 neigh addrs are gone
				if (!client.ip4addr && !client.ip6addr)
					client_remove(uspot, neigh);
			}
			// we expect to eventually receive FAILED/INCOMPLETE or DELNEIGH messages for all added neighs
			delete uspots[uspot].neighs[dst];
		}
	}

	// new and updated neighs are cmd RTM_NEWNEIGH. Deleted neighs are RTM_DELNEIGH
	if (rtnl.const.RTM_DELNEIGH == cmd)
		del_neigh();
	else {	// RTM_NEWNEIGH
		// process REACHABLE / STALE / FAILED neighbour states
		switch (state) {
			case rtnl.const.NUD_REACHABLE:
				uspots[uspot].neighs[dst] = mac;
				if (client) {
					delete client.idle_since;
					if (rtnl.const.AF_INET6 == family)
						client.ip6addr = dst;
					else
						client.ip4addr = dst;
				}
				else {
					if (rtnl.const.AF_INET6 == family)
						uspots[uspot].clients[mac] = { ip6addr: dst };
					else
						uspots[uspot].clients[mac] = { ip4addr: dst };
				}
				break;
			case rtnl.const.NUD_STALE:
				if (client && !client.idle_since)
					client.idle_since = time();
				break;
			case rtnl.const.NUD_FAILED:
				// lladdr is no longer available in these states
				del_neigh();
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
				client_state(uspot, address, 0);
				delete uspots[uspot].clients[address];
				return 0;
			}

			let client = {
				... uspots[uspot].clients[address] || {},
				state,
				data,
			};

			uspots[uspot].clients[address] = client;

			client_state(uspot, address, state);

			return 0;
		},
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

			client_remove(uspot, address);

			return 0;
		},
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
		 @param uspot: REQUIRED: target uspot
		 */
		args: {
			interface:"",
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
