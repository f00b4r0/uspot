// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2025 Thibaut Varène <hacks@slashdirt.org>

/* map contents:
 struct uspotbpf_cdata {
	 uint8_t flags;
	 uint64_t packets_in;
	 uint64_t bytes_in;
	 uint64_t packets_out;
	 uint64_t bytes_out;
 };
 */

'use strict';

let bpf = require("bpf");
import { pack, unpack } from 'struct';

const prio = 0x100;	// prio must be higher than that of ratelimit

function client_key(mac)
{
	let key = map(split(mac, ":"), hex);
	return pack("6B", ...key);	// network is big endian, string byte order is correct as is
}

let ctx = {};

function init(devname)
{
	let bpf_mod = bpf.open_module("/lib/bpf/uspot.o", {
		"program-type": {
			uspotbpf_acct_i: bpf.BPF_PROG_TYPE_SCHED_CLS,
			uspotbpf_acct_o: bpf.BPF_PROG_TYPE_SCHED_CLS,
		}
	});
	assert(bpf_mod, `Could not load BPF module: ${bpf.error()}`);

	let map = bpf_mod.get_map("m_clients");
	assert(map, `map open failed: ${bpf.error()}`);

	let prog = {
		ingress: bpf_mod.get_program("uspotbpf_acct_i"),
		egress: bpf_mod.get_program("uspotbpf_acct_o"),
	};
	assert(prog.ingress && prog.egress, `prog open failed: ${bpf.error()}`);

	ctx[devname] = { bpf_mod, prog, map, };
	/* we need to carry a reference to bpf_mod throughout execution to workaround a bug in ucode-mod-bpf:
	 <nbd> when the reference to the bpf module is dropped, it calls bpf_object__close internally
	 <nbd> so all program references also become invalid
	 Fixed in openwrt#e4c3c236b8f15e05b46d23d1771262e75d5b8f81 */
}

function exit(devname)
{
	delete ctx[devname];
}

return {
	load: function(devname)
	{
		init(devname);
		for (let type in ["egress", "ingress"])
			if (!ctx[devname].prog[type].tc_attach(devname, type, prio))
				return bpf.error();
	},

	unload: function(devname)
	{
		for (let type in ["egress", "ingress"])
			bpf.tc_detach(devname, type, prio);
		exit(devname);
	},

	client_add: function(devname, mac, tx, rx)
	{
		let flags = ((tx ? 1 : 0) << 0) | ((rx ? 1 : 0) << 1);
		if (ctx[devname])
			if (!ctx[devname].map.set(client_key(mac), pack("BQQQQ", flags, 0, 0, 0, 0)))
				return bpf.error();
	},

	client_del: function(devname, mac)
	{
		if (ctx[devname])
			ctx[devname].map.delete(client_key(mac));
	},

	client_get: function(devname, mac)
	{
		if (!ctx[devname])
			return {};

		let cdata = ctx[devname].map.get(client_key(mac));
		if (!cdata)
			return {};

		cdata = unpack("BQQQQ", cdata);
		return {
			packets_in: cdata[1],
			bytes_in: cdata[2],
			packets_out: cdata[3],
			bytes_out: cdata[4],
		};
	},
};
