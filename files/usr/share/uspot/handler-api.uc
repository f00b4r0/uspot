{%
// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022-2023 John Crispin <john@phrozen.org>
// SPDX-FileCopyrightText: 2023 Thibaut Varène <hacks@slashdirt.org>

'use strict';

push(REQUIRE_SEARCH_PATH, "/usr/share/uspot/*.uc");

let portal = require('portal');

global.handle_request = function(env) {
	let ctx = portal.handle_request(env);

	if (ctx) {
		let api = {
			captive: !ctx.connected,
			'user-portal-url': "https://" + env.HTTP_HOST + "/hotspot",
			'can-extend-session': !!ctx.config.cpa_can_extend,
		};
		if (ctx.config.cpa_venue_url)
			api['venue-info-url'] = ctx.config.cpa_venue_url;

		if (!api.captive) {
			/*
			 seconds-remaining	number
			 An integer that indicates the number of seconds remaining, after which the client will be placed
			 into a captive state. The API server SHOULD include this value if the client is not captive
			 (i.e., captive=false) and the client session is time-limited and SHOULD omit this value
			 for captive clients (i.e., captive=true) or when the session is not time-limited.
			 */
			if (ctx.seconds_remaining)
				api['seconds-remaining'] = ctx.seconds_remaining;

			/*
			 bytes-remaining	number
			 An integer that indicates the number of bytes remaining, after which the client will be placed
			 into a captive state. The byte count represents the sum of the total number of IP packet (layer 3)
			 bytes sent and received by the client, including IP headers. Captive Portal systems might not
			 count traffic to whitelisted servers, such as the API server, but clients cannot rely on such
			 behavior. The API server SHOULD include this value if the client is not captive (i.e., captive=false)
			 and the client session is byte-limited and SHOULD omit this value for captive clients
			 (i.e., captive=true) or when the session is not byte-limited.
			 */
			if (ctx.bytes_remaining)
				api['bytes-remaining'] = ctx.bytes_remaining;
		}

		include('templates/api.ut', { api } );
	}
};

%}
