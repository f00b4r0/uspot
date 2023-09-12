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
		};

		include('templates/api.uc', { api } );
	}
};

%}
