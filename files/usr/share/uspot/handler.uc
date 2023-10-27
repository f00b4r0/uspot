{%
// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022-2023 John Crispin <john@phrozen.org>
// SPDX-FileCopyrightText: 2023 Thibaut Varène <hacks@slashdirt.org>

'use strict';

push(REQUIRE_SEARCH_PATH, "/usr/share/uspot/*.uc");
let portal = require('portal');

// delegate an initial connection to the correct handler
function request_start(ctx) {
	portal.debug(ctx, 'start ' + (ctx.config.auth_mode || '') + ' flow');
	switch (ctx.config.auth_mode) {
	case 'click-to-continue':
		include('templates/click.ut', ctx);
		return;
	case 'credentials':
	case 'radius':
		include('templates/credentials.ut', ctx);
		return;
	case 'uam':
		// try mac-auth first if enabled
		if (+ctx.config.mac_auth) {
			let auth = portal.uspot_auth(ctx);
			if (auth && auth['access-accept']) {
				let redir = (ctx.config.final_redirect_url == 'uam') ? portal.uam_url(ctx, 'success') : ctx.config.final_redirect_url;
				portal.allow_client(ctx, redir);
				return;
			}
		}
		ctx.redir_location = portal.uam_url(ctx, 'notyet');
		include('templates/redir.ut', ctx);
		return;
	default:
		include('templates/error.ut', ctx);
		return;
	}
}

// delegate a local click-to-continue authentication
function request_click(ctx) {
	// make sure this is the right auth_mode
	if (ctx.config.auth_mode != 'click-to-continue') {
		include('templates/error.ut', ctx);
		return;
	}

	// check if a username and password was provided
	if (ctx.form_data.accept_terms != 'clicked') {
		portal.debug(ctx, 'user did not accept conditions');
		request_start({ ...ctx, error: 1 });
		return;
	}
	portal.uspot_auth(ctx);
	portal.allow_client(ctx);
}

// delegate username/password authentication
function request_credentials(ctx) {
	// make sure this is the right auth_mode
	if (ctx.config.auth_mode != ctx.form_data.action) {
		include('templates/error.ut', ctx);
		return;
	}

	// check if a username and password was provided
	if (!ctx.form_data.username || !ctx.form_data.password) {
		portal.debug(ctx, 'missing credentials');
		request_start({ ...ctx, error: 1 });
		return;
	}

	// check if the credentials are valid
	let auth = portal.uspot_auth(ctx, ctx.form_data.username, ctx.form_data.password);
	if (auth && auth['access-accept']) {
		portal.allow_client(ctx);
		return;
	}

	// auth failed
	portal.debug(ctx, 'invalid credentials');
	request_start({ ...ctx, error: 1 });
}

global.handle_request = function(env) {
	let ctx = portal.handle_request(env);

	if (!ctx)
		return;

	if (ctx.connected) {
		include('templates/connected.ut', ctx);
		return;
	}

	switch (ctx.form_data.action) {
	case 'credentials':
	case 'radius':
		request_credentials(ctx);
		return;
	case 'click':
		request_click(ctx);
		return;
	default:
		request_start(ctx);
		return;
	}
};

%}
