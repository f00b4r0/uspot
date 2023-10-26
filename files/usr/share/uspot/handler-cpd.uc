{%

'use strict';

import { urlencode, ENCODE_FULL } from 'lucihttp';

global.handle_request = function(env) {
	// this is only used in HTTP CPD "hijack" context: only for HTTP requests to some other host
	let redir = "http://" + env.HTTP_HOST + env.REQUEST_URI;
	redir = urlencode(redir, ENCODE_FULL);

	let redir_location = `http://${env.SERVER_ADDR}/hotspot/?redir=${redir}`;

	include('templates/redir.ut', { redir_location });
};
%}
