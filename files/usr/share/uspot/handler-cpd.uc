{%

'use strict';

let uci = require('uci').cursor();
let config = uci.get_all('uspot');

global.handle_request = function(env) {
	if (env.REMOTE_ADDR && +config?.def_captive?.debug)
		warn('uspot: ' + env.REMOTE_ADDR + ' - CPD redirect\n');
	include('templates/cpd.uc', { env });
};
%}
