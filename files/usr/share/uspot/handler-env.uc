{%

'use strict';

global.handle_request = function(env) {
	include("templates/dump-env.ut", { env });
};
