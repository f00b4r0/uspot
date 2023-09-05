{%

'use strict';

global.handle_request = function(env) {
	include("templates/dump-env.uc", { env });
};
