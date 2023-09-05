{%

'use strict';

global.handle_request = function(env) {
	include('templates/cpd.uc', { env });
};
%}
