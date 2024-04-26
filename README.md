# uspot

A captive portal system for OpenWrt

## Description

uspot implements a captive portal supporting click-to-continue, simple credential-based as well as RADIUS authentication.
uspot is UAM capable, supports RFC8908 Captive Portal API and has limited support for RFC5176 RADIUS Dynamic Authorization Extensions.

It is intended to be an alternative to e.g. CoovaChilli/ChilliSpot, fully compatible with OpenWrt:
it leverages existing OpenWrt tools such as uhttpd, dnsmasq, firewall4, ucode.

The software consists of several parts:
- A web frontend handling client user interface, local UAM and Captive Portal Detection duties
- A client management backend handling client authentication and accounting
- A firewall wrapper managing client network access and disconnection detection
- A RADIUS Dynamic Authorization Server for RFC5176 support

uspot requires OpenWrt 23.05 or newer.

### Features

uspot supports 4 authentication modes:
- `click-to-continue` provides a very simple "accept ToU and click to continue" interface
- `credentials` provides a simple username/password authentication (usernames and passwords defined in configuration)
- `radius` also provides a simple username/password authentication, but queries a RADIUS server for credentials validation
- `uam` enables RADIUS UAM authentication using a remote web portal

In `radius` and `uam` modes:
- RADIUS accounting is supported (only 'Session-Time' is reported for now)
- text and CHAP passwords are supported

In `uam` mode, MAC-based authentication bypass is supported.

uspot supports Captive Portal API (RFC8908), and supports some RADIUS DAE (RFC5176) Disconnect and CoA operations
(see comments in [radius-das.c](src/radius-das.c) for details on which attributes are supported).

In conjunction with [ratelimit](https://github.com/f00b4r0/ratelimit), uspot supports per-client bandwidth restriction.

uspot does not support state persistence: restarting uspot will reset client state.

## License

GPLv2-only - http://www.gnu.org/licenses/gpl-2.0.html

- Copyright (C) 2022-2023 John Crispin
- Copyright (C) 2023-2024 Thibaut VARÈNE

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License version 2,
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

See [LICENSE.md](LICENSE.md) for details.

## Configuration

The available configuration options and their defaults are listed in the provided [uspot](files/etc/config/uspot) configuration file.

To achieve a fully operational captive portal, additional components must be configured:
- firewall for traffic management
- dnsmasq for serving DHCP to captive clients
- uhttpd for the web interface

The OpenWrt configuration snippets below assume that a dedicated network interface named 'captive' has been created
and will be dedicated to the captive portal, and that a similarly named 'captive' uspot section is configured
in `/etc/config/uspot`.

The 'captive' network interface is assumed to have a static IPv4 address of '10.0.0.1/22'.
The provided configuration sets up an IPv4 captive portal.

### config/firewall

A dedicated firewall zone is created for the captive portal.
By default this zone is not allowed to forward traffic to the WAN zone, and all incoming traffic is rejected.
Specific ports are opened for correct operation of the captive portal.

```
# create a 'captive' zone for captive portal traffic
config zone
	option name 'captive'
	list network 'captive'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'

# setup CPD hijacking for unauthenticated clients
config redirect
	option name 'Redirect-unauth-captive-CPD'
	option src 'captive'
	option src_dport '80'
	option proto 'tcp'
	option target 'DNAT'
	option reflection '0'
	option ipset '!uspot'	# match with uspot option 'setname'

# allow DHCP for captive clients
config rule
	option name 'Allow-DHCP-NTP-captive'
	option src 'captive'
	option proto 'udp'
	option dest_port '67 123'
	option target 'ACCEPT'

# prevent access to LAN-side services from captive interface
# Linux implements a weak host model and traffic crossing zone boundary isn't considered forwarding on the router:
# it must be explicitely denied - NB order matter: DHCP is broadcast that would be caught by this rule
config rule
	option name 'Restrict-input-captive'
	option src 'captive'
	option dest_ip '!captive'
	option target 'DROP'

# allow incoming traffic to CPD / web interface and local UAM server
config rule
	option name 'Allow-captive-CPD-WEB-UAM'
	option src 'captive'
	option dest_port '80 443 3990'
	option proto 'tcp'
	option target 'ACCEPT'

# allow forwarding traffic to wan from authenticated clients
config rule
	option name 'Forward-auth-captive'
	option src 'captive'
	option dest 'wan'
	option proto 'any'
	option target 'ACCEPT'
	option ipset 'uspot'	# match with uspot option 'setname'

# allow DNS for captive clients
config rule
	option name 'Allow-DNS-captive'
	option src 'captive'
	list proto 'udp'
	list proto 'tcp'
	option dest_port '53'
	option target 'ACCEPT'
	
# if using RFC5176 RADIUS DAE:
config rule
	option name 'Allow-captive-DAE'
	option src 'wan'
	option proto 'udp'
	option family 'ipv4'
	option src_ip 'XX.XX.XX.XX'	# adjust as needed
	option dest_port '3799'		# match value for 'das_port' in config/uspot
	option target 'ACCEPT'

# create the ipset that will hold authenticated clients
config ipset
	option name 'uspot'	# match with uspot option 'setname'
	list match 'src_mac'

# optional whitelist for e.g. remote UAM host and/or dynamic hosts via dnsmasq ipset functionality
config rule
	option name 'Allow-Whitelist'
	option src 'captive'
	option dest 'wan'
	option proto 'any'
	option ipset 'wlist'
	option target 'ACCEPT'

# associated whitelist ipset with prepopulated entries
config ipset
	option name 'wlist'
	list match 'dest_ip'
	list entry 'XX.XX.XX.XX'	# adjust as needed for e.g. remote UAM server
	list entry 'XX.XX.XX.XX'

```

In the `Allow-captive-CPD-WEB-UAM` rule, port 80 is always required for CPD.
Port 443 is only required if using TLS UAM and/or enabling RFC8908 (Captive Portal API) support which can only operate over HTTPS.
Port 3990 is only required if using RADIUS UAM, and can be adjusted to match the value of `uam_port` in `config/uspot`.

The optional rule `Allow-captive-DAE` allows incoming WAN traffic to the local RADIUS Dynamic Authorization Server.
It is highly recommended to add restrictions on allowed source IP, since the server is very simple and does not implement
any security defense mechanism.

Note: uspot is compatible with firewall offloading.

### config/dhcp

```
config dhcp 'captive'
	option interface 'captive'
	option start '2'
	option limit '1000'
	option leasetime '2h'
	# add the following for RFC8910 Captive Portal API - DNS name is setup below
	list dhcp_option '114,https://captive.example.org/api'
	# optionally provide NTP server (if enabled on the device) - recommended for SSL cert validation
	list dhcp_option_force '42,10.0.0.1'

# add a local domain name for HTTPS support, name must match TLS certificate
config domain
	option name 'captive.example.org'
	option ip '10.0.0.1'

# if using optional dynamic hosts whitelist
config ipset
	list name 'wlist'	# match value with whitelist ipset name in config/firewall
	list domain 'my.whitelist1.domain'
	list domain 'my.whitelist2.domain'
```

This snippet will allow up to 1000 (modulo the captive network netmask) captive clients on interface 'captive' with a 2h lease time.
The DNS name `captive.example.org` aliases the 'captive' interface IP for TLS support
(public TLS certificates cannot be obtained for private IP addresses): a valid, CA-signed TLS certificate
will have to be created and provided for this to work. The RFC requires the API to be accessed over TLS.

### config/uhttpd

In new OpenWrt installations, uhttpd listens on all interfaces on port 80 by default, which would conflict with the
captive portal operation. So first, the default instance must be disabled or either set to listen to a
different port (e.g. 8080), or listen only on the LAN interface. This last option can be achieved using the
following uci commands, assuming a LAN IP of '192.168.1.1':

```
uci delete uhttpd.main.listen_http
uci add_list uhttpd.main.listen_http="192.168.1.1:80"
uci commit
```

Next, the uspot web interface and CPD/UAM handlers must be setup through separate instances:

```
config uhttpd 'uspot'
	list listen_http '10.0.0.1:80'
	option redirect_https '0'
	option max_requests '5'
	option no_dirlists '1'
	option home '/www-uspot'
	list ucode_prefix '/hotspot=/usr/share/uspot/handler.uc'
	list ucode_prefix '/cpd=/usr/share/uspot/handler-cpd.uc'
	option error_page '/cpd'
	# if using TLS and/or supporting RFC8908 CapPort API:
	list listen_https '10.0.0.1:443'
	option cert '/usr/share/certs/captive.pem'	# to be provided manually
	option key '/usr/share/certs/captive.key'	# to be provided manually
	# for RFC8908 support:
	list ucode_prefix '/api=/usr/share/uspot/handler-api.uc'

# if using RADIUS UAM authentication:
config uhttpd 'uam3990'
	list listen_http '10.0.0.1:3990'
	option redirect_https '0'
	option max_requests '5'
	option no_dirlists '1'
	option home '/www-uspot'
	list ucode_prefix '/logon=/usr/share/uspot/handler-uam.uc'
	list ucode_prefix '/logoff=/usr/share/uspot/handler-uam.uc'
	list ucode_prefix '/logout=/usr/share/uspot/handler-uam.uc'

```

As mentioned previously, the creation of the captive portal TLS certificate is required and not documented here.

### Extra features

When using RADIUS MAC address authentication, it is possible to speed up client authentication
and bypass the web interface by using e.g. the following extra DHCP script:

```sh
#!/bin/sh

ACTION="$1"
MAC="$2"
IP="$3"
NETID="${DNSMASQ_TAGS%% *}"

if [ "captive" == "$NETID" ]; then
	case "$ACTION" in
	add|old)
		ubus call uspot client_auth "{ \"uspot\":\"$NETID\", \"address\":\"$MAC\", \"client_ip\":\"$IP\" }" > /dev/null
		ubus call uspot client_enable "{ \"uspot\":\"$NETID\", \"address\":\"$MAC\" }" 2>/dev/null	# this will fail anyway if auth was denied
	;;
	esac
fi
```

This requires the `networkid` option to be set in the captive portal DHCP configuration to the value matching the
`config/uspot` section. If following the above configuration example, this can be achieved as follows:

```
uci set dhcp.captive.networkid='captive'
uci commit dhcp
```

Assuming this script is saved to e.g. `/root/captivescript.sh`, the following extra dnsmasq configuration will enable it:

```
uci set dhcp.@dnsmasq[0].dhcpscript='/root/captivescript.sh'
uci commit dhcp
```

When a client connects to the network, if its MAC is authorized the script will automatically authenticate the client
with the captive portal, without further action. 

**NB:** please note that this is a hackish work around to bypass the web interface but is not actually a "feature" in any respect.
Uspot _is_ a captive _portal_ after all. Bugs arising from using this hack will most likely not be considered.

### radcli

uspot does not install the dictionaries required by libradcli by default (to avoid conflicts).
They are provided in [radcli/](files/etc/radcli/) for your convenience.

## UAM interface

When configured for UAM operation, the follwing UAM URL parameters are provided by uspot in the query string to the remote UAM server:

 - `res`: can be one of `success`, `reject`, `notyet` and `logoff`
 - `uamip`: the uspot local web server address
 - `uamport`: the uspot local UAM server port (as configured with `uam_port` configuration option)
 - `challenge`: MD5 challenge string (from `challenge` configuration option + formatted MAC address)
 - `mac`: the formatted (via optional `format_mac` configuration option) client MAC address
 - `ip`: the web client IP address
 - `called`: the configured `nasmac`
 - `nasid`: the configured `nasid`
 - `sessionid`: the unique session identifier for this client request

Optionally, depending on local configuration and/or RADIUS parameters, the following extra parameters may be provided:

 - `timeleft`: seconds remaining for sessions with a set timeout
 - `ssl`: the configured `uam_sslurl` (urlencoded)
 - `userurl`: when CPD is used, the user-provided URL that was caught (urlencoded)
 - `reply`: the Reply-Message received from RADIUS (urlencoded)
 - `lang`: passed to-from UAM frontend and reflected in RADIUS ChilliSpot-Lang attribute 
 - `md`: when `uam_secret` is configured, the UAM URL MD5 checksum 

## Caveat

uspot has been primarily tested with IPv4 captive clients.

uspotfilter uses a RTNL listener to detect client state changes (disconnection in particular).
There are limitations in the RTNL implementation that may cause, under specific circumstances,
RTNL messages to be lost (see https://github.com/jow-/ucode/issues/184).
This could result in lingering sessions if e.g. said sessions do not have a set timeout.  
These limitations have been mitigated in ucode (see https://github.com/jow-/ucode/pull/185),
which means that the probability for such occurrences is expected to be low.

## TODO

- UI internationalization (i18n)
- traffic accounting
- IPv6 support in uspotfilter
