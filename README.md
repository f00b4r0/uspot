# uspot

A captive portal system

## Description

uspot implements a captive portal supporting click-to-continue, simple credential-based as well as RADIUS authentication.
uspot is UAM capable, and has limited support for RFC5176 RADIUS Dynamic Authorization Extensions.

It is intended to be an alternative to e.g. CoovaChilli/ChilliSpot, fully compatible with OpenWrt:
it leverages existing OpenWrt tools such as uhttpd, dnsmasq, firewall, ucode.

The software consists of several parts:
- A web frontend handling client user interface and Captive Portal Detection duties
- A client management backend handling client authentication and accounting
- A RADIUS Dynamic Authorization Server for RFC5176 support

## Configuration

The available configuration options and their defaults are listed in the provided [files/etc/config/uspot] configuration file.

To achieve a fully operational captive portal, additional components must be configured:
- dnsmasq for serving DHCP to captive clients
- firewall for traffic management
- uhttpd for the web interface

The OpenWrt configuration snippets below assume that a dedicated network interface named 'captive' has been created
and will be dedicated to the captive portal, and that a similarly named 'captive' uspot section is configured.

The 'captive' network interface is assumed to have a static IPv4 address of '10.0.0.1'.
The provided configuration sets up an IPv4 captive portal.

### config/dhcp

```
config dhcp 'captive'
	option interface 'captive'
	option start '2'
	option limit '1000'
	option leasetime '2h'
	# add the following for RFC8910 Captive Portal API - DNS name is setup below
	list dhcp_option_force '114,https://captive.example.org/api'

# add a local domain name for HTTPS support, name must match TLS certificate
config domain
	option name 'captive.example.org'
	option ip '10.0.0.1'
```

This snippet will allow up to 1000 captive clients on interface 'captive' with a 2h lease time.
The DNS name `captive.example.org` aliases the 'captive' interface IP for TLS support
(public TLS certificates cannot be obtained for private IP addresses): a valid, publicy-signed TLS certificate
will have to be created and provided for this to work. The RFC requires the API to be accessed over TLS.

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
	option mark '!1/127'

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
	option mark '1/127'

# allow DHCP for captive clients
config rule
	option name 'Allow-DHCP-captive'
	option src 'captive'
	option proto 'udp'
	option dest_port '67'
	option target 'ACCEPT'

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

# TODO: allow NTP for TLS validation - in spotfilter?
```

In the `Allow-captive-CPD-WEB-UAM` rule, port 80 is always required for CPD.
Port 443 is only required if using TLS UAM and/or enabling RFC8908 (Captive Portal API) support which can only operate over HTTPS.
Port 3990 is only required if using RADIUS UAM, and can be adjusted to match the value of `uam_port` in `config/uspot`.

The optional rule `Allow-captive-DAE` allows incoming WAN traffic to the local RADIUS Dynamic Authorization Server.
It is highly recommended to add restrictions on allowed source IP, since the server is very simple and does not implement
any security defense mechanism.

### config/uhttpd

In new OpenWrt installations, uhttpd listens on all interfaces on port 80 by default, which would conflict with the
captive portal operation. So first, the default instance must be disabled or either set to listen to a
different port (e.g. 8080), or listen only on the LAN interface. This last option can be achieved using the
following uci commands, assuming a LAN IP of "192.168.1.1":

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
	option cert '/usr/share/certs/captive.crt'	# to be provided manually
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

MAC="$2"
IP="$3"
NETID="${DNSMASQ_TAGS%% *}"

if [ "captive" == "$NETID" ]; then
	ubus call uspot client_auth "{ \"uspot\":\"$NETID\", \"address\":\"$MAC\", \"client_ip\":\"$IP\" }"
	ubus call uspot client_enable "{ \"uspot\":\"$NETID\", \"address\":\"$MAC\" }"	# this will fail anyway if auth was denied
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
