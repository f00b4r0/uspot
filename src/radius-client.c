/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * A simple JSON to radius client.
 * Copyright (C) 2022 John Crispin <john@phrozen.org>
 * Copyright (C) 2023,2025 Thibaut Varène <hacks@slashdirt.org>
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include <arpa/inet.h>

#include <radcli/radcli.h>

// compat defines for pre 1.3 libradcli
#ifndef RC_NAME_LENGTH
 #define RC_NAME_LENGTH NAME_LENGTH
#endif
#ifndef VENDOR_BIT_SIZE
 #define VENDOR_BIT_SIZE 16
#endif

#define RADCLI_DICT		"/etc/radcli/dictionary"

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/ulog.h>

enum {
	RADIUS_acct,
	RADIUS_authserver,
	RADIUS_acctserver,
	RADIUS_servtype,
	RADIUS_ACCT_TYPE,
	RADIUS_USERNAME,
	RADIUS_PASSWORD,
	RADIUS_CHAP_PASSWORD,
	RADIUS_CHAP_CHALLENGE,
	RADIUS_ACCT_SESSION,
	RADIUS_CLIENT_IP,
	RADIUS_CALLED_STATION,
	RADIUS_CALLING_STATION,
	RADIUS_NAS_IP,
	RADIUS_NAS_ID,
	RADIUS_TERMINATE_CAUSE,
	RADIUS_SESSION_TIME,
	RADIUS_INPUT_OCTETS,
	RADIUS_OUTPUT_OCTETS,
	RADIUS_INPUT_GIGAWORDS,
	RADIUS_OUTPUT_GIGAWORDS,
	RADIUS_INPUT_PACKETS,
	RADIUS_OUTPUT_PACKETS,
	RADIUS_LOGOFF_URL,
	RADIUS_CLASS,
	RADIUS_SERVICE_TYPE,
	RADIUS_PROXY_STATE_ACCT,
	RADIUS_PROXY_STATE_AUTH,
	RADIUS_LOCATION_NAME,
	RADIUS_NAS_PORT_TYPE,
	RADIUS_CUI,
	RADIUS_REPLY_MESSAGE,
	RADIUS_LANG,
	__RADIUS_MAX,
};

static struct blobmsg_policy radius_policy[__RADIUS_MAX] = {
	[RADIUS_acct] = { .name = "acct", .type = BLOBMSG_TYPE_BOOL },
	[RADIUS_authserver] = { .name = "server", .type = BLOBMSG_TYPE_STRING },
	[RADIUS_acctserver] = { .name = "acct_server", .type = BLOBMSG_TYPE_STRING },
	[RADIUS_servtype] = { .name = "serv_type", .type = BLOBMSG_TYPE_STRING },
	[RADIUS_PROXY_STATE_AUTH] = { .name = "auth_proxy", .type = BLOBMSG_TYPE_STRING },
	[RADIUS_PROXY_STATE_ACCT] = { .name = "acct_proxy", .type = BLOBMSG_TYPE_STRING },
};

static struct blob_buf b = {};
static struct blob_attr *tb[__RADIUS_MAX] = {};

static int cb_ip(void * p, size_t s, struct blob_attr *b);
static int cb_chap_passwd(void * p, size_t s, struct blob_attr *b);
static int cb_chap_challenge(void * p, size_t s, struct blob_attr *b);

#define VENDORSPEC_WBAL			14122
#define ATTR_WBAL_WISPR_LOCATION_NAME	2
#define ATTR_WBAL_WISPR_LOGOFF_URL	3

#define VENDORSPEC_CHILLI		14559
#define ATTR_CHILLI_CHILLISPOT_LANG	7

/** Internal keys to radcli association table */
static const struct {
	uint32_t attrid;		///< radcli attribute ID
	uint32_t vendorspec;		///< radcli vendorspec ID
	/**
	 * Optional callback for data processing.
	 * Takes a pointer to allocated output space (size as second arg), and a pointer to current blob_attr.
	 * Output will be passed verbatim to rc_avpair_add(). Returns output length.
	 */
	int (*const cb)(void *, size_t, struct blob_attr *);
} avpair[__RADIUS_MAX] = {
	[RADIUS_ACCT_TYPE] = { .attrid = PW_ACCT_STATUS_TYPE, },
	[RADIUS_USERNAME] = { .attrid = PW_USER_NAME, },
	[RADIUS_PASSWORD] = { .attrid = PW_USER_PASSWORD, },
	[RADIUS_CHAP_PASSWORD] = { .attrid = PW_CHAP_PASSWORD, .cb = cb_chap_passwd, },
	[RADIUS_CHAP_CHALLENGE] = { .attrid = PW_CHAP_CHALLENGE, .cb = cb_chap_challenge, },
	[RADIUS_ACCT_SESSION] = { .attrid = PW_ACCT_SESSION_ID, },
	[RADIUS_CLIENT_IP] = { .attrid = PW_FRAMED_IP_ADDRESS, .cb = cb_ip, },
	[RADIUS_CALLED_STATION] = { .attrid = PW_CALLED_STATION_ID, },
	[RADIUS_CALLING_STATION] = { .attrid = PW_CALLING_STATION_ID, },
	[RADIUS_NAS_IP] = { .attrid = PW_NAS_IP_ADDRESS, .cb = cb_ip, },
	[RADIUS_NAS_ID] = { .attrid = PW_NAS_IDENTIFIER, },
	[RADIUS_TERMINATE_CAUSE] = { .attrid = PW_ACCT_TERMINATE_CAUSE, },
	[RADIUS_SESSION_TIME] = { .attrid = PW_ACCT_SESSION_TIME, },
	[RADIUS_INPUT_OCTETS] = { .attrid = PW_ACCT_INPUT_OCTETS, },
	[RADIUS_OUTPUT_OCTETS] = { .attrid = PW_ACCT_OUTPUT_OCTETS, },
	[RADIUS_INPUT_GIGAWORDS] = { .attrid = PW_ACCT_INPUT_GIGAWORDS, },
	[RADIUS_OUTPUT_GIGAWORDS] = { .attrid = PW_ACCT_OUTPUT_GIGAWORDS },
	[RADIUS_INPUT_PACKETS] = { .attrid = PW_ACCT_INPUT_PACKETS, },
	[RADIUS_OUTPUT_PACKETS] = { .attrid = PW_ACCT_OUTPUT_PACKETS, },
	[RADIUS_LOGOFF_URL] = { .attrid = ATTR_WBAL_WISPR_LOGOFF_URL, .vendorspec = VENDORSPEC_WBAL, },
	[RADIUS_CLASS] = { .attrid = PW_CLASS, },
	[RADIUS_SERVICE_TYPE] = { .attrid = PW_SERVICE_TYPE, },
	[RADIUS_PROXY_STATE_AUTH] = { .attrid = PW_PROXY_STATE, },
	[RADIUS_PROXY_STATE_ACCT] = { .attrid = PW_PROXY_STATE, },
	[RADIUS_LOCATION_NAME] = { .attrid = ATTR_WBAL_WISPR_LOCATION_NAME, .vendorspec = VENDORSPEC_WBAL, },
	[RADIUS_NAS_PORT_TYPE] = { .attrid = PW_NAS_PORT_TYPE, },
	[RADIUS_CUI] = { .attrid = PW_CHARGEABLE_USER_IDENTITY, },
	[RADIUS_REPLY_MESSAGE] = { .attrid = PW_REPLY_MESSAGE, },
	[RADIUS_LANG] = { .attrid = ATTR_CHILLI_CHILLISPOT_LANG, .vendorspec = VENDORSPEC_CHILLI, },
};

/**
 * Convert a string of hex bytes into the equivalent null-terminated character string.
 * @param in null-terminated input hex string buffer
 * @param out output buffer
 * @param osize output buffer size
 * @return number of characters decoded or -1 on error
 * @note if osize is <= strlen(in)/2, the output will be truncated (null-terminated).
 * @warning no input sanitization is performed: in must be null-terminated;
 * the resulting output string may contain non-representable characters.
 */
static int
str_to_hex(const char *in, char *out, int osize)
{
	int ilen = strlen(in);
	int i;

	if (!osize)
		return -1;

	for (i = 0; (i < ilen/2) && (i < osize - 1); i++) {
		if (sscanf(&in[i * 2], "%2hhx", &out[i]) != 1)
			return -1;
	}

	out[i] = '\0';
	return i;
}

/**
 * Format IPv4 address.
 * @param p pointer to output value
 * @param s size of allocated output buffer
 * @param b input blob_attr (expect string)
 * @return effective length of value
 */
static int cb_ip(void * p, size_t s, struct blob_attr *b)
{
	struct sockaddr_in ip = {};

	assert(s >= sizeof(ip.sin_addr));
	inet_pton(AF_INET, blobmsg_get_string(b), &ip.sin_addr);
	ip.sin_addr.s_addr = ntohl(ip.sin_addr.s_addr);
	memcpy(p, &ip.sin_addr, sizeof(ip.sin_addr));

	return sizeof(ip.sin_addr);
}

static int cb_chap_passwd(void *p, size_t s, struct blob_attr *b)
{
	char *str = p;
	int len;

	len = str_to_hex(blobmsg_get_string(b), str+1, s-1);

	return len >= 0 ? len+1 : len;
}

static int cb_chap_challenge(void *p, size_t s, struct blob_attr *b)
{
	char *str = p;

	return str_to_hex(blobmsg_get_string(b), str, s);
}

static int
result(rc_handle const *rh, int accept, VALUE_PAIR *pair)
{
	struct blob_buf b = {};

	blob_buf_init(&b, 0);

	blobmsg_add_u32(&b, "access-accept", accept);

	if (pair) {
		void *c = blobmsg_open_table(&b, "reply");
		char name[RC_NAME_LENGTH+1], value[256];
		VALUE_PAIR *vp;

		for (vp = pair; vp != NULL; vp = vp->next) {
			if (rc_avpair_tostr(rh, vp, name, sizeof(name), value, sizeof(value)) == -1) {
				ULOG_NOTE("Ignoring unknown attribute in reply: %" PRIu64 "\n", vp->attribute);
				continue;	// add as many attributes as possible
			}
			blobmsg_add_string(&b, name, value);
		}
		blobmsg_close_table(&b, c);
	}
	printf("%s", blobmsg_format_json(b.head, true));

	return accept;
}

/**
 * @param key internal radius key id (from enum at top of file)
 * @return 0 if key is a normal RADIUS attribute and can be processed programmatically as such, 1 otherwise.
 */
static int nonattr_blobkey(int key)
{
	switch (key) {
		case RADIUS_acct:
		case RADIUS_authserver:
		case RADIUS_acctserver:
		case RADIUS_servtype:
		// override proxy
		case RADIUS_PROXY_STATE_ACCT:
		case RADIUS_PROXY_STATE_AUTH:
			return 1;	// ignore those keys
		default:
			return 0;
	}
}

static int
radius(rc_handle *rh)
{
	VALUE_PAIR *send = NULL, *received;
	char tempstr[RC_NAME_LENGTH];
	char *rtimeout;
	uint32_t val;
	void *pval;
	int len, i, ret;

	if (tb[RADIUS_authserver]) {
		if (rc_add_config(rh, "authserver", blobmsg_get_string(tb[RADIUS_authserver]), "code", __LINE__)) {
			ULOG_ERR("Failed to set authserver!\n");
			goto fail;
		}
	}
	if (tb[RADIUS_acctserver]) {
		if (rc_add_config(rh, "acctserver", blobmsg_get_string(tb[RADIUS_acctserver]), "code", __LINE__)) {
			ULOG_ERR("Failed to set acctserver!\n");
			goto fail;
		}
	}
	if (tb[RADIUS_servtype]) {
		if (rc_add_config(rh, "serv-type", blobmsg_get_string(tb[RADIUS_servtype]), "code", __LINE__)) {
			ULOG_ERR("Failed to set serv-type!\n");
			goto fail;
		}
	}

	if (tb[RADIUS_acct] && blobmsg_get_bool(tb[RADIUS_acct]))
		rtimeout = "2";		// short timeout for accounting requests
	else
		rtimeout = "5";

	if (rc_add_config(rh, "radius_timeout", rtimeout, "code", __LINE__))
		goto fail;
	if (rc_add_config(rh, "radius_retries", "1", "code", __LINE__))
		goto fail;
	if (rc_add_config(rh, "bindaddr", "*", "code", __LINE__))
		goto fail;
	if (rc_apply_config(rh) != 0) {
		ULOG_ERR("Failed to apply radcli config!\n");
		goto fail;
	}

	// process parsed blobmsg for radius request
	for (i = 0; i < __RADIUS_MAX; i++) {
		if (nonattr_blobkey(i))
			continue;	// ignore those keys

		if (!tb[i])
			continue;

		pval = NULL;
		len = 0;
		switch (radius_policy[i].type) {
			case BLOBMSG_TYPE_INT32:
				len = 4;
				if (avpair[i].cb) {
					len = avpair[i].cb(&val, sizeof(val), tb[i]);
					if (len < 0)
						goto fail;
				}
				else
					val = blobmsg_get_u32(tb[i]);
				pval = &val;
				break;
			case BLOBMSG_TYPE_STRING:
				len = -1;
				if (avpair[i].cb) {
					memset(tempstr, 0, sizeof(tempstr));
					len = avpair[i].cb(&tempstr, sizeof(tempstr), tb[i]);
					if (len < 0)
						goto fail;
					pval = &tempstr;
				}
				else
					pval = blobmsg_get_string(tb[i]);
				break;
			default:
				ULOG_ERR("Policy type not implemented, fix radius-client.c!\n");
				goto fail;
		}

		if (pval && len) {
			if (rc_avpair_add(rh, &send, avpair[i].attrid, pval, len, avpair[i].vendorspec) == NULL)
				goto fail;
		}
	}

	if (tb[RADIUS_acct] && blobmsg_get_bool(tb[RADIUS_acct])) {
		if (tb[RADIUS_PROXY_STATE_ACCT]) {
			if (rc_avpair_add(rh, &send, PW_PROXY_STATE, blobmsg_get_string(tb[RADIUS_PROXY_STATE_ACCT]), -1, 0) == NULL)
				goto fail;
		}

		return rc_acct(rh, 0, send);	// we don't really care
	} else {
		if (tb[RADIUS_PROXY_STATE_AUTH]) {
			if (rc_avpair_add(rh, &send, PW_PROXY_STATE, blobmsg_get_string(tb[RADIUS_PROXY_STATE_AUTH]), -1, 0) == NULL)
				goto fail;
		}

		ret = rc_auth(rh, 0, send, &received, NULL);
		switch (ret) {
		case OK_RC:
		case REJECT_RC:
		case CHALLENGE_RC:	// XXX TODO?
			return result(rh, (OK_RC == ret), received);
			break;
		case TIMEOUT_RC:
		default:
			goto fail;
			break;
		}
	}

fail:
	return -1;
}

int
main(int argc, char **argv)
{
	rc_handle *rh = rc_new();
	DICT_ATTR *DA;
	uint64_t attribute;
	int i;

	ulog_open(ULOG_STDIO | ULOG_SYSLOG, LOG_DAEMON, "uspot-radius");
	rc_openlog("uspot-radius");

	if (argc != 2) {
		ULOG_ERR("Invalid number of arguments!\n");
		goto fail;
	}

	if (rh == NULL) {
		ULOG_ERR("Out of memory!\n");
		goto fail;
	}

	rh = rc_config_init(rh);
	if (rh == NULL) {
		ULOG_ERR("Failed to initialize rc_config!\n");
		goto fail;
	}

	if (rc_add_config(rh, "dictionary", RADCLI_DICT, "code", __LINE__)) {
		ULOG_ERR("Failed to add dictionary!\n");
		goto fail;
	}

	if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary")) != 0) {
		ULOG_ERR("Failed to read dictionary!\n");
		goto fail;
	}

	// populate radius_policy from radcli dictionary names/types
	for (i = 0; i < __RADIUS_MAX; i++) {
		if (nonattr_blobkey(i))
			continue;

		attribute = ((uint64_t)avpair[i].vendorspec << VENDOR_BIT_SIZE) | (uint64_t)avpair[i].attrid;
		DA = rc_dict_getattr(rh, attribute);
		if (!DA) {
			ULOG_ERR("Failed to lookup attribute key %d\n", i);
			goto fail;
		}

		radius_policy[i].name = DA->name;
		switch (DA->type) {
			case PW_TYPE_INTEGER:
				radius_policy[i].type = BLOBMSG_TYPE_INT32;
				break;
			case PW_TYPE_STRING:
			case PW_TYPE_IPADDR:
			case PW_TYPE_DATE:
			case PW_TYPE_IPV6ADDR:
			case PW_TYPE_IPV6PREFIX:
				radius_policy[i].type = BLOBMSG_TYPE_STRING;
				break;
			default:
				ULOG_ERR("Unsupported attribute type %d for %s\n", DA->type, DA->name);
				goto fail;
		}
	}

	if (blob_buf_init(&b, 0))
		goto fail;
	if (!blobmsg_add_json_from_file(&b, argv[1])) {
		ULOG_ERR("Failed to read JSON!\n");
		goto fail;
	}

	if (blobmsg_parse(radius_policy, __RADIUS_MAX, tb, blob_data(b.head), blob_len(b.head))) {
		ULOG_ERR("Failed to parse JSON!\n");
		goto fail;
	}

	return radius(rh);
fail:
	return result(rh, 0, NULL);
}
