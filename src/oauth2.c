/*
 * Claws Mail -- a GTK based, lightweight, and fast e-mail client
 * Copyright (C) 2021-2023 the Claws Mail team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * 
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#include "claws-features.h"
#endif

#ifdef USE_OAUTH2

#include <glib.h>
#ifdef ENABLE_NLS
#include <glib/gi18n.h>
#else
#define _(a) (a)
#define N_(a) (a)
#endif
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "imap.h"
#include "oauth2.h"
#include "md5.h"
#include "utils.h"
#include "log.h"
#include "time.h"
#include "common/passcrypt.h"
#include "prefs_common.h"
#define GNUTLS_PRIORITY "NORMAL:!VERS-SSL3.0:!VERS-TLS1.0:!VERS-TLS1.1"
//Yahoo requires token requests to send POST header Authorization: Basic
//where the password is Base64 encoding of client_id:client_secret

static gchar *OAUTH2info[OAUTH2AUTH_LAST - 1][OA2_LAST] = {
	{
		[OA2_BASE_URL] = "accounts.google.com",
		[OA2_CLIENT_ID] = "406964657835-aq8lmia8j95dhl1a2bvharmfk3t1hgqj.apps.googleusercontent.com",
		[OA2_CLIENT_SECRET] = "kSmqreRr0qwBWJgbf5Y-PjSU",
		[OA2_REDIRECT_URI] = "http://127.0.0.1:8888",
		[OA2_AUTH_RESOURCE] = "/o/oauth2/auth",
		[OA2_ACCESS_RESOURCE] = "/o/oauth2/token",
		[OA2_REFRESH_RESOURCE] = "/o/oauth2/token",
		[OA2_RESPONSE_TYPE] = "code",
		[OA2_SCOPE_FOR_AUTH] = "https://mail.google.com",
		[OA2_GRANT_TYPE_ACCESS] = "authorization_code",
		[OA2_GRANT_TYPE_REFRESH] = "refresh_token",
	},
	{
		[OA2_BASE_URL] = "login.microsoftonline.com",
		[OA2_CLIENT_ID] = "9e5f94bc-e8a4-4e73-b8be-63364c29d753",
		[OA2_REDIRECT_URI] = "http://127.0.0.1:8888",
		[OA2_AUTH_RESOURCE] = "/common/oauth2/v2.0/authorize",
		[OA2_ACCESS_RESOURCE] = "/common/oauth2/v2.0/token",
		[OA2_REFRESH_RESOURCE] = "/common/oauth2/v2.0/token",
		[OA2_RESPONSE_TYPE] = "code",
		[OA2_SCOPE_FOR_AUTH] = "offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/POP.AccessAsUser.All https://outlook.office.com/SMTP.Send",
		[OA2_GRANT_TYPE_ACCESS] = "authorization_code",
		[OA2_GRANT_TYPE_REFRESH] = "refresh_token",
		[OA2_TENANT] = "common",
		[OA2_SCOPE_FOR_ACCESS] = "offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/POP.AccessAsUser.All https://outlook.office.com/SMTP.Send",
		[OA2_RESPONSE_MODE] = "query",
	},
	{
		[OA2_BASE_URL] = "login.microsoftonline.com",
		[OA2_CLIENT_ID] = "9e5f94bc-e8a4-4e73-b8be-63364c29d753",
		[OA2_REDIRECT_URI] = "https://login.microsoftonline.com/common/oauth2/nativeclient",
		[OA2_AUTH_RESOURCE] = "/common/oauth2/v2.0/authorize",
		[OA2_ACCESS_RESOURCE] = "/common/oauth2/v2.0/token",
		[OA2_REFRESH_RESOURCE] = "/common/oauth2/v2.0/token",
		[OA2_RESPONSE_TYPE] = "code",
		[OA2_SCOPE_FOR_AUTH] = "offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/POP.AccessAsUser.All https://outlook.office.com/SMTP.Send",
		[OA2_GRANT_TYPE_ACCESS] = "authorization_code",
		[OA2_GRANT_TYPE_REFRESH] = "refresh_token",
		[OA2_TENANT] = "common",
		[OA2_STATE] = "",
		[OA2_SCOPE_FOR_ACCESS] = "offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/POP.AccessAsUser.All https://outlook.office.com/SMTP.Send",
		[OA2_RESPONSE_MODE] = "fragment",
	},
	{
		[OA2_BASE_URL] = "api.login.yahoo.com",
		[OA2_CLIENT_ID] = "",
		[OA2_CLIENT_SECRET] = ".",
		[OA2_REDIRECT_URI] = "oob",
		[OA2_AUTH_RESOURCE] = "/oauth2/request_auth",
		[OA2_ACCESS_RESOURCE] = "/oauth2/get_token",
		[OA2_REFRESH_RESOURCE] = "/oauth2/get_token",
		[OA2_RESPONSE_TYPE] = "code",
		[OA2_GRANT_TYPE_ACCESS] = "authorization_code",
		[OA2_GRANT_TYPE_REFRESH] = "refresh_token",
		[OA2_HEADER_AUTH_BASIC] = "1",
	},
};

static gchar *OAUTH2CodeMarker[OAUTH2AUTH_LAST - 1][2] = {
	[OAUTH2AUTH_GOOGLE] = {"code=", "&scope="},
	[OAUTH2AUTH_OUTLOOK] = {"code=", " HTTP"},
	[OAUTH2AUTH_EXCHANGE] = {"code=", "&session_state="},
};

static gchar *oauth2_post_request(gchar *host, gchar *resource, gchar *header, gchar *body)
{
	gint fixed_len = 16+49+36+(17+8)+7+19+23+1;
	gint len = strlen(body);
	GString *request = g_string_sized_new(fixed_len + strlen(resource) + len + strlen(header));

	g_string_append_printf(request, "POST %s HTTP/1.1\r\n", resource);
	g_string_append(request, "Content-Type: application/x-www-form-urlencoded\r\n");
	g_string_append(request, "Accept: text/html,application/json\r\n");
	g_string_append_printf(request, "Content-Length: %i\r\n", len);
	g_string_append_printf(request, "Host: %s\r\n", host);
	g_string_append(request, "Connection: close\r\n");
	g_string_append(request, "User-Agent: ClawsMail\r\n");
	if (header[0])
		g_string_append_printf(request, "%s\r\n", header);
	g_string_append_printf(request, "\r\n%s", body);

	return g_string_free(request, FALSE);
}

static gchar *oauth2_filter_access(const gchar *json, char **expiry)
{
	GMatchInfo *matchInfo;
	GRegex *regex;
	gchar *access_token = NULL;
	gboolean matched;

	regex = g_regex_new("\"access_token\": ?\"(.*?)\",?", G_REGEX_RAW, 0, NULL);
	if (!regex)
		return NULL;
	matched = g_regex_match(regex, json, 0, &matchInfo);
	if (matched)
		access_token = g_match_info_fetch(matchInfo, 1);
	g_match_info_free(matchInfo);
	g_regex_unref(regex);
	if (!matched || !access_token)
		return NULL;

	*expiry = NULL;
	regex = g_regex_new("\"expires_in\": ?([0-9]*),?", G_REGEX_RAW, 0, NULL);
	if (!regex)
		return access_token;
	matched = g_regex_match(regex, json, 0, &matchInfo);
	if (matched)
		*expiry = g_match_info_fetch(matchInfo, 1);
	g_match_info_free(matchInfo);
	g_regex_unref(regex);

	return access_token;
}

static gchar *oauth2_filter_refresh(const gchar *json)
{
	GMatchInfo *matchInfo;
	GRegex *regex;
	gchar *refresh_token = NULL;
	gboolean matched;

	regex = g_regex_new("\"refresh_token\": ?\"(.*?)\",?", G_REGEX_RAW, 0, NULL);
	if (!regex)
		return NULL;
	matched = g_regex_match(regex, json, 0, &matchInfo);
	if (matched)
		refresh_token = g_match_info_fetch(matchInfo, 1);
	g_match_info_free(matchInfo);
	g_regex_unref(regex);

	return refresh_token;
}

static gchar *oauth2_get_token_from_response(Oauth2Service provider, const gchar *response)
{
	gchar *token = NULL;

	debug_print("Auth response: %s\n", response);
	if (provider == OAUTH2AUTH_YAHOO) {
		/* Providers which display auth token in browser for users to copy */
		token = g_strdup(response);
	} else {
		gchar *start = g_strstr_len(response, strlen(response), OAUTH2CodeMarker[provider][0]);
		if (start == NULL)
			return NULL;
		start += strlen(OAUTH2CodeMarker[provider][0]);
		gchar *stop = g_strstr_len(response, strlen(response), OAUTH2CodeMarker[provider][1]);
		if (stop == NULL)
			return NULL;
		token = g_strndup(start, stop - start);
	}

	return token;
}

static gchar *oauth2_contact_server(SockInfo *sock, const gchar *request)
{
	gboolean got_some_error, timeout;
	gint ret;
	char buf[1024];
	GString *response = g_string_sized_new(sizeof(buf));
	time_t end_time = time(NULL);

	end_time += prefs_common_get_prefs()->io_timeout_secs;

	if (!response)
		return NULL;

	if (sock_write(sock, request, strlen(request)) < 0) {
		log_message(LOG_PROTOCOL, _("OAuth2 socket write error\n"));
		return NULL;
	}

	do {
		ret = sock_read(sock, buf, sizeof(buf) - 1);
		got_some_error = ret < 0;
		timeout = time(NULL) > end_time;

		if (timeout)
			break;

		if (ret < 0 && errno == EAGAIN)
			continue;

		if (got_some_error)
			break;

		if (ret) {
			buf[ret] = '\0';
			g_string_append_len(response, buf, ret);
		}
	} while (ret);

	if (timeout)
		log_message(LOG_PROTOCOL, _("OAuth2 socket timeout error\n"));

	return g_string_free(response, got_some_error || timeout);
}

int oauth2_obtain_tokens(Oauth2Service provider, OAUTH2Data *OAUTH2Data, const gchar *authcode)
{
	g_autofree gchar *request = NULL;
	g_autofree gchar *response = NULL;
	gchar *body;
	gchar *uri;
	gchar *header;
	gchar *tmp_hd, *tmp_hd_encoded;
	gchar *access_token;
	gchar *expiry;
	gint ret;
	SockInfo *sock;
	const gchar *client_id;
	const gchar *client_secret;
	g_autofree gchar *token = NULL;
	gchar *tmp;
	gint i;

	i = (int)provider - 1;
	if (!Oauth2Service_is_valid(provider))
		return (1);

	token = oauth2_get_token_from_response(provider, authcode);
	debug_print("Auth token: %s\n", token);
	if (token == NULL) {
		log_message(LOG_PROTOCOL, _("OAuth2 missing authorization code\n"));
		return (1);
	}
	debug_print("Connect: %s:443\n", OAUTH2info[i][OA2_BASE_URL]);
	sock = sock_connect(OAUTH2info[i][OA2_BASE_URL], 443);
	if (sock == NULL) {
		log_message(LOG_PROTOCOL, _("OAuth2 connection error\n"));
		return (1);
	}
	sock->ssl_cert_auto_accept = TRUE;
	sock->use_tls_sni = TRUE;
	sock_set_nonblocking_mode(sock, FALSE);
	gint timeout_secs = prefs_common_get_prefs()->io_timeout_secs;
	debug_print("Socket timeout: %i sec(s)\n", timeout_secs);
	sock_set_io_timeout(timeout_secs);
	sock->gnutls_priority = GNUTLS_PRIORITY;
	if (ssl_init_socket(sock) == FALSE) {
		log_message(LOG_PROTOCOL, _("OAuth2 TLS connection error\n"));
		return (1);
	}

	if (OAUTH2Data->custom_client_id && strlen(OAUTH2Data->custom_client_id))
		client_id = OAUTH2Data->custom_client_id;
	else
		client_id = OAUTH2info[i][OA2_CLIENT_ID];

	body = g_strconcat("client_id=", client_id, "&code=", token, NULL);
	debug_print("Body: %s\n", body);

	if (OAUTH2Data->custom_client_secret && strlen(OAUTH2Data->custom_client_secret))
		client_secret = OAUTH2Data->custom_client_secret;
	else
		client_secret = OAUTH2info[i][OA2_CLIENT_SECRET];
	if (client_secret) {
		uri = g_uri_escape_string(client_secret, NULL, FALSE);
		tmp = g_strconcat(body, "&client_secret=", uri, NULL);
		g_free(body);
		g_free(uri);
		body = tmp;
	}

	if (OAUTH2info[i][OA2_REDIRECT_URI]) {
		tmp = g_strconcat(body, "&redirect_uri=", OAUTH2info[i][OA2_REDIRECT_URI], NULL);
		g_free(body);
		body = tmp;
	}
	if (OAUTH2info[i][OA2_GRANT_TYPE_ACCESS]) {
		tmp = g_strconcat(body, "&grant_type=", OAUTH2info[i][OA2_GRANT_TYPE_ACCESS], NULL);
		g_free(body);
		body = tmp;
	}
	if (OAUTH2info[i][OA2_TENANT]) {
		tmp = g_strconcat(body, "&tenant=", OAUTH2info[i][OA2_TENANT], NULL);
		g_free(body);
		body = tmp;
	}
	if (OAUTH2info[i][OA2_SCOPE_FOR_ACCESS]) {
		tmp = g_strconcat(body, "&scope=", OAUTH2info[i][OA2_SCOPE_FOR_ACCESS], NULL);
		g_free(body);
		body = tmp;
	}
	if (OAUTH2info[i][OA2_STATE]) {
		tmp = g_strconcat(body, "&state=", OAUTH2info[i][OA2_STATE], NULL);
		g_free(body);
		body = tmp;
	}

	if (OAUTH2info[i][OA2_HEADER_AUTH_BASIC]) {
		tmp_hd = g_strconcat(client_id, ":", client_secret?:"", NULL);
		tmp_hd_encoded = g_base64_encode(tmp_hd, strlen(tmp_hd));
		header = g_strconcat("Authorization: Basic ", tmp_hd_encoded, NULL);
		g_free(tmp_hd_encoded);
		g_free(tmp_hd);
	} else {
		header = g_strconcat("", NULL);
	}

	debug_print("Complete body: %s\n", body);
	request = oauth2_post_request(OAUTH2info[i][OA2_BASE_URL], OAUTH2info[i][OA2_ACCESS_RESOURCE], header, body);
	if (request)
		response = oauth2_contact_server(sock, request);
	debug_print("Response: %s\n", response);

	if (response && (access_token = oauth2_filter_access(response, &expiry))) {
		GTimeVal tv;
		time_t t;

		debug_print("access_token %s expiry %s\n", access_token, expiry);

		g_get_current_time(&tv);
		t = (time_t)atol(expiry?:"0");
		t += tv.tv_sec;
		OAUTH2Data->expiry = g_strdup_printf("%zu", t);
		g_free(expiry);

		OAUTH2Data->access_token = access_token;
		ret = 0;
		log_message(LOG_PROTOCOL, _("OAuth2 access token obtained\n"));
	} else {
		log_message(LOG_PROTOCOL, _("OAuth2 access token not obtained\n"));
		debug_print("OAuth2 - request: %s\n Response: %s", request, response);
		ret = 1;
	}

	if (response && (OAUTH2Data->refresh_token = oauth2_filter_refresh(response))) {
		log_message(LOG_PROTOCOL, _("OAuth2 refresh token obtained\n"));
	} else {
		log_message(LOG_PROTOCOL, _("OAuth2 refresh token not obtained\n"));
	}

	sock_close(sock, TRUE);
	g_free(body);
	g_free(header);

	return (ret);
}

static gint oauth2_use_refresh_token(Oauth2Service provider, OAUTH2Data *OAUTH2Data)
{

	g_autofree gchar *request = NULL;
	g_autofree gchar *response = NULL;
	gchar *body;
	gchar *uri;
	gchar *header;
	gchar *tmp_hd, *tmp_hd_encoded;
	gchar *access_token = NULL;
	gchar *expiry;
	gint ret;
	SockInfo *sock;
	const gchar *client_id;
	const gchar *client_secret;
	gchar *tmp;
	gint i;

	i = (int)provider - 1;
	if (!Oauth2Service_is_valid(provider))
		return (1);

	sock = sock_connect(OAUTH2info[i][OA2_BASE_URL], 443);
	if (sock == NULL) {
		log_message(LOG_PROTOCOL, _("OAuth2 connection error\n"));
		return (1);
	}
	sock->ssl_cert_auto_accept = TRUE;
	sock->use_tls_sni = TRUE;
	sock_set_nonblocking_mode(sock, FALSE);
	gint timeout_secs = prefs_common_get_prefs()->io_timeout_secs;
	debug_print("Socket timeout: %i sec(s)\n", timeout_secs);
	sock_set_io_timeout(timeout_secs);
	sock->gnutls_priority = GNUTLS_PRIORITY;
	if (ssl_init_socket(sock) == FALSE) {
		log_message(LOG_PROTOCOL, _("OAuth2 TLS connection error\n"));
		return (1);
	}

	if (OAUTH2Data->custom_client_id && strlen(OAUTH2Data->custom_client_id))
		client_id = OAUTH2Data->custom_client_id;
	else
		client_id = OAUTH2info[i][OA2_CLIENT_ID];

	uri = g_uri_escape_string(client_id, NULL, FALSE);
	body = g_strconcat("client_id=", uri, "&refresh_token=", OAUTH2Data->refresh_token, NULL);
	g_free(uri);

	if (OAUTH2Data->custom_client_secret && strlen(OAUTH2Data->custom_client_secret))
		client_secret = OAUTH2Data->custom_client_secret;
	else
		client_secret = OAUTH2info[i][OA2_CLIENT_SECRET];
	if (client_secret) {
		uri = g_uri_escape_string(client_secret, NULL, FALSE);
		tmp = g_strconcat(body, "&client_secret=", uri, NULL);
		g_free(body);
		g_free(uri);
		body = tmp;
	}

	if (OAUTH2info[i][OA2_GRANT_TYPE_REFRESH]) {
		uri = g_uri_escape_string(OAUTH2info[i][OA2_GRANT_TYPE_REFRESH], NULL, FALSE);
		tmp = g_strconcat(body, "&grant_type=", uri, NULL);
		g_free(body);
		g_free(uri);
		body = tmp;
	}
	if (OAUTH2info[i][OA2_SCOPE_FOR_ACCESS]) {
		uri = g_uri_escape_string(OAUTH2info[i][OA2_SCOPE_FOR_ACCESS], NULL, FALSE);
		tmp = g_strconcat(body, "&scope=", uri, NULL);
		g_free(body);
		g_free(uri);
		body = tmp;
	}
	if (OAUTH2info[i][OA2_STATE]) {
		uri = g_uri_escape_string(OAUTH2info[i][OA2_STATE], NULL, FALSE);
		tmp = g_strconcat(body, "&state=", uri, NULL);
		g_free(body);
		g_free(uri);
		body = tmp;
	}

	if (OAUTH2info[i][OA2_HEADER_AUTH_BASIC]) {
		tmp_hd = g_strconcat(client_id, ":", client_secret?:"", NULL);
		tmp_hd_encoded = g_base64_encode(tmp_hd, strlen(tmp_hd));
		header = g_strconcat("Authorization: Basic ", tmp_hd_encoded, NULL);
		g_free(tmp_hd_encoded);
		g_free(tmp_hd);
	} else {
		header = g_strconcat("", NULL);
	}

	request = oauth2_post_request(OAUTH2info[i][OA2_BASE_URL], OAUTH2info[i][OA2_REFRESH_RESOURCE], header, body);
	if (request)
		response = oauth2_contact_server(sock, request);
	debug_print("Response: %s\n", response);

	if (response && (access_token = oauth2_filter_access(response, &expiry))) {
		GTimeVal tv;
		time_t t;

		debug_print("access_token %s expiry %s\n", access_token, expiry);

		g_get_current_time(&tv);
		t = (time_t)atol(expiry?:"0");
		t += tv.tv_sec;
		g_free(expiry);
		expiry = OAUTH2Data->expiry = g_strdup_printf("%zu", t);

		OAUTH2Data->access_token = access_token;
		ret = 0;
		log_message(LOG_PROTOCOL, _("OAuth2 access token obtained\n"));
	} else {
		log_message(LOG_PROTOCOL, _("OAuth2 access token not obtained\n"));
		debug_print("OAuth2 - request: %s\n Response: %s", request, response);
		ret = 1;
	}

	if (response && (OAUTH2Data->refresh_token = oauth2_filter_refresh(response))) {
		log_message(LOG_PROTOCOL, _("OAuth2 replacement refresh token provided\n"));
	} else
		log_message(LOG_PROTOCOL, _("OAuth2 replacement refresh token not provided\n"));

	debug_print("OAuth2 - access token: %s\n", access_token);
	debug_print("OAuth2 - access token expiry: %s\n", expiry);

	sock_close(sock, TRUE);
	g_free(body);
	g_free(header);

	return (ret);
}

gchar *oauth2_authorisation_url(Oauth2Service provider, const gchar *custom_client_id)
{
	gint i;
	const gchar *client_id = NULL;
	gchar *tmp;
	GString *auth_url;

	i = (int)provider - 1;
	if (!Oauth2Service_is_valid(provider))
		return NULL;

	auth_url = g_string_sized_new(1024);

	g_string_append(auth_url, "https://");
   	g_string_append(auth_url, OAUTH2info[i][OA2_BASE_URL]);
   	g_string_append(auth_url, OAUTH2info[i][OA2_AUTH_RESOURCE]);
   	g_string_append(auth_url, "?client_id=");

	if (custom_client_id && strlen(custom_client_id)) {
		tmp = g_uri_escape_string(custom_client_id, NULL, FALSE);
	} else {
		client_id = OAUTH2info[i][OA2_CLIENT_ID];
		tmp = g_uri_escape_string(client_id, NULL, FALSE);
	}
   	g_string_append(auth_url, tmp);
	g_free(tmp);

	if (OAUTH2info[i][OA2_REDIRECT_URI]) {
		tmp = g_uri_escape_string(OAUTH2info[i][OA2_REDIRECT_URI], NULL, FALSE);
		g_string_append(auth_url, "&redirect_uri=");
		g_string_append(auth_url, tmp);
		g_free(tmp);
	}
	if (OAUTH2info[i][OA2_RESPONSE_TYPE]) {
		g_string_append(auth_url, "&response_type=");
		g_string_append(auth_url, OAUTH2info[i][OA2_RESPONSE_TYPE]);
	}
	if (OAUTH2info[i][OA2_SCOPE_FOR_AUTH]) {
		tmp = g_uri_escape_string(OAUTH2info[i][OA2_SCOPE_FOR_AUTH], NULL, FALSE);
		g_string_append(auth_url, "&scope=");
		g_string_append(auth_url, tmp);
		g_free(tmp);
	}
	if (OAUTH2info[i][OA2_TENANT]) {
		tmp = g_uri_escape_string(OAUTH2info[i][OA2_TENANT], NULL, FALSE);
		g_string_append(auth_url, "&tenant=");
		g_string_append(auth_url, tmp);
		g_free(tmp);
	}
	if (OAUTH2info[i][OA2_RESPONSE_MODE]) {
		g_string_append(auth_url, "&response_mode=");
		g_string_append(auth_url, OAUTH2info[i][OA2_RESPONSE_MODE]);
	}
	if (OAUTH2info[i][OA2_STATE]) {
		tmp = g_uri_escape_string(OAUTH2info[i][OA2_STATE], NULL, FALSE);
		g_string_append(auth_url, "&state=");
		g_string_append(auth_url, tmp);
		g_free(tmp);
	}

	return g_string_free(auth_url, FALSE);
}

gint oauth2_check_passwds(PrefsAccount *ac_prefs)
{
	gchar *uid = g_strdup_printf("%d", ac_prefs->account_id);
	OAUTH2Data *OAUTH2Data = g_malloc0(sizeof(*OAUTH2Data));
	gint ret = 0;

	OAUTH2Data->custom_client_id = g_strdup(ac_prefs->oauth2_client_id);
	OAUTH2Data->custom_client_secret = g_strdup(ac_prefs->oauth2_client_secret);

	if (passwd_store_has_password(PWS_ACCOUNT, uid, PWS_ACCOUNT_OAUTH2_EXPIRY)) {
		GTimeVal tv;
		struct tm *tm;
		time_t expiry, now, diff;
		g_autofree gchar *acc;
		char buf_expiry[32], buf_now[32];
	   	const char *expiry_hint;
		static const char tm_fmt[] = "%Y-%m-%d %H:%M:%S %Z";

		memset(buf_expiry, 0, sizeof(buf_expiry));
		acc = passwd_store_get_account(ac_prefs->account_id, PWS_ACCOUNT_OAUTH2_EXPIRY);
		expiry = (time_t)atol(acc);
		tm = gmtime(&expiry);
		strftime(buf_expiry, sizeof(buf_expiry), tm_fmt, tm);

		memset(buf_now, 0, sizeof(buf_now));
		g_get_current_time(&tv);
		now = tv.tv_sec;
		tm = gmtime(&now);
		strftime(buf_now, sizeof(buf_now), tm_fmt, tm);

		if (expiry > now) {
			diff = expiry - now;
			expiry_hint = "s remaining";
		} else {
			diff = now - expiry;
			expiry_hint = "s stale";
		}
		debug_print("%s PWS_ACCOUNT_OAUTH2_EXPIRY %s. Expiry:%s,Now:%s %zu%s\n", uid, acc, buf_expiry, buf_now, diff, expiry_hint);
		// Reduce available token life to avoid attempting connections with (near) expired tokens
		if (expiry > 120)
			expiry -= 120;
		if (expiry > now) {
			log_message(LOG_PROTOCOL, _("OAuth2 access token still fresh\n"));
			goto out;
		}
	}

	if (passwd_store_has_password(PWS_ACCOUNT, uid, PWS_ACCOUNT_OAUTH2_REFRESH)) {
		log_message(LOG_PROTOCOL, _("OAuth2 obtaining access token using refresh token\n"));
		OAUTH2Data->refresh_token = passwd_store_get_account(ac_prefs->account_id, PWS_ACCOUNT_OAUTH2_REFRESH);
		debug_print("%s PWS_ACCOUNT_OAUTH2_REFRESH %s\n", uid, OAUTH2Data->refresh_token);
		ret = oauth2_use_refresh_token(ac_prefs->oauth2_provider, OAUTH2Data);
	} else if (passwd_store_has_password(PWS_ACCOUNT, uid, PWS_ACCOUNT_OAUTH2_AUTH)) {
		log_message(LOG_PROTOCOL, _("OAuth2 trying for fresh access token with authorization code\n"));
		g_autofree gchar *acc;
		acc = passwd_store_get_account(ac_prefs->account_id, PWS_ACCOUNT_OAUTH2_AUTH);
		ret = oauth2_obtain_tokens(ac_prefs->oauth2_provider, OAUTH2Data, acc);
	} else
		ret = 1;

	if (ret)
		log_message(LOG_PROTOCOL, _("OAuth2 access token not obtained\n"));
	else {
		if (ac_prefs->imap_auth_type == IMAP_AUTH_OAUTH2 || (ac_prefs->use_pop_auth && ac_prefs->pop_auth_type == POPAUTH_OAUTH2))
			passwd_store_set_account(ac_prefs->account_id, PWS_ACCOUNT_RECV, OAUTH2Data->access_token, FALSE);
		if (ac_prefs->use_smtp_auth && ac_prefs->smtp_auth_type == SMTPAUTH_OAUTH2)
			passwd_store_set_account(ac_prefs->account_id, PWS_ACCOUNT_SEND, OAUTH2Data->access_token, FALSE);
		passwd_store_set_account(ac_prefs->account_id, PWS_ACCOUNT_OAUTH2_EXPIRY, OAUTH2Data->expiry, FALSE);
		//Some providers issue replacement refresh tokens with each access token. Re-store whether replaced or not. 
		if (OAUTH2Data->refresh_token)
			passwd_store_set_account(ac_prefs->account_id, PWS_ACCOUNT_OAUTH2_REFRESH, OAUTH2Data->refresh_token, FALSE);
		passwd_store_write_config();
		log_message(LOG_PROTOCOL, _("OAuth2 access and refresh token updated\n"));
	}

out:
	oauth2_release(OAUTH2Data);
	g_free(OAUTH2Data);
	g_free(uid);

	return (ret);
}

void oauth2_release(OAUTH2Data *OAUTH2Data)
{
	g_free(OAUTH2Data->refresh_token);
	g_free(OAUTH2Data->access_token);
	g_free(OAUTH2Data->expiry);
	g_free(OAUTH2Data->custom_client_id);
	g_free(OAUTH2Data->custom_client_secret);
}
#endif /* USE_GNUTLS */
/*
 * vim: noet ts=4 shiftwidth=4 nowrap
 */
