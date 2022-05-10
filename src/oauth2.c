/*
 * Claws Mail -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 2021-2022 the Claws Mail team
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

#include "oauth2.h"
#include "md5.h"
#include "utils.h"
#include "log.h"
#include "time.h"
#include "common/passcrypt.h"

//Yahoo requires token requests to send POST header Authorization: Basic
//where the password is Base64 encoding of client_id:client_secret

static gchar *OAUTH2info[4][17] = {
	{
		[OA2_BASE_URL] = "accounts.google.com",
		[OA2_CLIENT_ID] = "",
	 ".",
	 "urn:ietf:wg:oauth:2.0:oob",
	 "/o/oauth2/auth",
	 "/o/oauth2/token",
	 "/o/oauth2/token",
	 "code",
	 "https://mail.google.com",
	 "authorization_code",
	 "refresh_token",
	 "",
	 "",
	 "",
	 "",
	 "",
	 ""},
	{
		[OA2_BASE_URL] = "login.microsoftonline.com",
		[OA2_CLIENT_ID] = "",
	 "",
	 "https://login.microsoftonline.com/common/oauth2/nativeclient",
	 "/common/oauth2/v2.0/authorize",
	 "/common/oauth2/v2.0/token",
	 "/common/oauth2/v2.0/token",
	 "code",
	 "wl.imap offline_access",
	 "authorization_code",
	 "refresh_token",
	 "common",
	 "",
	 "offline",
	 "wl.imap offline_access",
	 "fragment",
	 ""},
	{
		[OA2_BASE_URL] = "login.microsoftonline.com",
		[OA2_CLIENT_ID] = "",
	 "",
	 "https://login.microsoftonline.com/common/oauth2/nativeclient",
	 "/common/oauth2/v2.0/authorize",
	 "/common/oauth2/v2.0/token",
	 "/common/oauth2/v2.0/token",
	 "code",
	 "offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/POP.AccessAsUser.All https://outlook.office.com/SMTP.Send",
	 "authorization_code",
	 "refresh_token",
	 "common",
	 "",
	 "offline",
	 "offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/POP.AccessAsUser.All https://outlook.office.com/SMTP.Send",
	 "fragment",
	 ""},
	{
		[OA2_BASE_URL] = "api.login.yahoo.com",
		[OA2_CLIENT_ID] = "",
	 ".",
	 "oob",
	 "/oauth2/request_auth",
	 "/oauth2/get_token",
	 "/oauth2/get_token",
	 "code",
	 "",
	 "authorization_code",
	 "refresh_token",
	 "",
	 "",
	 "",
	 "",
	 "",
	 "1"}
};

static gchar *OAUTH2CodeMarker[5][2] = {
	{"", ""},
	{"google_begin_mark", "google_end_mark"}, /* Not used since token avalable to user to copy in browser window */
	{"#code=", "&session_state"},
	{"#code=", "&session_state"},
	{"yahoo_begin_mark", "yahoo_end_mark"} /* Not used since token avalable to user to copy in browser window */
};

static gchar *oauth2_contact_server(SockInfo *sock, const gchar *request);
static guchar *oauth2_decode(const gchar *in);

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

static gint oauth2_filter_access(gchar *json, gchar **access_token_p, gint *expiry)
{
	GMatchInfo *matchInfo;
	GRegex *regex;
	gchar *access_token = NULL;
	gboolean matched;

	regex = g_regex_new("\"access_token\": ?\"(.*?)\",?", 0, 0, NULL);
	if (!regex)
		return -1;
	matched = g_regex_match(regex, json, 0, &matchInfo);
	if (matched)
		access_token = g_match_info_fetch(matchInfo, 1);
	g_match_info_free(matchInfo);
	g_regex_unref(regex);
	*access_token_p = access_token;
	if (!matched || !access_token)
		return -1;

	*expiry = 0;
	regex = g_regex_new("\"expires_in\": ?([0-9]*),?", 0, 0, NULL);
	if (!regex)
		return 0;
	matched = g_regex_match(regex, json, 0, &matchInfo);
	if (matched) {
		g_autofree gchar *str = g_match_info_fetch(matchInfo, 1);
		gint expires_in = atoi(str);
		// Reduce available token life to avoid attempting connections with (near) expired tokens
		if (expires_in > 120)
			expires_in -= 120;
		*expiry = (g_get_real_time() / G_USEC_PER_SEC) + expires_in;
	}
	g_match_info_free(matchInfo);
	g_regex_unref(regex);

	return 0;
}

static gint oauth2_filter_refresh(gchar *json, gchar **refresh_token_p)
{
	GMatchInfo *matchInfo;
	GRegex *regex;
	gchar *refresh_token = NULL;
	gboolean matched;

	regex = g_regex_new("\"refresh_token\": ?\"(.*?)\",?", 0, 0, NULL);
	if (!regex)
		return -1;
	matched = g_regex_match(regex, json, 0, &matchInfo);
	if (matched)
		refresh_token = g_match_info_fetch(matchInfo, 1);
	g_match_info_free(matchInfo);
	g_regex_unref(regex);
	*refresh_token_p = refresh_token;

	return (!matched || !refresh_token) ? -1 : 0;
}

static gchar *oauth2_get_token_from_response(Oauth2Service provider, const gchar *response)
{
	gchar *token = NULL;

	debug_print("Auth response: %s\n", response);
	if (provider == OAUTH2AUTH_YAHOO || provider == OAUTH2AUTH_GOOGLE) {
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

int oauth2_obtain_tokens(Oauth2Service provider, OAUTH2Data *OAUTH2Data, const gchar *authcode)
{
	g_autofree gchar *request = NULL;
	g_autofree gchar *response = NULL;
	gchar *body;
	gchar *uri, *uri2;
	gchar *header;
	gchar *tmp_hd, *tmp_hd_encoded;
	gchar *access_token;
	gchar *refresh_token;
	gint expiry = 0;
	gint ret;
	SockInfo *sock;
	gchar *client_id;
	gchar *client_secret;
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

	sock = sock_connect(OAUTH2info[i][OA2_BASE_URL], 443);
	if (sock == NULL) {
		log_message(LOG_PROTOCOL, _("OAuth2 connection error\n"));
		return (1);
	}
	sock->ssl_cert_auto_accept = TRUE;
	sock->use_tls_sni = TRUE;
	sock_set_nonblocking_mode(sock, FALSE);
	sock_set_io_timeout(10);
	sock->gnutls_priority = "NORMAL:!VERS-SSL3.0:!VERS-TLS1.0:!VERS-TLS1.1";
	if (ssl_init_socket(sock) == FALSE) {
		log_message(LOG_PROTOCOL, _("OAuth2 TLS connection error\n"));
		return (1);
	}

	if (OAUTH2Data->custom_client_id)
		client_id = g_strdup(OAUTH2Data->custom_client_id);
	else
		client_id = oauth2_decode(OAUTH2info[i][OA2_CLIENT_ID]);

	uri = g_uri_escape_string(client_id, NULL, FALSE);
	uri2 = g_uri_escape_string(token, NULL, FALSE);
	body = g_strconcat("client_id=", uri, "&code=", uri2, NULL);
	g_free(uri2);
	g_free(uri);

	if (OAUTH2info[i][OA2_CLIENT_SECRET][0]) {
		//Only allow custom client secret if the service provider would usually expect a client secret
		if (OAUTH2Data->custom_client_secret)
			client_secret = g_strdup(OAUTH2Data->custom_client_secret);
		else
			client_secret = oauth2_decode(OAUTH2info[i][OA2_CLIENT_SECRET]);
		uri = g_uri_escape_string(client_secret, NULL, FALSE);
		tmp = g_strconcat(body, "&client_secret=", uri, NULL);
		g_free(body);
		g_free(uri);
		body = tmp;
	} else {
		client_secret = g_strconcat("", NULL);
	}

	if (OAUTH2info[i][OA2_REDIRECT_URI][0]) {
		uri = g_uri_escape_string(OAUTH2info[i][OA2_REDIRECT_URI], NULL, FALSE);
		tmp = g_strconcat(body, "&redirect_uri=", uri, NULL);
		g_free(body);
		g_free(uri);
		body = tmp;
	}
	if (OAUTH2info[i][OA2_GRANT_TYPE_ACCESS][0]) {
		uri = g_uri_escape_string(OAUTH2info[i][OA2_GRANT_TYPE_ACCESS], NULL, FALSE);
		tmp = g_strconcat(body, "&grant_type=", uri, NULL);
		g_free(body);
		g_free(uri);
		body = tmp;
	}
	if (OAUTH2info[i][OA2_TENANT][0]) {
		uri = g_uri_escape_string(OAUTH2info[i][OA2_TENANT], NULL, FALSE);
		tmp = g_strconcat(body, "&tenant=", uri, NULL);
		g_free(body);
		g_free(uri);
		body = tmp;
	}
	if (OAUTH2info[i][OA2_SCOPE_FOR_ACCESS][0]) {
		uri = g_uri_escape_string(OAUTH2info[i][OA2_SCOPE_FOR_ACCESS], NULL, FALSE);
		tmp = g_strconcat(body, "&scope=", uri, NULL);
		g_free(body);
		g_free(uri);
		body = tmp;
	}
	if (OAUTH2info[i][OA2_STATE][0]) {
		uri = g_uri_escape_string(OAUTH2info[i][OA2_STATE], NULL, FALSE);
		tmp = g_strconcat(body, "&state=", uri, NULL);
		g_free(body);
		g_free(uri);
		body = tmp;
	}

	if (OAUTH2info[i][OA2_HEADER_AUTH_BASIC][0]) {
		tmp_hd = g_strconcat(client_id, ":", client_secret, NULL);
		tmp_hd_encoded = g_base64_encode(tmp_hd, strlen(tmp_hd));
		header = g_strconcat("Authorization: Basic ", tmp_hd_encoded, NULL);
		g_free(tmp_hd_encoded);
		g_free(tmp_hd);
	} else {
		header = g_strconcat("", NULL);
	}

	request = oauth2_post_request(OAUTH2info[i][OA2_BASE_URL], OAUTH2info[i][OA2_ACCESS_RESOURCE], header, body);
	if (request)
		response = oauth2_contact_server(sock, request);

	if (response && oauth2_filter_access(response, &access_token, &expiry) == 0) {
		OAUTH2Data->access_token = access_token;
		OAUTH2Data->expiry = expiry;
		OAUTH2Data->expiry_str = g_strdup_printf("%i", expiry);
		ret = 0;
		log_message(LOG_PROTOCOL, _("OAuth2 access token obtained\n"));
	} else {
		log_message(LOG_PROTOCOL, _("OAuth2 access token not obtained\n"));
		debug_print("OAuth2 - request: %s\n Response: %s", request, response);
		ret = 1;
	}

	if (response && oauth2_filter_refresh(response, &refresh_token) == 0) {
		OAUTH2Data->refresh_token = refresh_token;
		log_message(LOG_PROTOCOL, _("OAuth2 refresh token obtained\n"));
	} else {
		log_message(LOG_PROTOCOL, _("OAuth2 refresh token not obtained\n"));
	}

	sock_close(sock, TRUE);
	g_free(body);
	g_free(header);
	g_free(client_id);
	g_free(client_secret);

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
	gchar *refresh_token;
	gint expiry = 0;
	gint ret;
	SockInfo *sock;
	gchar *client_id;
	gchar *client_secret;
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
	sock_set_io_timeout(10);
	sock->gnutls_priority = "NORMAL:!VERS-SSL3.0:!VERS-TLS1.0:!VERS-TLS1.1";
	if (ssl_init_socket(sock) == FALSE) {
		log_message(LOG_PROTOCOL, _("OAuth2 TLS connection error\n"));
		return (1);
	}

	if (OAUTH2Data->custom_client_id)
		client_id = g_strdup(OAUTH2Data->custom_client_id);
	else
		client_id = oauth2_decode(OAUTH2info[i][OA2_CLIENT_ID]);

	uri = g_uri_escape_string(client_id, NULL, FALSE);
	body = g_strconcat("client_id=", uri, "&refresh_token=", OAUTH2Data->refresh_token, NULL);
	g_free(uri);

	if (OAUTH2info[i][OA2_CLIENT_SECRET][0]) {
		//Only allow custom client secret if the service provider would usually expect a client secret
		if (OAUTH2Data->custom_client_secret)
			client_secret = g_strdup(OAUTH2Data->custom_client_secret);
		else
			client_secret = oauth2_decode(OAUTH2info[i][OA2_CLIENT_SECRET]);
		uri = g_uri_escape_string(client_secret, NULL, FALSE);
		tmp = g_strconcat(body, "&client_secret=", uri, NULL);
		g_free(body);
		g_free(uri);
		body = tmp;
	} else {
		client_secret = g_strconcat("", NULL);
	}

	if (OAUTH2info[i][OA2_GRANT_TYPE_REFRESH][0]) {
		uri = g_uri_escape_string(OAUTH2info[i][OA2_GRANT_TYPE_REFRESH], NULL, FALSE);
		tmp = g_strconcat(body, "&grant_type=", uri, NULL);
		g_free(body);
		g_free(uri);
		body = tmp;
	}
	if (OAUTH2info[i][OA2_SCOPE_FOR_ACCESS][0]) {
		uri = g_uri_escape_string(OAUTH2info[i][OA2_SCOPE_FOR_ACCESS], NULL, FALSE);
		tmp = g_strconcat(body, "&scope=", uri, NULL);
		g_free(body);
		g_free(uri);
		body = tmp;
	}
	if (OAUTH2info[i][OA2_STATE][0]) {
		uri = g_uri_escape_string(OAUTH2info[i][OA2_STATE], NULL, FALSE);
		tmp = g_strconcat(body, "&state=", uri, NULL);
		g_free(body);
		g_free(uri);
		body = tmp;
	}

	if (OAUTH2info[i][OA2_HEADER_AUTH_BASIC][0]) {
		tmp_hd = g_strconcat(client_id, ":", client_secret, NULL);
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

	if (response && oauth2_filter_access(response, &access_token, &expiry) == 0) {
		OAUTH2Data->access_token = access_token;
		OAUTH2Data->expiry = expiry;
		OAUTH2Data->expiry_str = g_strdup_printf("%i", expiry);
		ret = 0;
		log_message(LOG_PROTOCOL, _("OAuth2 access token obtained\n"));
	} else {
		log_message(LOG_PROTOCOL, _("OAuth2 access token not obtained\n"));
		debug_print("OAuth2 - request: %s\n Response: %s", request, response);
		ret = 1;
	}

	if (response && oauth2_filter_refresh(response, &refresh_token) == 0) {
		OAUTH2Data->refresh_token = refresh_token;
		log_message(LOG_PROTOCOL, _("OAuth2 replacement refresh token provided\n"));
	} else
		log_message(LOG_PROTOCOL, _("OAuth2 replacement refresh token not provided\n"));

	debug_print("OAuth2 - access token: %s\n", access_token);
	debug_print("OAuth2 - access token expiry: %i\n", expiry);

	sock_close(sock, TRUE);
	g_free(body);
	g_free(header);
	g_free(client_id);
	g_free(client_secret);

	return (ret);
}

static gchar *oauth2_contact_server(SockInfo *sock, const gchar *request)
{
	gboolean success;
	gint ret;
	char buf[1024];
	GString *response;

	if (sock_write(sock, request, strlen(request)) < 0) {
		log_message(LOG_PROTOCOL, _("OAuth2 socket write error\n"));
		return NULL;
	}

	response = g_string_sized_new(sizeof(buf));
	do {
		ret = sock_read(sock, buf, sizeof(buf) - 1);

		if (ret < 0 && errno == EAGAIN)
			continue;

		success = FALSE;
		if (ret < 0)
			break;

		if (ret > sizeof(buf) - 1)
			break;

		success = TRUE;
		buf[ret] = '\0';
		g_string_append_len(response, buf, ret);
	} while (ret);

	return g_string_free(response, !success);
}

gchar *oauth2_authorisation_url(Oauth2Service provider, const gchar *custom_client_id)
{
	gint i;
	g_autofree gchar *client_id = NULL;
	gchar *tmp;
	GString *url;

	i = (int)provider - 1;
	if (!Oauth2Service_is_valid(provider))
		return NULL;

	url = g_string_sized_new(1024);

	g_string_append(url, "https://");
   	g_string_append(url, OAUTH2info[i][OA2_BASE_URL]);
   	g_string_append(url, OAUTH2info[i][OA2_AUTH_RESOURCE]);
   	g_string_append(url, "?client_id=");

	if (custom_client_id) {
		tmp = g_uri_escape_string(custom_client_id, NULL, FALSE);
	} else {
		client_id = oauth2_decode(OAUTH2info[i][OA2_CLIENT_ID]);
		tmp = g_uri_escape_string(client_id, NULL, FALSE);
	}
   	g_string_append(url, tmp);
	g_free(tmp);

	if (OAUTH2info[i][OA2_REDIRECT_URI][0]) {
		tmp = g_uri_escape_string(OAUTH2info[i][OA2_REDIRECT_URI], NULL, FALSE);
		g_string_append(url, "&redirect_uri=");
		g_string_append(url, tmp);
		g_free(tmp);

	}
	if (OAUTH2info[i][OA2_RESPONSE_TYPE][0]) {
		tmp = g_uri_escape_string(OAUTH2info[i][OA2_RESPONSE_TYPE], NULL, FALSE);
		g_string_append(url, "&response_type=");
		g_string_append(url, tmp);
		g_free(tmp);
	}
	if (OAUTH2info[i][OA2_SCOPE_FOR_AUTH][0]) {
		tmp = g_uri_escape_string(OAUTH2info[i][OA2_SCOPE_FOR_AUTH], NULL, FALSE);
		g_string_append(url, "&scope=");
		g_string_append(url, tmp);
		g_free(tmp);
	}
	if (OAUTH2info[i][OA2_TENANT][0]) {
		tmp = g_uri_escape_string(OAUTH2info[i][OA2_TENANT], NULL, FALSE);
		g_string_append(url, "&tenant=");
		g_string_append(url, tmp);
		g_free(tmp);
	}
	if (OAUTH2info[i][OA2_RESPONSE_MODE][0]) {
		tmp = g_uri_escape_string(OAUTH2info[i][OA2_RESPONSE_MODE], NULL, FALSE);
		g_string_append(url, "&response_mode=");
		g_string_append(url, tmp);
		g_free(tmp);
	}
	if (OAUTH2info[i][OA2_STATE][0]) {
		tmp = g_uri_escape_string(OAUTH2info[i][OA2_STATE], NULL, FALSE);
		g_string_append(url, "&state=");
		g_string_append(url, tmp);
		g_free(tmp);
	}

	return g_string_free(url, FALSE);
}

gint oauth2_check_passwds(PrefsAccount *ac_prefs)
{
	gchar *uid = g_strdup_printf("%d", ac_prefs->account_id);
	gint expiry;
	OAUTH2Data *OAUTH2Data = g_malloc0(sizeof(*OAUTH2Data));
	gint ret = 0;
	gchar *acc;

	OAUTH2Data->custom_client_id = g_strdup(ac_prefs->oauth2_client_id);
	OAUTH2Data->custom_client_secret = g_strdup(ac_prefs->oauth2_client_secret);

	if (passwd_store_has_password(PWS_ACCOUNT, uid, PWS_ACCOUNT_OAUTH2_EXPIRY)) {
		acc = passwd_store_get_account(ac_prefs->account_id, PWS_ACCOUNT_OAUTH2_EXPIRY);
		expiry = atoi(acc);
		g_free(acc);
		if (expiry > (g_get_real_time() / G_USEC_PER_SEC)) {
			log_message(LOG_PROTOCOL, _("OAuth2 access token still fresh\n"));
			goto out;
		}
	}

	if (passwd_store_has_password(PWS_ACCOUNT, uid, PWS_ACCOUNT_OAUTH2_REFRESH)) {
		log_message(LOG_PROTOCOL, _("OAuth2 obtaining access token using refresh token\n"));
		OAUTH2Data->refresh_token = passwd_store_get_account(ac_prefs->account_id, PWS_ACCOUNT_OAUTH2_REFRESH);
		ret = oauth2_use_refresh_token(ac_prefs->oauth2_provider, OAUTH2Data);
	} else if (passwd_store_has_password(PWS_ACCOUNT, uid, PWS_ACCOUNT_OAUTH2_AUTH)) {
		log_message(LOG_PROTOCOL, _("OAuth2 trying for fresh access token with authorization code\n"));
		acc = passwd_store_get_account(ac_prefs->account_id, PWS_ACCOUNT_OAUTH2_AUTH);
		ret = oauth2_obtain_tokens(ac_prefs->oauth2_provider, OAUTH2Data, acc);
		g_free(acc);
	} else {
		ret = 1;
	}

	if (ret) {
		log_message(LOG_PROTOCOL, _("OAuth2 access token not obtained\n"));
	} else {
		passwd_store_set_account(ac_prefs->account_id, PWS_ACCOUNT_RECV, OAUTH2Data->access_token, FALSE);
		if (ac_prefs->use_smtp_auth && ac_prefs->smtp_auth_type == SMTPAUTH_OAUTH2)
			passwd_store_set_account(ac_prefs->account_id, PWS_ACCOUNT_SEND, OAUTH2Data->access_token, FALSE);
		passwd_store_set_account(ac_prefs->account_id, PWS_ACCOUNT_OAUTH2_EXPIRY, OAUTH2Data->expiry_str, FALSE);
		//Some providers issue replacement refresh tokens with each access token. Re-store whether replaced or not. 
		passwd_store_set_account(ac_prefs->account_id, PWS_ACCOUNT_OAUTH2_REFRESH, OAUTH2Data->refresh_token, FALSE);
		log_message(LOG_PROTOCOL, _("OAuth2 access and refresh token updated\n"));
	}

out:
	oauth2_release(OAUTH2Data);
	g_free(OAUTH2Data);
	g_free(uid);

	return (ret);
}

/* returns allocated string which must be freed */
static guchar *oauth2_decode(const gchar *in)
{
	guchar *tmp;
	gsize len;

	tmp = g_base64_decode(in, &len);
	passcrypt_decrypt(tmp, len);
	return tmp;
}

/* For testing */
void oauth2_encode(const gchar *in)
{
	guchar *tmp = g_strdup(in);
	guchar *tmp2 = g_strdup(in);
	gchar *result;
	gsize len = strlen(in);

	passcrypt_encrypt(tmp, len);
	result = g_base64_encode(tmp, len);
	tmp2 = oauth2_decode(result);

	log_message(LOG_PROTOCOL, _("OAuth2 original: %s\n"), in);
	log_message(LOG_PROTOCOL, _("OAuth2 encoded: %s\n"), result);
	log_message(LOG_PROTOCOL, _("OAuth2 decoded: %s\n\n"), tmp2);

	g_free(tmp);
	g_free(tmp2);
	g_free(result);
}

void oauth2_release(OAUTH2Data *OAUTH2Data)
{
	g_free(OAUTH2Data->refresh_token);
	g_free(OAUTH2Data->access_token);
	g_free(OAUTH2Data->expiry_str);
	g_free(OAUTH2Data->custom_client_id);
	g_free(OAUTH2Data->custom_client_secret);
}
/*
 * vim: noet ts=4 shiftwidth=4
 */
