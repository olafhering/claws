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
#  include "config.h"
#include "claws-features.h"
#endif

#ifdef USE_OAUTH2

#include "defs.h"
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
#include "common/version.h"
#include "file-utils.h"
#include "prefs_common.h"

#define GNUTLS_PRIORITY "NORMAL:!VERS-SSL3.0:!VERS-TLS1.0:!VERS-TLS1.1"
//Yahoo requires token requests to send POST header Authorization: Basic
//where the password is Base64 encoding of client_id:client_secret

static gint oauth2_post_request (gchar *buf, gchar *host, gchar *resource, gchar *header, gchar *body);
static gint oauth2_filter_refresh (gchar *json, gchar *refresh_token);
static gint oauth2_filter_access (gchar *json, gchar *access_token, gint *expiry);
static GList *oauth2_providers_list = NULL;
static Oauth2Info tmp_oa2_info;

static PrefParam oauth2_info[] = {
	{"oa2_name", NULL, &tmp_oa2_info.oa2_name, P_STRING, NULL, NULL, NULL},
	{"oa2_base_url", NULL, &tmp_oa2_info.oa2_base_url, P_STRING, NULL, NULL, NULL},
	{"oa2_client_id", NULL, &tmp_oa2_info.oa2_client_id, P_STRING, NULL, NULL, NULL},
	{"oa2_client_secret", NULL, &tmp_oa2_info.oa2_client_secret, P_STRING, NULL, NULL, NULL},
	{"oa2_redirect_uri", NULL, &tmp_oa2_info.oa2_redirect_uri, P_STRING, NULL, NULL, NULL},
	{"oa2_auth_resource", NULL, &tmp_oa2_info.oa2_auth_resource, P_STRING, NULL, NULL, NULL},
	{"oa2_access_resource", NULL, &tmp_oa2_info.oa2_access_resource, P_STRING, NULL, NULL, NULL},
	{"oa2_refresh_resource", NULL, &tmp_oa2_info.oa2_refresh_resource, P_STRING, NULL, NULL, NULL},
	{"oa2_response_type", NULL, &tmp_oa2_info.oa2_response_type, P_STRING, NULL, NULL, NULL},
	{"oa2_scope_for_auth", NULL, &tmp_oa2_info.oa2_scope_for_auth, P_STRING, NULL, NULL, NULL},
	{"oa2_grant_type_access", NULL, &tmp_oa2_info.oa2_grant_type_access, P_STRING, NULL, NULL, NULL},
	{"oa2_grant_type_refresh", NULL, &tmp_oa2_info.oa2_grant_type_refresh, P_STRING, NULL, NULL, NULL},
	{"oa2_tenant", NULL, &tmp_oa2_info.oa2_tenant, P_STRING, NULL, NULL, NULL},
	{"oa2_state", NULL, &tmp_oa2_info.oa2_state, P_STRING, NULL, NULL, NULL},
	{"oa2_access_type", NULL, &tmp_oa2_info.oa2_access_type, P_STRING, NULL, NULL, NULL},
	{"oa2_scope_for_access", NULL, &tmp_oa2_info.oa2_scope_for_access, P_STRING, NULL, NULL, NULL},
	{"oa2_response_mode", NULL, &tmp_oa2_info.oa2_response_mode, P_STRING, NULL, NULL, NULL},
	{"oa2_header_auth_basic", NULL, &tmp_oa2_info.oa2_header_auth_basic, P_STRING, NULL, NULL, NULL},
	{"oa2_two_stage_pop", NULL, &tmp_oa2_info.oa2_two_stage_pop, P_INT, NULL, NULL, NULL},
	{"oa2_codemarker_start", NULL, &tmp_oa2_info.oa2_codemarker_start, P_STRING, NULL, NULL, NULL},
	{"oa2_codemarker_stop", NULL, &tmp_oa2_info.oa2_codemarker_stop, P_STRING, NULL, NULL, NULL},
	{NULL, NULL, NULL, P_OTHER, NULL, NULL, NULL}
};

static gchar *oauth2_tmpl =
	"protected=0\n\n"
	"[Oauth2: 1]\n"
	"oa2_name=Google\n"
	"oa2_base_url=accounts.google.com\n"
	"oa2_client_id=\n"
	"oa2_client_secret=.\n"
	"oa2_redirect_uri=http://127.0.0.1:8888\n"
	"oa2_auth_resource=/o/oauth2/auth\n"
	"oa2_access_resource=/o/oauth2/token\n"
	"oa2_refresh_resource=/o/oauth2/token\n"
	"oa2_response_type=code\n"
	"oa2_scope_for_auth=https://mail.google.com\n"
	"oa2_grant_type_access=authorization_code\n"
	"oa2_grant_type_refresh=refresh_token\n"
	"oa2_tenant=\n"
	"oa2_state=\n"
	"oa2_access_type=\n"
	"oa2_scope_for_access=\n"
	"oa2_response_mode=\n"
	"oa2_header_auth_basic=\n"
	"oa2_two_stage_pop=0\n"
	"oa2_codemarker_start=code=\n"
	"oa2_codemarker_stop=&scope=\n\n"
	"[Oauth2: 2]\n"
	"oa2_name=Outlook\n"
	"oa2_base_url=login.microsoftonline.com\n"
	"oa2_client_id=\n"
	"oa2_client_secret=\n"
	"oa2_redirect_uri=http://127.0.0.1:8888\n"
	"oa2_auth_resource=/common/oauth2/v2.0/authorize\n"
	"oa2_access_resource=/common/oauth2/v2.0/token\n"
	"oa2_refresh_resource=/common/oauth2/v2.0/token\n"
	"oa2_response_type=code\n"
	"oa2_scope_for_auth=offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/POP.AccessAsUser.All https://outlook.office.com/SMTP.Send\n"
	"oa2_grant_type_access=authorization_code\n"
	"oa2_grant_type_refresh=refresh_token\n"
	"oa2_tenant=common\n"
	"oa2_state=\n"
	"oa2_access_type=offline\n"
	"oa2_scope_for_access=offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/POP.AccessAsUser.All https://outlook.office.com/SMTP.Send\n"
	"oa2_response_mode=query\n"
	"oa2_header_auth_basic=\n"
	"oa2_two_stage_pop=1\n"
	"oa2_codemarker_start=code=\n"
	"oa2_codemarker_stop= HTTP\n\n"
	"[Oauth2: 3]\n"
	"oa2_name=Exchange\n"
	"oa2_base_url=login.microsoftonline.com\n"
	"oa2_client_id=\n"
	"oa2_client_secret=\n"
	"oa2_redirect_uri=http://127.0.0.1:8888\n"
	"oa2_auth_resource=/common/oauth2/v2.0/authorize\n"
	"oa2_access_resource=/common/oauth2/v2.0/token\n"
	"oa2_refresh_resource=/common/oauth2/v2.0/token\n"
	"oa2_response_type=code\n"
	"oa2_scope_for_auth=offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/POP.AccessAsUser.All https://outlook.office.com/SMTP.Send\n"
	"oa2_grant_type_access=authorization_code\n"
	"oa2_grant_type_refresh=refresh_token\n"
	"oa2_tenant=common\n"
	"oa2_state=\n"
	"oa2_access_type=offline\n"
	"oa2_scope_for_access=offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/POP.AccessAsUser.All https://outlook.office.com/SMTP.Send\n"
	"oa2_response_mode=query\n"
	"oa2_header_auth_basic=\n"
	"oa2_two_stage_pop=1\n"
	"oa2_codemarker_start=code=\n"
	"oa2_codemarker_stop=&session_state=\n\n"
	"[Oauth2: 4]\n"
	"oa2_name=Microsoft_gcchigh\n"
	"oa2_base_url=login.microsoftonline.us\n"
	"oa2_client_id=\n"
	"oa2_client_secret=\n"
	"oa2_redirect_uri=http://127.0.0.1:8888\n"
	"oa2_auth_resource=/common/oauth2/v2.0/authorize\n"
	"oa2_access_resource=/common/oauth2/v2.0/token\n"
	"oa2_refresh_resource=/common/oauth2/v2.0/token\n"
	"oa2_response_type=code\n"
	"oa2_scope_for_auth=offline_access https://outlook.office365.us/IMAP.AccessAsUser.All https://outlook.office365.us/POP.AccessAsUser.All https://outlook.office365.us/SMTP.Send\n"
	"oa2_grant_type_access=authorization_code\n"
	"oa2_grant_type_refresh=refresh_token\n"
	"oa2_tenant=common\n"
	"oa2_state=\n"
	"oa2_access_type=offline\n"
	"oa2_scope_for_access=offline_access https://outlook.office365.us/IMAP.AccessAsUser.All https://outlook.office365.us/POP.AccessAsUser.All https://outlook.office365.us/SMTP.Send\n"
	"oa2_response_mode=query\n"
	"oa2_header_auth_basic=\n"
	"oa2_two_stage_pop=1\n"
	"oa2_codemarker_start=code=\n"
	"oa2_codemarker_stop=&session_state=\n\n"
	"[Oauth2: 5]\n"
	"oa2_name=Yahoo\n"
	"oa2_base_url=api.login.yahoo.com\n"
	"oa2_client_id=\n"
	"oa2_client_secret=.\n"
	"oa2_redirect_uri=oob\n"
	"oa2_auth_resource=/oauth2/request_auth\n"
	"oa2_access_resource=/oauth2/get_token\n"
	"oa2_refresh_resource=/oauth2/get_token\n"
	"oa2_response_type=code\n"
	"oa2_scope_for_auth=\n"
	"oa2_grant_type_access=authorization_code\n"
	"oa2_grant_type_refresh=refresh_token\n"
	"oa2_tenant=\n"
	"oa2_state=\n"
	"oa2_access_type=\n"
	"oa2_scope_for_access=\n"
	"oa2_response_mode=\n"
	"oa2_header_auth_basic=1\n"
	"oa2_two_stage_pop=0\n"
	"oa2_codemarker_start=\n"
	"oa2_codemarker_stop=\n"
	;

static Oauth2Info *oauth2_new_from_config(const gchar *label)
{
	gchar *rcpath;
	Oauth2Info *oa2_info;

	cm_return_val_if_fail(label != NULL, NULL);

	oa2_info = g_new0(Oauth2Info, 1);

	/* Load default values to tmp_oa2_info first, ... */
	memset(&tmp_oa2_info, 0, sizeof(Oauth2Info));
	prefs_set_default(oauth2_info);

	/* ... overriding them with values from stored config file. */
	rcpath = g_strconcat(get_rc_dir(), G_DIR_SEPARATOR_S, OAUTH2_RC, NULL);
	prefs_read_config(oauth2_info, label, rcpath, NULL);
	g_free(rcpath);

	*oa2_info = tmp_oa2_info;

	return oa2_info;
}

void account_read_oauth2_all(void)
{
	GSList *oauth2_label_list = NULL, *cur;
	Oauth2Info *oauth2_prefs;
	gchar *rcpath;
	gchar *oauth2_text, *version_text;
	FILE *fp;
	gchar buf[PREFSBUFSIZE];
	gint protected = 1;
	gint matchedversion = 0;

	debug_print("Reading oauth2rc file\n");
	
	rcpath = g_strconcat(get_rc_dir(), G_DIR_SEPARATOR_S, OAUTH2_RC, NULL);
	if ((fp = claws_fopen(rcpath, "rb")) == NULL) {
	        //No oauth2rc file exists
	        oauth2_text = g_strconcat("[Version: ", VERSION, "]\n", oauth2_tmpl, NULL);
	        str_write_to_file(oauth2_text, rcpath, TRUE);
		g_free(oauth2_text);
		debug_print("No oauth2rc file found, new one created\n");

		if ((fp = claws_fopen(rcpath, "rb")) == NULL) {
		        if (ENOENT != errno) FILE_OP_ERROR(rcpath, "claws_fopen");
			g_free(rcpath);
			return;
		}
	}else{  
	        //oauth2rc file exists. Check version and whether protected from update
	        version_text = g_strconcat("[Version: ", VERSION, "]\n", NULL);
	        while (claws_fgets(buf, sizeof(buf), fp) != NULL) {
		        if (!strncmp(buf, "protected=0", 11)) {
			  protected = 0;
			  debug_print("oauth2rc file is unprotected from updates\n");
			}
			
			if (!strcmp(buf, version_text)) {
			  matchedversion = 1;
			  debug_print("oauth2rc file matches Claws version\n");
			}
		}
		g_free(version_text);
		rewind(fp);
		
		if(!protected && !matchedversion){
		        //oauth2rc not protected from updates and does not match this version of Claws
		        //Update it to the latest template version.
		        claws_fclose(fp);
			oauth2_text = g_strconcat("[Version: ", VERSION, "]\n", oauth2_tmpl, NULL);
			str_write_to_file(oauth2_text, rcpath, TRUE);
			g_free(oauth2_text);
			debug_print("Replacement oauth2rc file created to match this Claws version\n");
			
			if ((fp = claws_fopen(rcpath, "rb")) == NULL) {
			        if (ENOENT != errno) FILE_OP_ERROR(rcpath, "claws_fopen");
				g_free(rcpath);
				return;
			}
		}
	}
	g_free(rcpath);

	while (claws_fgets(buf, sizeof(buf), fp) != NULL) {
		if (!strncmp(buf, "[Oauth2: ", 9)) {
			strretchomp(buf);
			memmove(buf, buf + 1, sizeof(buf) - 1);
			buf[strlen(buf) - 1] = '\0';
			debug_print("Found configuration: %s\n", buf);
			oauth2_label_list = g_slist_append(oauth2_label_list,
						       g_strdup(buf));
		}
	}
	claws_fclose(fp);

	/* read config data from file */
	for (cur = oauth2_label_list; cur != NULL; cur = cur->next) {
	        debug_print("Extracting oauth2 data\n");
		oauth2_prefs = oauth2_new_from_config((gchar *)cur->data);
		oauth2_providers_list = g_list_append(oauth2_providers_list, oauth2_prefs);
	}

	while (oauth2_label_list) {
		g_free(oauth2_label_list->data);
		oauth2_label_list = g_slist_remove(oauth2_label_list,
					       oauth2_label_list->data);
	}
}

GList *oauth2_providers_get_list(void)
{
	return oauth2_providers_list;
}

static gint oauth2_post_request (gchar *buf, gchar *host, gchar *resource, gchar *header, gchar *body)
{
       gint len;

       debug_print("Complete body: %s\n", body);
       len = strlen(body);
       if (header[0])
	 return snprintf(buf, OAUTH2BUFSIZE, "POST %s HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept: text/html,application/json\r\nContent-Length: %i\r\nHost: %s\r\nConnection: close\r\nUser-Agent: ClawsMail\r\n%s\r\n\r\n%s", resource, len, host, header, body);
       else
	 return snprintf(buf, OAUTH2BUFSIZE, "POST %s HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept: text/html,application/json\r\nContent-Length: %i\r\nHost: %s\r\nConnection: close\r\nUser-Agent: ClawsMail\r\n\r\n%s", resource, len, host, body);
}

static gint oauth2_filter_access (gchar *json, gchar *access_token, gint *expiry)
{
       GMatchInfo *matchInfo;
       GRegex *regex;
       
       regex = g_regex_new ("\"access_token\": ?\"(.*?)\",?", G_REGEX_RAW, 0, NULL);
       g_regex_match (regex, json, 0, &matchInfo);
       if (g_match_info_matches (matchInfo)) 
	 g_stpcpy (access_token,g_match_info_fetch (matchInfo, 1));
       else{  
	 g_match_info_free (matchInfo);
	 return (-1);
       }
       
       g_match_info_free (matchInfo);
       
       regex = g_regex_new ("\"expires_in\": ?([0-9]*),?", G_REGEX_RAW, 0, NULL);
       g_regex_match (regex, json, 0, &matchInfo);
       if (g_match_info_matches (matchInfo)){
	 // Reduce available token life to avoid attempting connections with (near) expired tokens
	 *expiry = (g_get_real_time () / G_USEC_PER_SEC) + atoi(g_match_info_fetch (matchInfo, 1)) - 120; 
       }else{
	 g_match_info_free (matchInfo);
	 return (-2);
       }
       
       g_match_info_free (matchInfo);
       
       return(0);
}

static gint oauth2_filter_refresh (gchar *json, gchar *refresh_token)
{
       GMatchInfo *matchInfo;
       GRegex *regex;
       
       regex = g_regex_new ("\"refresh_token\": ?\"(.*?)\",?", G_REGEX_RAW, 0, NULL);
       g_regex_match (regex, json, 0, &matchInfo);
       if (g_match_info_matches (matchInfo)) 
	 g_stpcpy (refresh_token,g_match_info_fetch (matchInfo, 1));
       else{  
	 g_match_info_free (matchInfo);
	 return (-1);
       }
       
       g_match_info_free (matchInfo);
       
       return(0);
}

static gchar* oauth2_get_token_from_response(Oauth2Service provider, const gchar* response) {
	gchar* token = NULL;
	gint i;
	Oauth2Info *oa2;
	
	//Retrieve oauth2 configuration information
	if(provider > g_list_length(oauth2_providers_list)){
	  debug_print("Configured OAUTH2 provider is not present in the oauth2rc config file\n");
	  return NULL;
	}
	
	i = (int)provider - 1;

	oa2 = g_list_nth_data (oauth2_providers_list, i);
	
        debug_print("Auth response: %s\n", response);
        if (!oa2->oa2_codemarker_start || !oa2->oa2_codemarker_stop ||
	    !oa2->oa2_codemarker_start[0] || !oa2->oa2_codemarker_stop[0]) {
	  /* Providers which display auth token in browser for users to copy */
                token = g_strdup(response);
        } else {
                gchar* start = g_strstr_len(response, strlen(response), oa2->oa2_codemarker_start);
                if (start == NULL)
                        return NULL;
                start += strlen(oa2->oa2_codemarker_start);
                gchar* stop = g_strstr_len(response, strlen(response), oa2->oa2_codemarker_stop);
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
		g_string_free(response, TRUE);
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

int oauth2_obtain_tokens (Oauth2Service provider, OAUTH2Data *OAUTH2Data, const gchar *authcode)
{
	gchar *request;
	gchar *response;
	gchar *body;
	gchar *uri;
	gchar *header;
	gchar *tmp_hd, *tmp_hd_encoded;
	gchar *access_token;
	gchar *refresh_token;
	gint expiry = 0;
	gint ret;
	SockInfo *sock;
	gchar *client_id;
	gchar *client_secret;
        gchar *token = NULL;
        gchar *tmp;
	gint i;
	Oauth2Info *oa2;
	
	//Retrieve oauth2 configuration information
	if(provider > g_list_length(oauth2_providers_list)){
	  debug_print("Configured OAUTH2 provider is not present in the oauth2rc config file\n");
	  return (1);
	}
	
	i = (int)provider - 1;
	oa2 = g_list_nth_data (oauth2_providers_list, i);

        token = oauth2_get_token_from_response(provider, authcode);
        debug_print("Auth token: %s\n", token);
        if (token == NULL) {
                log_message(LOG_PROTOCOL, _("OAuth2 missing authorization code\n"));
                return (1);
        }
        debug_print("Connect: %s:443\n", oa2->oa2_base_url);
	sock = sock_connect(oa2->oa2_base_url, 443);
	if (sock == NULL) {
                log_message(LOG_PROTOCOL, _("OAuth2 connection error\n"));
                g_free(token);
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
                g_free(token);
                return (1);
        }

	refresh_token = g_malloc(OAUTH2BUFSIZE+1);	
	access_token = g_malloc(OAUTH2BUFSIZE+1);
	request = g_malloc(OAUTH2BUFSIZE+1);

	if(OAUTH2Data->custom_client_id[0])
	  client_id = g_strdup(OAUTH2Data->custom_client_id);
	else
	  client_id = g_strdup(oa2->oa2_client_id);

        body = g_strconcat ("client_id=", client_id, "&code=", token, NULL);
        debug_print("Body: %s\n", body);
        g_free(token);

	if(oa2->oa2_client_secret[0]){
	  //Only allow custom client secret if the service provider would usually expect a client secret
	  if(OAUTH2Data->custom_client_secret[0])
	    client_secret = g_strdup(OAUTH2Data->custom_client_secret);
	  else
	    client_secret = g_strdup(oa2->oa2_client_secret);
	  uri = g_uri_escape_string (client_secret, NULL, FALSE);
	  tmp = g_strconcat (body, "&client_secret=", uri, NULL);
	  g_free(body);
          g_free(uri);
	  body = tmp;
	}else{
	  client_secret = g_strconcat ("", NULL);
	}

	if(oa2->oa2_redirect_uri[0]) {
          tmp = g_strconcat(body, "&redirect_uri=", oa2->oa2_redirect_uri, NULL);
	  g_free(body);
	  body = tmp;
	}
	if(oa2->oa2_grant_type_access[0]) {
          tmp = g_strconcat(body, "&grant_type=", oa2->oa2_grant_type_access, NULL);
	  g_free(body);
	  body = tmp;
	}
	if(oa2->oa2_tenant[0]) {
          tmp = g_strconcat(body, "&tenant=", oa2->oa2_tenant, NULL);
	  g_free(body);
	  body = tmp;
	}
	if(oa2->oa2_scope_for_access[0]) {
          tmp = g_strconcat(body, "&scope=", oa2->oa2_scope_for_access, NULL);
	  g_free(body);
	  body = tmp;
	}
	if(oa2->oa2_state[0]) {
          tmp = g_strconcat(body, "&state=", oa2->oa2_state, NULL);
	  g_free(body);
	  body = tmp;
	}

	if(oa2->oa2_header_auth_basic[0]){
	  tmp_hd = g_strconcat(client_id, ":", client_secret, NULL);
	  tmp_hd_encoded = g_base64_encode (tmp_hd, strlen(tmp_hd));
	  header = g_strconcat ("Authorization: Basic ", tmp_hd_encoded, NULL);
	  g_free(tmp_hd_encoded);
	  g_free(tmp_hd);
	}else{
	  header = g_strconcat ("", NULL);
	}

	oauth2_post_request (request, oa2->oa2_base_url, oa2->oa2_access_resource, header, body);
	response = oauth2_contact_server (sock, request);
	debug_print("Response from server: %s\n", response);

	if(response && oauth2_filter_access (response, access_token, &expiry) == 0){
	  OAUTH2Data->access_token = g_strdup(access_token);
	  OAUTH2Data->expiry = expiry;
	  OAUTH2Data->expiry_str = g_strdup_printf ("%i", expiry);
	  ret = 0;
	  log_message(LOG_PROTOCOL, _("OAuth2 access token obtained\n"));
	}else{
	  log_message(LOG_PROTOCOL, _("OAuth2 access token not obtained\n"));
	  debug_print("OAuth2 - request: %s\n Response: %s", request, response);
	  ret = 1;
	}

	if(response && oauth2_filter_refresh (response, refresh_token) == 0){
	  OAUTH2Data->refresh_token = g_strdup(refresh_token);
	  log_message(LOG_PROTOCOL, _("OAuth2 refresh token obtained\n"));
	}else{
	  log_message(LOG_PROTOCOL, _("OAuth2 refresh token not obtained\n"));
	}

	sock_close(sock, TRUE);
	g_free(body);
	g_free(header);
	g_free(request);
	g_free(response);
	g_free(client_id);
	g_free(client_secret);
	g_free(access_token);
	g_free(refresh_token);

	return (ret);
}

gint oauth2_use_refresh_token (Oauth2Service provider, OAUTH2Data *OAUTH2Data)
{

	gchar *request;
	gchar *response;
	gchar *body;
	gchar *uri;
	gchar *header;
	gchar *tmp_hd, *tmp_hd_encoded;
	gchar *access_token;
	gchar *refresh_token;
	gint expiry = 0;
	gint ret;
	SockInfo *sock;
	gchar *client_id;
	gchar *client_secret;
	gchar *tmp;
	gint i;
	Oauth2Info *oa2;
	
	//Retrieve oauth2 configuration information
	if(provider > g_list_length(oauth2_providers_list)){
	  debug_print("Configured OAUTH2 provider is not present in the oauth2rc config file\n");
	  return (1);
	}
	
	i = (int)provider - 1;
	oa2 = g_list_nth_data (oauth2_providers_list, i);

	sock = sock_connect(oa2->oa2_base_url, 443);
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

	access_token = g_malloc(OAUTH2BUFSIZE+1);
	refresh_token = g_malloc(OAUTH2BUFSIZE+1);
	request = g_malloc(OAUTH2BUFSIZE+1);

	if(OAUTH2Data->custom_client_id[0])
	  client_id = g_strdup(OAUTH2Data->custom_client_id);
	else
	  client_id = g_strdup(oa2->oa2_client_id);

	uri = g_uri_escape_string (client_id, NULL, FALSE);
	body = g_strconcat ("client_id=", uri, "&refresh_token=", OAUTH2Data->refresh_token, NULL); 
	g_free(uri);

	if(oa2->oa2_client_secret[0]){
	  //Only allow custom client secret if the service provider would usually expect a client secret
	  if(OAUTH2Data->custom_client_secret[0])
	    client_secret = g_strdup(OAUTH2Data->custom_client_secret);
	  else
	    client_secret = g_strdup(oa2->oa2_client_secret);
	  uri = g_uri_escape_string (client_secret, NULL, FALSE);
	  tmp = g_strconcat (body, "&client_secret=", uri, NULL);
	  g_free(body);
	  g_free(uri);
	  body = tmp;
	}else{
	  client_secret = g_strconcat ("", NULL);
	}

	if(oa2->oa2_grant_type_refresh[0]) {
	  uri = g_uri_escape_string (oa2->oa2_grant_type_refresh, NULL, FALSE);
	  tmp = g_strconcat (body, "&grant_type=", uri, NULL);	
	  g_free(body);
	  g_free(uri);
	  body = tmp;
	}
	if(oa2->oa2_scope_for_access[0]) {
	  uri = g_uri_escape_string (oa2->oa2_scope_for_access, NULL, FALSE);
	  tmp = g_strconcat (body, "&scope=", uri, NULL);
	  g_free(body);
	  g_free(uri);
	  body = tmp;
	}
	if(oa2->oa2_state[0]) {
	  uri = g_uri_escape_string (oa2->oa2_state, NULL, FALSE);
	  tmp = g_strconcat (body, "&state=", uri, NULL);
	  g_free(body);
	  g_free(uri);
	  body = tmp;
	}

	if(oa2->oa2_header_auth_basic[0]){
	  tmp_hd = g_strconcat(client_id, ":", client_secret, NULL);
	  tmp_hd_encoded = g_base64_encode (tmp_hd, strlen(tmp_hd));
	  header = g_strconcat ("Authorization: Basic ", tmp_hd_encoded, NULL);
	  g_free(tmp_hd_encoded);
	  g_free(tmp_hd);
	}else{
	  header = g_strconcat ("", NULL);
	}

	oauth2_post_request (request, oa2->oa2_base_url, oa2->oa2_refresh_resource, header, body);
	debug_print("Request: %s\n", request);
	response = oauth2_contact_server (sock, request);
	debug_print("Response from server: %s\n", response);


	if(response && oauth2_filter_access (response, access_token, &expiry) == 0){
	  OAUTH2Data->access_token = g_strdup(access_token);
	  OAUTH2Data->expiry = expiry;
	  OAUTH2Data->expiry_str = g_strdup_printf ("%i", expiry);
	  ret = 0;
	  log_message(LOG_PROTOCOL, _("OAuth2 access token obtained\n"));
	}else{
	  log_message(LOG_PROTOCOL, _("OAuth2 access token not obtained\n"));
	  debug_print("OAuth2 - request: %s\n Response: %s", request, response);
	  ret = 1;
	}

	if (response && oauth2_filter_refresh (response, refresh_token) == 0) {
		OAUTH2Data->refresh_token = g_strdup(refresh_token);
		log_message(LOG_PROTOCOL, _("OAuth2 replacement refresh token provided\n"));
	} else
		log_message(LOG_PROTOCOL, _("OAuth2 replacement refresh token not provided\n"));

	debug_print("OAuth2 - access token: %s\n", access_token);
	debug_print("OAuth2 - access token expiry: %i\n", expiry);
	
	sock_close(sock, TRUE);
	g_free(body);
	g_free(header);
	g_free(request);
	g_free(response);
	g_free(client_id);
	g_free(client_secret);
	g_free(access_token);
	g_free(refresh_token);

	return (ret);
}

gint oauth2_authorisation_url (Oauth2Service provider, gchar **url, const gchar *custom_client_id)
{
	gint i;
	gchar *client_id = NULL;
	gchar *tmp;
	gchar *uri;
	Oauth2Info *oa2;
	
	//Retrieve oauth2 configuration information
	if(provider > g_list_length(oauth2_providers_list)){
	  debug_print("Configured OAUTH2 provider is not present in the oauth2rc config file\n");
	  return (1);
	}
	
	i = (int)provider - 1;
	oa2 = g_list_nth_data (oauth2_providers_list, i);

	debug_print("FROM OAUTH2.C Oauth2 name: %s\n", oa2->oa2_name);
	debug_print("FROM OAUTH2.C Oauth2 URL: %s\n", oa2->oa2_redirect_uri);

	if(!custom_client_id[0])
	  client_id = g_strdup(oa2->oa2_client_id);
	
	uri = g_uri_escape_string (custom_client_id[0] ? custom_client_id : client_id, NULL, FALSE);
	*url = g_strconcat ("https://", oa2->oa2_base_url, oa2->oa2_auth_resource, "?client_id=",
			    uri, NULL);
	g_free(uri);
	if (client_id)
	  g_free(client_id);

	if(oa2->oa2_redirect_uri[0]) {
	  uri = g_uri_escape_string (oa2->oa2_redirect_uri, NULL, FALSE);
	  tmp = g_strconcat (*url, "&redirect_uri=", uri, NULL);
	  g_free(*url);
	  *url = tmp;
	  g_free(uri);
    
	}  
	if(oa2->oa2_response_type[0]) {
	  uri = g_uri_escape_string (oa2->oa2_response_type, NULL, FALSE);
	  tmp = g_strconcat (*url, "&response_type=", uri, NULL);
	  g_free(*url);
	  *url = tmp;
	  g_free(uri);
	}  
	if(oa2->oa2_scope_for_auth[0]) {
	  uri = g_uri_escape_string (oa2->oa2_scope_for_auth, NULL, FALSE);
	  tmp = g_strconcat (*url, "&scope=", uri, NULL);
	  g_free(*url);
	  *url = tmp;
	  g_free(uri);
	}  
	if(oa2->oa2_tenant[0]) {
	  uri = g_uri_escape_string (oa2->oa2_tenant, NULL, FALSE);
	  tmp = g_strconcat (*url, "&tenant=", uri, NULL);
	  g_free(*url);
	  *url = tmp;
	  g_free(uri);
	}  
	if(oa2->oa2_response_mode[0]) {
	  uri = g_uri_escape_string (oa2->oa2_response_mode, NULL, FALSE);
	  tmp = g_strconcat (*url, "&response_mode=", uri, NULL);
	  g_free(*url);
	  *url = tmp;
	  g_free(uri);
	}  
	if(oa2->oa2_state[0]) {
	  uri = g_uri_escape_string (oa2->oa2_state, NULL, FALSE);
	  tmp = g_strconcat (*url, "&state=", uri, NULL);
	  g_free(*url);
	  *url = tmp;
	  g_free(uri);
	}  

	return (0);
}

gint oauth2_check_passwds (PrefsAccount *ac_prefs)
{
	gchar *uid = g_strdup_printf("%d", ac_prefs->account_id);
	gint expiry;
	OAUTH2Data *OAUTH2Data = g_malloc(sizeof(* OAUTH2Data)); 
	gint ret;
	gchar *acc;

	oauth2_init (OAUTH2Data);

	OAUTH2Data->custom_client_id = ac_prefs->oauth2_client_id;
	OAUTH2Data->custom_client_secret = ac_prefs->oauth2_client_secret;
	
	if (passwd_store_has_password(PWS_ACCOUNT, uid, PWS_ACCOUNT_OAUTH2_EXPIRY)) {
		acc = passwd_store_get_account(ac_prefs->account_id, PWS_ACCOUNT_OAUTH2_EXPIRY);
		expiry = atoi(acc);
		g_free(acc);
		if (expiry >  (g_get_real_time () / G_USEC_PER_SEC)) {
			g_free(OAUTH2Data);
			log_message(LOG_PROTOCOL, _("OAuth2 access token still fresh\n"));
			g_free(uid);
			return (0);
		}
	}
	
	if (passwd_store_has_password(PWS_ACCOUNT, uid, PWS_ACCOUNT_OAUTH2_REFRESH)) {
		log_message(LOG_PROTOCOL, _("OAuth2 obtaining access token using refresh token\n"));
		OAUTH2Data->refresh_token = passwd_store_get_account(ac_prefs->account_id, PWS_ACCOUNT_OAUTH2_REFRESH);
		ret = oauth2_use_refresh_token (ac_prefs->oauth2_provider, OAUTH2Data);
	} else if (passwd_store_has_password(PWS_ACCOUNT, uid, PWS_ACCOUNT_OAUTH2_AUTH)) {
		log_message(LOG_PROTOCOL, _("OAuth2 trying for fresh access token with authorization code\n"));
		acc = passwd_store_get_account(ac_prefs->account_id, PWS_ACCOUNT_OAUTH2_AUTH);
		ret = oauth2_obtain_tokens (ac_prefs->oauth2_provider, OAUTH2Data, acc);
		g_free(acc);
	} else
		ret = 1;
	
	if (ret)
		log_message(LOG_PROTOCOL, _("OAuth2 access token not obtained\n"));
	else {
		if (ac_prefs->imap_auth_type == IMAP_AUTH_OAUTH2 ||
		    (ac_prefs->use_pop_auth && ac_prefs->pop_auth_type == POPAUTH_OAUTH2))
			passwd_store_set_account(ac_prefs->account_id, PWS_ACCOUNT_RECV, OAUTH2Data->access_token, FALSE);
		if (ac_prefs->use_smtp_auth && ac_prefs->smtp_auth_type == SMTPAUTH_OAUTH2)
			passwd_store_set_account(ac_prefs->account_id, PWS_ACCOUNT_SEND, OAUTH2Data->access_token, FALSE);
		passwd_store_set_account(ac_prefs->account_id, PWS_ACCOUNT_OAUTH2_EXPIRY, OAUTH2Data->expiry_str, FALSE);
		//Some providers issue replacement refresh tokens with each access token. Re-store whether replaced or not. 
		if (OAUTH2Data->refresh_token != NULL)
			passwd_store_set_account(ac_prefs->account_id, PWS_ACCOUNT_OAUTH2_REFRESH, OAUTH2Data->refresh_token, FALSE);
		passwd_store_write_config();
		log_message(LOG_PROTOCOL, _("OAuth2 access and refresh token updated\n"));  
	}
	if (OAUTH2Data->refresh_token) {
		memset(OAUTH2Data->refresh_token, 0, strlen(OAUTH2Data->refresh_token));
	}
	g_free(OAUTH2Data->refresh_token);
	g_free(OAUTH2Data);
	g_free(uid);
	
	return (ret);
}

gint oauth2_init (OAUTH2Data *OAUTH2Data)
{ 
	 OAUTH2Data->refresh_token = NULL;
	 OAUTH2Data->access_token = NULL;
	 OAUTH2Data->expiry_str = NULL;
	 OAUTH2Data->expiry = 0;
	 OAUTH2Data->custom_client_id = NULL;
	 OAUTH2Data->custom_client_secret = NULL;
	 
	 return (0);
}

#endif	/* USE_OAUTH2 */
