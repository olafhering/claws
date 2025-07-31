/*
 * Claws Mail -- a GTK based, lightweight, and fast e-mail client
 * Copyright (C) 2020-2022 the Claws Mail team
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
#include "claws-features.h"
#endif

#ifdef USE_OAUTH2

#include <glib.h>

#include "socket.h"
#include "passwordstore.h"
#include "smtp.h"
#include "prefs_account.h"
#include "prefs_gtk.h"

#define OAUTH2BUFSIZE		8192
#define OAUTH2AUTH_NONE 0

GList	     *oauth2_providers_get_list		(void);

typedef int Oauth2Service;

typedef struct _OAUTH2Data OAUTH2Data;

struct _OAUTH2Data
{
	gchar *refresh_token;
	gchar *access_token;
        gint expiry;
        gchar *expiry_str;
        gchar *custom_client_id;
        gchar *custom_client_secret;
};

gint oauth2_init (OAUTH2Data *OAUTH2Data);
gint oauth2_check_passwds (PrefsAccount *ac_prefs);
gint oauth2_obtain_tokens (Oauth2Service provider, OAUTH2Data *OAUTH2Data, const gchar *authcode);
gint oauth2_authorisation_url (Oauth2Service provider, gchar **url, const gchar *custom_client_id);
gint oauth2_use_refresh_token (Oauth2Service provider, OAUTH2Data *OAUTH2Data);

struct _Oauth2Info
{
        gchar *oa2_name;
        gchar *oa2_base_url;
        gchar *oa2_client_id;
        gchar *oa2_client_secret;
        gchar *oa2_redirect_uri;
        gchar *oa2_auth_resource;
        gchar *oa2_access_resource;
        gchar *oa2_refresh_resource;
        gchar *oa2_response_type;
        gchar *oa2_scope_for_auth;
        gchar *oa2_grant_type_access;
        gchar *oa2_grant_type_refresh;
        gchar *oa2_tenant;
        gchar *oa2_state;
        gchar *oa2_access_type;
        gchar *oa2_scope_for_access;
        gchar *oa2_response_mode;
        gchar *oa2_header_auth_basic;
        gint  oa2_two_stage_pop;
        gchar *oa2_codemarker_start;
        gchar *oa2_codemarker_stop;
};

typedef struct _Oauth2Info  Oauth2Info;

void account_read_oauth2_all (void);

#endif	/* USE_OAUTH2 */
