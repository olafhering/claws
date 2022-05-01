/*
 * Claws Mail -- a GTK based, lightweight, and fast e-mail client
 * Copyright (C) 2012-2023 the Claws Mail team
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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#include "claws-features.h"
#endif

#include "advsearch.h"

#include <glib.h>
#include <ctype.h>

#include "matcher.h"
#include "matcher_parser.h"
#include "utils.h"
#include "prefs_common.h"
#include "timing.h"

struct _AdvancedSearch {
	struct {
		AdvancedSearchType type;
		gchar *matchstring;
	} request;

	MatcherList *predicate;
	gboolean is_fast;
	gboolean search_aborted;

	struct {
		gboolean (*cb)(gpointer data, guint at, guint matched, guint total);
		gpointer data;
	} on_progress_cb;
	struct {
		void (*cb)(gpointer data);
		gpointer data;
	} on_error_cb;
};

void advsearch_set_on_progress_cb(AdvancedSearch *search, gboolean (*cb)(gpointer, guint, guint, guint), gpointer data)
{
	search->on_progress_cb.cb = cb;
	search->on_progress_cb.data = data;
}

void advsearch_set_on_error_cb(AdvancedSearch *search, void (*cb)(gpointer data), gpointer data)
{
	search->on_error_cb.cb = cb;
	search->on_error_cb.data = data;
}

static void prepare_matcher(AdvancedSearch *search);
static gboolean search_impl(MsgInfoList **messages, AdvancedSearch *search, FolderItem *folderItem, gboolean recursive);

// --------------------------

AdvancedSearch *advsearch_new()
{
	AdvancedSearch *result;

	result = g_new0(AdvancedSearch, 1);

	return result;
}

void advsearch_free(AdvancedSearch *search)
{
	if (search->predicate != NULL)
		matcherlist_free(search->predicate);

	g_free(search->request.matchstring);
	g_free(search);
}

void advsearch_set(AdvancedSearch *search, AdvancedSearchType type, const gchar *matchstring)
{
	cm_return_if_fail(search != NULL);

	search->request.type = type;

	g_free(search->request.matchstring);
	search->request.matchstring = g_strdup(matchstring);

	prepare_matcher(search);
}

gboolean advsearch_is_fast(AdvancedSearch *search)
{
	cm_return_val_if_fail(search != NULL, FALSE);

	return search->is_fast;
}

gboolean advsearch_has_proper_predicate(AdvancedSearch *search)
{
	cm_return_val_if_fail(search != NULL, FALSE);

	return search->predicate != NULL;
}

gboolean advsearch_search_msgs_in_folders(AdvancedSearch *search, MsgInfoList **messages, FolderItem *folderItem, gboolean recursive)
{
	if (search == NULL || search->predicate == NULL)
		return FALSE;

	search->search_aborted = FALSE;
	return search_impl(messages, search, folderItem, recursive);
}

void advsearch_abort(AdvancedSearch *search)
{
	search->search_aborted = TRUE;
}

static void advsearch_extract_param(GString *matcherstr, gchar **cmd_start_, gchar **cmd_end_, gboolean quotes, gboolean qualifier, gboolean casesens, gboolean regex)
{
	gchar *cmd_start, *cmd_end;
	gchar term_char, save_char;

	cmd_start = *cmd_start_;
	cmd_end = *cmd_end_;

	/* extract a parameter, allow quotes */
	while (*cmd_end && isspace((guchar)*cmd_end))
		cmd_end++;

	cmd_start = cmd_end;
	if (*cmd_start == '"') {
		term_char = '"';
		cmd_end++;
	} else
		term_char = ' ';

	/* extract actual parameter */
	while ((*cmd_end) && (*cmd_end != term_char))
		cmd_end++;

	if (*cmd_end == '"')
		cmd_end++;

	save_char = *cmd_end;
	*cmd_end = '\0';

	if (qualifier) {
		if (casesens)
			g_string_append(matcherstr, regex ? "regexp " : "match ");
		else
			g_string_append(matcherstr, regex ? "regexpcase " : "matchcase ");
	}

	/* do we need to add quotes ? */
	if (quotes && term_char != '"')
		g_string_append(matcherstr, "\"");

	/* copy actual parameter */
	g_string_append(matcherstr, cmd_start);

	/* do we need to add quotes ? */
	if (quotes && term_char != '"')
		g_string_append(matcherstr, "\"");

	/* restore original character */
	*cmd_end = save_char;

	*cmd_end_ = cmd_end;
	*cmd_start_ = cmd_start;
	return;
}

gchar *advsearch_expand_search_string(const gchar *search_string)
{
	int i = 0;
	gchar *cmd_start, *cmd_end;
	gchar save_char;
	GString *matcherstr;
	gchar *returnstr = NULL;
	gchar *copy_str;
	gboolean casesens, dontmatch, regex;
	/* list of allowed pattern abbreviations */
	struct {
		gchar *abbreviated; /* abbreviation */
		gchar *command;	/* actual matcher command */
		gint numparams;	/* number of params for cmd */
		gboolean qualifier; /* do we append stringmatch operations */
		gboolean quotes; /* do we need quotes */
	} cmds[] = {
		{"a", "all", 0, FALSE, FALSE},
		{"ag", "age_greater", 1, FALSE, FALSE},
		{"al", "age_lower", 1, FALSE, FALSE},
		{"agh", "age_greater_hours", 1, FALSE, FALSE},
		{"alh", "age_lower_hours", 1, FALSE, FALSE},
		{"b", "body_part", 1, TRUE, TRUE},
		{"B", "message", 1, TRUE, TRUE},
		{"c", "cc", 1, TRUE, TRUE},
		{"C", "to_or_cc", 1, TRUE, TRUE},
		{"D", "deleted", 0, FALSE, FALSE},
		{"da", "date_after", 1, FALSE, TRUE},
		{"db", "date_before", 1, FALSE, TRUE},
		{"e", "header \"Sender\"", 1, TRUE, TRUE},
		{"E", "execute", 1, FALSE, TRUE},
		{"f", "from", 1, TRUE, TRUE},
		{"F", "forwarded", 0, FALSE, FALSE},
		{"h", "headers_part", 1, TRUE, TRUE},
		{"H", "headers_cont", 1, TRUE, TRUE},
		{"ha", "has_attachments", 0, FALSE, FALSE},
		{"i", "messageid", 1, TRUE, TRUE},
		{"I", "inreplyto", 1, TRUE, TRUE},
		{"k", "colorlabel", 1, FALSE, FALSE},
		{"L", "locked", 0, FALSE, FALSE},
		{"n", "newsgroups", 1, TRUE, TRUE},
		{"N", "new", 0, FALSE, FALSE},
		{"O", "~new", 0, FALSE, FALSE},
		{"r", "replied", 0, FALSE, FALSE},
		{"R", "~unread", 0, FALSE, FALSE},
		{"s", "subject", 1, TRUE, TRUE},
		{"se", "score_equal", 1, FALSE, FALSE},
		{"sg", "score_greater", 1, FALSE, FALSE},
		{"sl", "score_lower", 1, FALSE, FALSE},
		{"Se", "size_equal", 1, FALSE, FALSE},
		{"Sg", "size_greater", 1, FALSE, FALSE},
		{"Ss", "size_smaller", 1, FALSE, FALSE},
		{"t", "to", 1, TRUE, TRUE},
		{"tg", "tag", 1, TRUE, TRUE},
		{"T", "marked", 0, FALSE, FALSE},
		{"U", "unread", 0, FALSE, FALSE},
		{"x", "references", 1, TRUE, TRUE},
		{"X", "test", 1, FALSE, FALSE},
		{"v", "header", 2, TRUE, TRUE},
		{"&", "&", 0, FALSE, FALSE},
		{"|", "|", 0, FALSE, FALSE},
		{"p", "partial", 0, FALSE, FALSE},
		{NULL, NULL, 0, FALSE, FALSE}
	};

	if (search_string == NULL)
		return NULL;

	copy_str = g_strdup(search_string);

	matcherstr = g_string_sized_new(16);
	cmd_start = copy_str;
	while (cmd_start && *cmd_start) {
		/* skip all white spaces */
		while (*cmd_start && isspace((guchar)*cmd_start))
			cmd_start++;
		cmd_end = cmd_start;

		/* extract a command */
		while (*cmd_end && !isspace((guchar)*cmd_end))
			cmd_end++;

		/* save character */
		save_char = *cmd_end;
		*cmd_end = '\0';

		dontmatch = FALSE;
		casesens = FALSE;
		regex = FALSE;

		/* ~ and ! mean logical NOT */
		if (*cmd_start == '~' || *cmd_start == '!') {
			dontmatch = TRUE;
			cmd_start++;
		}
		/* % means case sensitive match */
		if (*cmd_start == '%') {
			casesens = TRUE;
			cmd_start++;
		}
		/* # means regex match */
		if (*cmd_start == '#') {
			regex = TRUE;
			cmd_start++;
		}

		/* find matching abbreviation */
		for (i = 0; cmds[i].command; i++) {
			if (!strcmp(cmd_start, cmds[i].abbreviated)) {
				/* restore character */
				*cmd_end = save_char;

				/* copy command */
				if (matcherstr->len > 0) {
					g_string_append(matcherstr, " ");
				}
				if (dontmatch)
					g_string_append(matcherstr, "~");
				g_string_append(matcherstr, cmds[i].command);
				g_string_append(matcherstr, " ");

				/* stop if no params required */
				if (cmds[i].numparams == 0)
					break;

				/* extract a first parameter before the final matched one */
				if (cmds[i].numparams == 2) {
					advsearch_extract_param(matcherstr, &cmd_start, &cmd_end, cmds[i].quotes, FALSE, casesens, regex);
					g_string_append(matcherstr, " ");
				}
				advsearch_extract_param(matcherstr, &cmd_start, &cmd_end, cmds[i].quotes, cmds[i].qualifier, casesens, regex);
				break;
			}
		}

		if (*cmd_end)
			cmd_end++;
		cmd_start = cmd_end;
	}

	g_free(copy_str);

	/* return search string if no match is found to allow
	   all available filtering expressions in advanced search */
	if (matcherstr->len > 0) {
		returnstr = g_string_free(matcherstr, FALSE);
	} else {
		returnstr = g_strdup(search_string);
		g_string_free(matcherstr, TRUE);
	}
	return returnstr;
}

static void prepare_matcher_extended(AdvancedSearch *search)
{
	gchar *newstr = advsearch_expand_search_string(search->request.matchstring);

	if (newstr && newstr[0] != '\0') {
		search->predicate = matcher_parser_get_cond(newstr, &search->is_fast);
		g_free(newstr);
	}
}

#define debug_matcher_list(prefix, list)					\
do {										\
	gchar *str = list ? matcherlist_to_string(list) : g_strdup("(NULL)");	\
										\
	debug_print("%s: %s\n", prefix, str);					\
										\
	g_free(str);								\
} while(0)

static void prepare_matcher_tag(AdvancedSearch *search)
{
	gchar **words = search->request.matchstring ? g_strsplit(search->request.matchstring, " ", -1)
	    : NULL;
	gint i = 0;

	if (search->predicate == NULL) {
		search->predicate = g_new0(MatcherList, 1);
		search->predicate->bool_and = FALSE;
		search->is_fast = TRUE;
	}

	while (words && words[i] && *words[i]) {
		MatcherProp *matcher;

		g_strstrip(words[i]);

		matcher = matcherprop_new(MATCHCRITERIA_TAG, NULL, MATCHTYPE_MATCHCASE, words[i], 0);

		search->predicate->matchers = g_slist_prepend(search->predicate->matchers, matcher);

		i++;
	}
	g_strfreev(words);
}

static void prepare_matcher_header(AdvancedSearch *search, gint match_header)
{
	MatcherProp *matcher;

	if (search->predicate == NULL) {
		search->predicate = g_new0(MatcherList, 1);
		search->predicate->bool_and = FALSE;
		search->is_fast = TRUE;
	}

	matcher = matcherprop_new(match_header, NULL, MATCHTYPE_MATCHCASE, search->request.matchstring, 0);

	search->predicate->matchers = g_slist_prepend(search->predicate->matchers, matcher);
}

static void prepare_matcher_mixed(AdvancedSearch *search)
{
	prepare_matcher_tag(search);
	debug_matcher_list("tag matcher list", search->predicate);

	/* we want an OR search */
	if (search->predicate)
		search->predicate->bool_and = FALSE;

	prepare_matcher_header(search, MATCHCRITERIA_SUBJECT);
	debug_matcher_list("tag + subject matcher list", search->predicate);
	prepare_matcher_header(search, MATCHCRITERIA_FROM);
	debug_matcher_list("tag + subject + from matcher list", search->predicate);
	prepare_matcher_header(search, MATCHCRITERIA_TO);
	debug_matcher_list("tag + subject + from + to matcher list", search->predicate);
	prepare_matcher_header(search, MATCHCRITERIA_CC);
	debug_matcher_list("tag + subject + from + to + cc matcher list", search->predicate);
}

static void prepare_matcher(AdvancedSearch *search)
{
	const gchar *search_string;

	cm_return_if_fail(search != NULL);

	if (search->predicate) {
		matcherlist_free(search->predicate);
		search->predicate = NULL;
	}

	search_string = search->request.matchstring;

	if (search_string == NULL || search_string[0] == '\0')
		return;

	switch (search->request.type) {
	case ADVANCED_SEARCH_SUBJECT:
		prepare_matcher_header(search, MATCHCRITERIA_SUBJECT);
		debug_matcher_list("subject search", search->predicate);
		break;

	case ADVANCED_SEARCH_FROM:
		prepare_matcher_header(search, MATCHCRITERIA_FROM);
		debug_matcher_list("from search", search->predicate);
		break;

	case ADVANCED_SEARCH_TO:
		prepare_matcher_header(search, MATCHCRITERIA_TO);
		debug_matcher_list("to search", search->predicate);
		break;

	case ADVANCED_SEARCH_TAG:
		prepare_matcher_tag(search);
		debug_matcher_list("tag search", search->predicate);
		break;

	case ADVANCED_SEARCH_MIXED:
		prepare_matcher_mixed(search);
		debug_matcher_list("mixed search", search->predicate);
		break;

	case ADVANCED_SEARCH_EXTENDED:
		prepare_matcher_extended(search);
		debug_matcher_list("extended search", search->predicate);
		break;

	default:
		debug_print("unknown search type (%d)\n", search->request.type);
		break;
	}
}

static gboolean search_progress_notify_cb(gpointer data, gboolean on_server, guint at, guint matched, guint total)
{
	AdvancedSearch *search = (AdvancedSearch *)data;

	if (search->search_aborted)
		return FALSE;

	if (on_server || search->on_progress_cb.cb == NULL)
		return TRUE;

	return search->on_progress_cb.cb(search->on_progress_cb.data, at, matched, total);
}

static gboolean search_filter_folder(MsgNumberList **msgnums, AdvancedSearch *search, FolderItem *folderItem, gboolean onServer)
{
	gint matched;
	gboolean tried_server = onServer;

	matched = folder_item_search_msgs(folderItem->folder, folderItem, msgnums, &onServer, search->predicate, search_progress_notify_cb, search);

	if (matched < 0) {
		if (search->on_error_cb.cb != NULL)
			search->on_error_cb.cb(search->on_error_cb.data);
		return FALSE;
	}

	if (folderItem->folder->klass->supports_server_search && tried_server && !onServer) {
		return search_filter_folder(msgnums, search, folderItem, onServer);
	} else {
		return TRUE;
	}
}

static gboolean search_impl(MsgInfoList **messages, AdvancedSearch *search, FolderItem *folderItem, gboolean recursive)
{
	if (recursive) {
		START_TIMING("recursive");
		if (!search_impl(messages, search, folderItem, FALSE)) {
			END_TIMING();
			return FALSE;
		}
		if (folderItem->node->children != NULL && !search->search_aborted) {
			GNode *node;
			for (node = folderItem->node->children; node != NULL; node = node->next) {
				FolderItem *cur = FOLDER_ITEM(node->data);
				debug_print("in: %s\n", cur->path);
				if (!search_impl(messages, search, cur, TRUE)) {
					END_TIMING();
					return FALSE;
				}
			}
		}
		END_TIMING();
	} else if (!folderItem->no_select) {
		MsgNumberList *msgnums = NULL;
		MsgNumberList *cur;
		MsgInfoList *msgs = NULL;
		gboolean can_search_on_server = folderItem->folder->klass->supports_server_search;
		START_TIMING("folder");
		if (!search_filter_folder(&msgnums, search, folderItem, can_search_on_server)) {
			g_slist_free(msgnums);
			END_TIMING();
			return FALSE;
		}

		for (cur = msgnums; cur != NULL; cur = cur->next) {
			MsgInfo *msg = folder_item_get_msginfo(folderItem, GPOINTER_TO_UINT(cur->data));

			msgs = g_slist_prepend(msgs, msg);
		}

		while (msgs != NULL) {
			MsgInfoList *front = msgs;

			msgs = msgs->next;

			front->next = *messages;
			*messages = front;
		}

		g_slist_free(msgnums);
		END_TIMING();
	}

	return TRUE;
}
/*
 * vim: noet ts=4 shiftwidth=4 nowrap
 */
