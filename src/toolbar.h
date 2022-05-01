/*
 * Claws Mail -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 2001-2017 Hiroyuki Yamamoto and the Claws Mail team
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

#ifndef __CUSTOM_TOOLBAR_H__
#define __CUSTOM_TOOLBAR_H__

#include "gtk/gtkutils.h"

#define SEPARATOR_PIXMAP     "---"

typedef struct _Toolbar Toolbar;
typedef struct _ToolbarItem ToolbarItem;
typedef struct _ToolbarClawsActions ToolbarClawsActions;

typedef enum {
	TOOLBAR_MAIN = 0,
	TOOLBAR_COMPOSE,
	TOOLBAR_MSGVIEW
} ToolbarType;

#define NUM_TOOLBARS	3

typedef enum {
	COMPOSEBUTTON_MAIL,
	COMPOSEBUTTON_NEWS
} ComposeButtonType;

typedef enum {
	LEARN_SPAM,
	LEARN_HAM
} LearnButtonType;

struct _Toolbar {
	GtkWidget *toolbar;

	GtkWidget *folders_btn;
	GtkWidget *get_btn;
	GtkWidget *getall_btn;
	GtkWidget *send_btn;

	GtkWidget *compose_mail_btn;
	GtkWidget *compose_mail_icon;
	GtkWidget *compose_news_icon;

	GtkWidget *reply_btn;
	GtkWidget *replysender_btn;
	GtkWidget *replyall_btn;
	GtkWidget *replylist_btn;

	GtkWidget *fwd_btn;

	GtkWidget *trash_btn;
	GtkWidget *delete_btn;
	GtkWidget *delete_dup_btn;
	GtkWidget *prev_btn;
	GtkWidget *next_btn;
	GtkWidget *exec_btn;

	GtkWidget *separator;
	GtkWidget *learn_spam_btn;
	GtkWidget *learn_spam_icon;
	GtkWidget *learn_ham_icon;

	GtkWidget *cancel_inc_btn;
	GtkWidget *cancel_send_btn;
	GtkWidget *cancel_all_btn;

	ComposeButtonType compose_btn_type;
	LearnButtonType learn_btn_type;

	/* compose buttons */
	GtkWidget *sendl_btn;
	GtkWidget *draft_btn;
	GtkWidget *insert_btn;
	GtkWidget *attach_btn;
	GtkWidget *sig_btn;
	GtkWidget *repsig_btn;
	GtkWidget *exteditor_btn;
	GtkWidget *linewrap_current_btn;
	GtkWidget *linewrap_all_btn;
	GtkWidget *addrbook_btn;

	GtkWidget *open_mail_btn;
	GtkWidget *close_window_btn;

	GtkWidget *preferences_btn;

	GSList *action_list;
	GSList *item_list;

#ifdef USE_ENCHANT
	GtkWidget *spellcheck_btn;
#endif

	GtkWidget *privacy_sign_btn;
	GtkWidget *privacy_encrypt_btn;
};

struct _ToolbarItem {
	gint index;
	gchar *file;
	gchar *text;
	ToolbarType type;
	gpointer parent;
};

#define TOOLBAR_DESTROY_ITEMS(item_list) \
{ \
        ToolbarItem *item; \
	while (item_list != NULL) { \
		item = (ToolbarItem*)item_list->data; \
		item_list = g_slist_remove(item_list, item); \
		toolbar_item_destroy(item); \
	}\
	g_slist_free(item_list);\
}

#define TOOLBAR_DESTROY_ACTIONS(action_list) \
{ \
	ToolbarClawsActions *action; \
	while (action_list != NULL) { \
		action = (ToolbarClawsActions*)action_list->data;\
		action_list = \
			g_slist_remove(action_list, action);\
		if (action->name) \
			g_free(action->name); \
		g_free(action); \
	} \
	g_slist_free(action_list); \
}

/* enum holds available actions for both
   Compose Toolbar and Main Toolbar
*/
enum {
	/* main toolbar */
	A_RECEIVE_ALL = 0,
	A_RECEIVE_CUR,
	A_SEND_QUEUED,
	A_COMPOSE_EMAIL,
	A_COMPOSE_NEWS,
	A_REPLY_MESSAGE,
	A_REPLY_SENDER,
	A_REPLY_ALL,
	A_REPLY_ML,
	A_OPEN_MAIL,
	A_FORWARD,
	A_TRASH,
	A_DELETE_REAL,
	A_DELETE_DUP,
	A_EXECUTE,
	A_GOTO_PREV,
	A_GOTO_NEXT,

	A_IGNORE_THREAD,
	A_WATCH_THREAD,
	A_MARK,
	A_UNMARK,
	A_LOCK,
	A_UNLOCK,
	A_ALL_READ,
	A_ALL_UNREAD,
	A_READ,
	A_UNREAD,
	A_RUN_PROCESSING,

	A_PRINT,
	A_LEARN_SPAM,
	A_GO_FOLDERS,
	A_PREFERENCES,

	/* compose toolbar */
	A_SEND,
	A_SEND_LATER,
	A_DRAFT,
	A_INSERT,
	A_ATTACH,
	A_SIG,
	A_REP_SIG,
	A_EXTEDITOR,
	A_LINEWRAP_CURRENT,
	A_LINEWRAP_ALL,
	A_ADDRBOOK,
#ifdef USE_ENCHANT
	A_CHECK_SPELLING,
#endif
	A_PRIVACY_SIGN,
	A_PRIVACY_ENCRYPT,

	/* common items */
	A_CLAWS_ACTIONS,
	A_CANCEL_INC,
	A_CANCEL_SEND,
	A_CANCEL_ALL,
	A_CLOSE,

	A_SEPARATOR,

	A_CLAWS_PLUGINS,

	N_ACTION_VAL
};

struct _ToolbarClawsActions {
	GtkWidget *widget;
	gchar *name;
};

GList *toolbar_get_action_items(ToolbarType source);

void toolbar_save_config_file(ToolbarType source);
void toolbar_read_config_file(ToolbarType source);

void toolbar_set_default(ToolbarType source);
void toolbar_clear_list(ToolbarType source);

GSList *toolbar_get_list(ToolbarType source);
void toolbar_set_list_item(ToolbarItem *t_item, ToolbarType source);

gint toolbar_ret_val_from_descr(const gchar *descr);
gchar *toolbar_ret_descr_from_val(gint val);

void toolbar_main_set_sensitive(gpointer data);
void toolbar_comp_set_sensitive(gpointer data, gboolean sensitive);

/* invoked by mainwindow entries and toolbar actions */
void delete_msgview_cb(gpointer data, guint action, GtkWidget *widget);
void inc_mail_cb(gpointer data, guint action, GtkWidget *widget);
void inc_all_account_mail_cb(gpointer data, guint action, GtkWidget *widget);
void send_queue_cb(gpointer data, guint action, GtkWidget *widget);
void compose_mail_cb(gpointer data, guint action, GtkWidget *widget);
void compose_news_cb(gpointer data, guint action, GtkWidget *widget);
/* END */

void toolbar_toggle(guint action, gpointer data);
void toolbar_update(ToolbarType type, gpointer data);
Toolbar *toolbar_create(ToolbarType type, GtkWidget *container, gpointer data);
void toolbar_set_style(GtkWidget *toolbar_wid, GtkWidget *handlebox_wid, guint action);
void toolbar_destroy(Toolbar *toolbar);
void toolbar_item_destroy(ToolbarItem *toolbar_item);

void toolbar_set_learn_button(Toolbar *toolbar, LearnButtonType learn_btn_type);
const gchar *toolbar_get_short_text(int action);
int toolbar_get_icon(int action);
gboolean toolbar_check_action_btns(ToolbarType type);
#endif /* __CUSTOM_TOOLBAR_H__ */
