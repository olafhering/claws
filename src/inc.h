/*
 * Sylpheed -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 1999-2012 Hiroyuki Yamamoto and the Claws Mail team
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

#ifndef __INC_H__
#define __INC_H__

#ifdef HAVE_CONFIG_H
#include "claws-features.h"
#endif

#include <glib.h>

#include "mainwindow.h"
#include "progressdialog.h"
#include "prefs_account.h"
#include "session.h"
#include "pop.h"

typedef struct _IncProgressDialog IncProgressDialog;
typedef struct _IncSession IncSession;

typedef enum {
	INC_SUCCESS,
	INC_CONNECT_ERROR,
	INC_AUTH_FAILED,
	INC_LOCKED,
	INC_ERROR,
	INC_NO_SPACE,
	INC_IO_ERROR,
	INC_SOCKET_ERROR,
	INC_EOF,
	INC_TIMEOUT,
	INC_CANCEL
} IncState;

struct _IncProgressDialog {
	ProgressDialog *dialog;

	MainWindow *mainwin;

	gboolean show_dialog;

	GDateTime *progress_tv;
	GDateTime *folder_tv;

	GList *queue_list; /* list of IncSession */
	gint cur_row;
};

struct _IncSession {
	Session *session;
	IncState inc_state;

	gint cur_total_bytes;

	gpointer data;
};

#define TIMEOUT_ITV	200

void inc_mail(MainWindow *mainwin, gboolean notify);
gint inc_account_mail(MainWindow *mainwin, PrefsAccount *account);

/* This function just blindly checks all accounts in the passed
 * account_list, and doesn't care about whether the configuration
 * says they should be checked or not. These checks should be done
 * by the caller, and account_list should look accordingly.
 * The caller is responsible for freeing the list afterwards. */
void inc_account_list_mail(MainWindow *mainwin, GList *list, /* linked list of PrefsAccount* pointers */
			   gboolean autocheck, gboolean notify);

/* This function is used by the global autocheck interval (autocheck TRUE),
 * or check at startup (check_at_startup TRUE)
 * or by the manual 'Receive all' feature (autocheck FALSE). It makes
 * sure correct list of accounts is marked for checking, based on
 * global and account configuration, and calls inc_account_list_mail(). */
void inc_all_account_mail(MainWindow *mainwin, gboolean autocheck, gboolean check_at_startup, gboolean notify);

void inc_progress_update(Pop3Session *session);

void inc_pop_before_smtp(PrefsAccount *acc);

gboolean inc_is_active(void);

void inc_cancel_all(void);

extern guint inc_lock_count;
#define inc_lock() {								\
	inc_lock_real();							\
	debug_print("called inc_lock (lock count %d)\n", inc_lock_count);	\
}

#define inc_unlock() {								\
	inc_unlock_real();							\
	debug_print("called inc_unlock (lock count %d)\n", inc_lock_count);	\
}

void inc_lock_real(void);
void inc_unlock_real(void);

void inc_autocheck_timer_init(MainWindow *mainwin);
void inc_autocheck_timer_set(void);
void inc_autocheck_timer_remove(void);
gboolean inc_offline_should_override(gboolean force_ask, const gchar *msg);

void inc_account_autocheck_timer_remove(PrefsAccount *account);
void inc_account_autocheck_timer_set_interval(PrefsAccount *account);

void inc_reset_offline_override_timers();

#endif /* __INC_H__ */
