/*
 * Claws Mail -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 1999-2014 Hiroyuki Yamamoto and the Claws Mail team
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

#ifndef __QUOTE_FMT_H__

#define __QUOTE_FMT_H__

#ifdef USE_ENCHANT
#include "gtkaspell.h"
#endif

#define quote_fmt_parse	quote_fmtparse

void quote_fmt_quote_description(GtkWidget *widget, GtkWidget *pref_window);

gchar *quote_fmt_get_buffer(void);
GList *quote_fmt_get_attachments_list(void);
gint quote_fmt_get_line(void);
#ifdef USE_ENCHANT
void quote_fmt_init(MsgInfo *info, const gchar *my_quote_str, const gchar *my_body, gboolean my_dry_run, PrefsAccount *account, gboolean escaped_string, GtkAspell *gtkaspell);
#else
void quote_fmt_init(MsgInfo *info, const gchar *my_quote_str, const gchar *my_body, gboolean my_dry_run, PrefsAccount *account, gboolean escaped_string);
#endif
gint quote_fmtparse(void);
int quote_fmtlex_destroy(void);
void quote_fmt_scan_string(const gchar *str);
void quote_fmt_reset_vartable(void);
gint quote_fmt_get_cursor_pos(void);

void quotefmt_create_new_msg_fmt_widgets(GtkWindow *parent_window, GtkWidget *parent_box, GtkWidget **checkbtn_compose_with_format, GtkWidget **override_from_format, GtkWidget **edit_subject_format, GtkWidget **edit_body_format, gboolean add_info_button, void (*set_defaults_func)(void));
void quotefmt_create_reply_fmt_widgets(GtkWindow *parent_window, GtkWidget *parent_box, GtkWidget **checkbtn_reply_with_format, GtkWidget **override_from_format, GtkWidget **edit_reply_quotemark, GtkWidget **edit_reply_format, gboolean add_info_button, void (*set_defaults_func)(void));
void quotefmt_create_forward_fmt_widgets(GtkWindow *parent_window, GtkWidget *parent_box, GtkWidget **checkbtn_forward_with_format, GtkWidget **override_from_format, GtkWidget **edit_fw_quotemark, GtkWidget **edit_fw_format, gboolean add_info_button, void (*set_defaults_func)(void));
void quotefmt_add_info_button(GtkWindow *parent_window, GtkWidget *parent_box);
void quotefmt_add_defaults_button(GtkWindow *parent_window, GtkWidget *parent_box, void (*set_defaults_func)(void));

void quotefmt_check_new_msg_formats(gboolean use_format, gchar *override_from_fmt, gchar *subject_fmt, gchar *body_fmt);
void quotefmt_check_reply_formats(gboolean use_format, gchar *override_from_fmt, gchar *quotation_mark, gchar *body_fmt);
void quotefmt_check_forward_formats(gboolean use_format, gchar *override_from_fmt, gchar *quotation_mark, gchar *body_fmt);

#endif /* __QUOTE_FMT_H__ */
