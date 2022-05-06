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

#include "config.h"
#include "defs.h"

#include <glib.h>
#include <glib/gi18n.h>
#include <gdk/gdkkeysyms.h>
#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>

#include "sourcewindow.h"
#include "utils.h"
#include "gtkutils.h"
#include "prefs_common.h"
#include "file-utils.h"

static void source_window_size_alloc_cb(GtkWidget *widget, GtkAllocation *allocation);
static gint source_window_delete_cb(GtkWidget *widget, GdkEventAny *event, SourceWindow *sourcewin);
static gboolean key_pressed(GtkWidget *widget, GdkEventKey *event, SourceWindow *sourcewin);
static void source_window_append(SourceWindow *sourcewin, const gchar *str);
static void source_window_destroy(SourceWindow *sourcewin);

static void source_window_init()
{
}

SourceWindow *source_window_create(void)
{
	SourceWindow *sourcewin;
	GtkWidget *window;
	GtkWidget *scrolledwin;
	GtkWidget *text;
	static PangoFontDescription *font_desc;

	static GdkGeometry geometry;

	debug_print("Creating source window...\n");
	sourcewin = g_new0(SourceWindow, 1);

	window = gtkut_window_new(GTK_WINDOW_TOPLEVEL, "sourcewindow");
	gtk_window_set_title(GTK_WINDOW(window), _("Source of the message"));
	gtk_window_set_resizable(GTK_WINDOW(window), TRUE);
	gtk_window_set_type_hint(GTK_WINDOW(window), GDK_WINDOW_TYPE_HINT_DIALOG);
	gtk_widget_set_size_request(window, prefs_common.sourcewin_width, prefs_common.sourcewin_height);

	if (!geometry.min_height) {
		geometry.min_width = 400;
		geometry.min_height = 320;
	}
	gtk_window_set_geometry_hints(GTK_WINDOW(window), NULL, &geometry, GDK_HINT_MIN_SIZE);

	g_signal_connect(G_OBJECT(window), "size_allocate", G_CALLBACK(source_window_size_alloc_cb), sourcewin);
	g_signal_connect(G_OBJECT(window), "delete_event", G_CALLBACK(source_window_delete_cb), sourcewin);
	g_signal_connect(G_OBJECT(window), "key_press_event", G_CALLBACK(key_pressed), sourcewin);
	gtk_widget_realize(window);

	scrolledwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwin), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwin), GTK_SHADOW_IN);
	gtk_container_add(GTK_CONTAINER(window), scrolledwin);
	gtk_widget_show(scrolledwin);

	text = gtk_text_view_new();
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text), GTK_WRAP_WORD_CHAR);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(text), FALSE);
	if (!font_desc && prefs_common.textfont)
		font_desc = pango_font_description_from_string(prefs_common.textfont);
	if (font_desc)
		gtk_widget_modify_font(text, font_desc);
	gtk_container_add(GTK_CONTAINER(scrolledwin), text);
	gtk_widget_show(text);

	sourcewin->window = window;
	sourcewin->scrolledwin = scrolledwin;
	sourcewin->text = text;

	source_window_init();

	return sourcewin;
}

void source_window_show(SourceWindow *sourcewin)
{
	gtk_widget_show_all(sourcewin->window);
}

static void source_window_destroy(SourceWindow *sourcewin)
{
	if (sourcewin->updating) {
		debug_print("deferring destroy\n");
		sourcewin->deferred_destroy = TRUE;
		return;
	}
	gtk_widget_destroy(sourcewin->window);
	g_free(sourcewin);
}

void source_window_show_msg(SourceWindow *sourcewin, MsgInfo *msginfo)
{
	gchar *file;
	gchar *title;
	FILE *fp;
	gchar buf[BUFFSIZE];

	cm_return_if_fail(msginfo != NULL);

	sourcewin->updating = TRUE;
	file = procmsg_get_message_file(msginfo);
	sourcewin->updating = FALSE;

	if (sourcewin->deferred_destroy) {
		g_free(file);
		source_window_destroy(sourcewin);
		return;
	}

	cm_return_if_fail(file != NULL);

	if ((fp = claws_fopen(file, "rb")) == NULL) {
		FILE_OP_ERROR(file, "claws_fopen");
		g_free(file);
		return;
	}

	debug_print("Displaying the source of %s ...\n", file);

	title = g_strdup_printf(_("%s - Source"), file);
	gtk_window_set_title(GTK_WINDOW(sourcewin->window), title);
	g_free(title);
	g_free(file);

	while (claws_fgets(buf, sizeof(buf), fp) != NULL)
		source_window_append(sourcewin, buf);

	claws_fclose(fp);
}

static void source_window_append(SourceWindow *sourcewin, const gchar *str)
{
	GtkTextView *text = GTK_TEXT_VIEW(sourcewin->text);
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(text);
	GtkTextIter iter;
	gchar *out;
	gint len;

	len = strlen(str) + 1;
	Xalloca(out, len, return);
	conv_utf8todisp(out, len, str);

	gtk_text_buffer_get_iter_at_offset(buffer, &iter, -1);
	gtk_text_buffer_insert(buffer, &iter, out, -1);
}

static void source_window_size_alloc_cb(GtkWidget *widget, GtkAllocation *allocation)
{
	cm_return_if_fail(allocation != NULL);

	prefs_common.sourcewin_width = allocation->width;
	prefs_common.sourcewin_height = allocation->height;
}

static gint source_window_delete_cb(GtkWidget *widget, GdkEventAny *event, SourceWindow *sourcewin)
{
	source_window_destroy(sourcewin);
	return TRUE;
}

static gboolean key_pressed(GtkWidget *widget, GdkEventKey *event, SourceWindow *sourcewin)
{
	if (!event || !sourcewin)
		return FALSE;

	switch (event->keyval) {
	case GDK_KEY_W:
	case GDK_KEY_w:
		if ((event->state & GDK_CONTROL_MASK) != 0)
			gtk_widget_destroy(sourcewin->window);
		break;
	case GDK_KEY_Escape:
		source_window_destroy(sourcewin);
		return TRUE;
		break;
	}

	return FALSE;
}
/*
 * vim: noet ts=4 shiftwidth=4
 */
