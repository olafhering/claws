/*
 * Claws Mail -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 1999-2004 Hiroyuki Yamamoto
 * This file (C) 2005 Andrej Kacian <andrej@kacian.sk>
 *
 * - Dialog which appears when manually subscribing a new feed.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Global includes */
#include <glib/gi18n.h>
#include <gtk/gtk.h>

/* Claws Mail includes */
#include <mainwindow.h>

/* Local includes */
#include "libfeed/feed.h"
#include "rssyl_subscribe_gtk.h"

void rssyl_subscribe_dialog(RSubCtx *ctx)
{
	GtkWidget *win, *vbox, *title, *titleframe, *titlelabel, *editprops;
	gint ret;
	gchar *newtitle;

	g_return_if_fail(ctx != NULL);
	g_return_if_fail(ctx->feed != NULL);

	/* Create window */
	win = gtk_dialog_new_with_buttons(_("Subscribe new feed?"), GTK_WINDOW(mainwindow_get_mainwindow()->window), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT, GTK_STOCK_OK, GTK_RESPONSE_ACCEPT, NULL);
	gtk_dialog_set_default_response(GTK_DIALOG(win), GTK_RESPONSE_ACCEPT);

	vbox = gtk_dialog_get_content_area(GTK_DIALOG(win));

	/* Feed title */
	titleframe = gtk_frame_new(NULL);
	gtk_container_set_border_width(GTK_CONTAINER(titleframe), 5);
	gtk_frame_set_label_align(GTK_FRAME(titleframe), 0.05, 0.5);
	gtk_frame_set_shadow_type(GTK_FRAME(titleframe), GTK_SHADOW_ETCHED_OUT);
	gtk_box_pack_start(GTK_BOX(vbox), titleframe, FALSE, FALSE, 0);

	titlelabel = gtk_label_new(g_strconcat("<b>", _("Feed folder:"), "</b>", NULL));
	gtk_label_set_use_markup(GTK_LABEL(titlelabel), TRUE);
	gtk_misc_set_padding(GTK_MISC(titlelabel), 5, 0);
	gtk_frame_set_label_widget(GTK_FRAME(titleframe), titlelabel);

	title = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(title), feed_get_title(ctx->feed));
	gtk_entry_set_activates_default(GTK_ENTRY(title), TRUE);
	gtk_widget_set_tooltip_text(title, _("Instead of using official title, you can enter a different folder " "name for the feed."));
	gtk_container_add(GTK_CONTAINER(titleframe), title);

	editprops = gtk_check_button_new_with_mnemonic(_("_Edit feed properties after subscribing"));
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(editprops), FALSE);
	gtk_box_pack_start(GTK_BOX(vbox), editprops, FALSE, FALSE, 0);

	gtk_widget_show_all(vbox);

	ret = gtk_dialog_run(GTK_DIALOG(win));

	if (ret == GTK_RESPONSE_ACCEPT) {
		/* Modify ctx->feed based on user changes in dialog */
		newtitle = (gchar *)gtk_entry_get_text(GTK_ENTRY(title));
		if (strcmp(feed_get_title(ctx->feed), newtitle)) {
			debug_print("RSSyl: Using user-supplied feed title '%s', instead of '%s'\n", newtitle, feed_get_title(ctx->feed));
			ctx->official_title = g_strdup(feed_get_title(ctx->feed));
			feed_set_title(ctx->feed, newtitle);
		}
		ctx->edit_properties = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(editprops));
	} else {
		/* Destroy the feed to signal outside that user cancelled subscribing */
		feed_free(ctx->feed);
		ctx->feed = NULL;
	}

	gtk_widget_destroy(win);
}
/*
 * vim: noet ts=4 shiftwidth=4 nowrap
 */
