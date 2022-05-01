/*
 * Claws Mail -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 1999-2021 the Claws Mail team and Colin Leroy
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

#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <gdk/gdkkeysyms.h>
#include <sys/types.h>
#include <dirent.h>

#include "manage_window.h"
#include "utils.h"
#include "mainwindow.h"
#include "gtkutils.h"
#include "alertpanel.h"
#include "textview.h"
#include "mimeview.h"
#include "prefs_common.h"
#include "menu.h"

enum {
	URI_OPENER_URL,
	URI_OPENER_DATA,
	N_URI_OPENER_COLUMNS
};

static struct URIOpener {
	GtkWidget *window;
	GtkWidget *hbox_scroll;
	GtkWidget *hbox1;
	GtkWidget *vbox1;
	GtkWidget *label;
	GtkWidget *urilist;
	GtkWidget *scrolledwin;
	GtkWidget *open_btn;
	GtkWidget *close_btn;
	MessageView *msgview;
	GSList *uris;
} opener;

static void uri_opener_list_copy_cb(gpointer action, gpointer data);

static GtkActionGroup *uri_opener_popup_action = NULL;
static GtkWidget *uri_opener_popup_menu = NULL;

static GtkActionEntry uri_opener_popup_entries[] = {
	{"UriOpenerPopup", NULL, "UriOpenerPopup", NULL, NULL, NULL},
	{"UriOpenerPopup/Copy", NULL, N_("C_opy URL"), NULL, NULL, G_CALLBACK(uri_opener_list_copy_cb)}
};

static void uri_opener_load_uris(void);
static void uri_opener_open_cb(GtkWidget *widget, gpointer data);
static void uri_opener_close_cb(GtkWidget *widget, gpointer data);
static void uri_opener_select_all_cb(GtkWidget *widget, gpointer data);
static gboolean key_pressed(GtkWidget *widget, GdkEventKey *event, gpointer data);
static void uri_opener_double_clicked(GtkTreeView *list_view, GtkTreePath *path, GtkTreeViewColumn *column, gpointer data);
static void uri_opener_create(void);
static gint uri_opener_list_btn_pressed(GtkWidget *widget, GdkEventButton *event, GtkTreeView *list_view);
static gboolean uri_opener_list_popup_menu(GtkWidget *widget, gpointer data);

void uri_opener_open(MessageView *msgview, GSList *uris)
{
	cm_return_if_fail(msgview);
	cm_return_if_fail(msgview->mimeview);
	cm_return_if_fail(msgview->mimeview->textview);

	if (!opener.window)
		uri_opener_create();

	manage_window_set_transient(GTK_WINDOW(opener.window));
	gtk_widget_grab_focus(opener.close_btn);

	if (uris == NULL) {
		alertpanel_notice(_("There are no URLs in this email."));
		return;
	}

	opener.msgview = msgview;
	opener.uris = g_slist_copy(uris);
	uri_opener_load_uris();

	gtk_widget_show(opener.window);
	gtk_widget_grab_focus(opener.urilist);
	gtk_window_set_modal(GTK_WINDOW(opener.window), TRUE);
}

static GtkListStore *uri_opener_create_data_store(void)
{
	return gtk_list_store_new(N_URI_OPENER_COLUMNS, G_TYPE_STRING, G_TYPE_POINTER, -1);
}

static void uri_opener_create_list_view_columns(GtkWidget *list_view)
{
	GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes(_("Included URLs:"), renderer, "markup", URI_OPENER_URL, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_view), column);
}

static GtkWidget *uri_opener_list_view_create(void)
{
	GtkTreeView *list_view;
	GtkTreeSelection *selector;
	GtkTreeModel *model;

	model = GTK_TREE_MODEL(uri_opener_create_data_store());
	list_view = GTK_TREE_VIEW(gtk_tree_view_new_with_model(model));
	g_object_unref(model);

	gtk_tree_view_set_rules_hint(list_view, prefs_common.use_stripes_everywhere);

	selector = gtk_tree_view_get_selection(list_view);
	gtk_tree_selection_set_mode(selector, GTK_SELECTION_MULTIPLE);

	g_signal_connect(G_OBJECT(list_view), "row_activated", G_CALLBACK(uri_opener_double_clicked), list_view);
	g_signal_connect(G_OBJECT(list_view), "popup-menu", G_CALLBACK(uri_opener_list_popup_menu), list_view);
	g_signal_connect(G_OBJECT(list_view), "button-press-event", G_CALLBACK(uri_opener_list_btn_pressed), list_view);

	/* create the columns */
	uri_opener_create_list_view_columns(GTK_WIDGET(list_view));

	return GTK_WIDGET(list_view);

}

static GtkWidget *uri_opener_scrolled_win_create(void)
{
	GtkWidget *scrolledwin;

	scrolledwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwin), GTK_SHADOW_ETCHED_IN);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwin), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

	gtk_widget_set_size_request(scrolledwin, 200, 250);
	gtk_widget_show(scrolledwin);

	return scrolledwin;
}

static void uri_opener_size_allocate_cb(GtkWidget *widget, GtkAllocation *allocation)
{
	cm_return_if_fail(allocation != NULL);

	prefs_common.uriopenerwin_width = allocation->width;
	prefs_common.uriopenerwin_height = allocation->height;
}

static void uri_opener_create(void)
{
	GtkWidget *window;
	GtkWidget *hbox_scroll;
	GtkWidget *hbox;
	GtkWidget *hbox1;
	GtkWidget *vbox1;
	GtkWidget *label;
	GtkWidget *urilist;
	GtkWidget *select_all_btn;
	GtkWidget *open_btn;
	GtkWidget *close_btn;
	GtkWidget *scrolledwin;
	static GdkGeometry geometry;

	window = gtkut_window_new(GTK_WINDOW_TOPLEVEL, "uri_opener");
	gtk_window_set_title(GTK_WINDOW(window), C_("Dialog title", "Open URLs"));

	gtk_container_set_border_width(GTK_CONTAINER(window), 8);
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
	gtk_window_set_resizable(GTK_WINDOW(window), TRUE);
	gtk_window_set_type_hint(GTK_WINDOW(window), GDK_WINDOW_TYPE_HINT_DIALOG);
	g_signal_connect(G_OBJECT(window), "delete_event", G_CALLBACK(uri_opener_close_cb), NULL);
	g_signal_connect(G_OBJECT(window), "size_allocate", G_CALLBACK(uri_opener_size_allocate_cb), NULL);
	g_signal_connect(G_OBJECT(window), "key_press_event", G_CALLBACK(key_pressed), NULL);
	MANAGE_WINDOW_SIGNALS_CONNECT(window);

	vbox1 = gtk_vbox_new(FALSE, 6);
	gtkut_stock_button_set_create(&hbox1, &open_btn, GTK_STOCK_OPEN, &close_btn, GTK_STOCK_CLOSE, NULL, NULL);

	g_signal_connect(G_OBJECT(open_btn), "clicked", G_CALLBACK(uri_opener_open_cb), NULL);

	g_signal_connect(G_OBJECT(close_btn), "clicked", G_CALLBACK(uri_opener_close_cb), NULL);

	urilist = uri_opener_list_view_create();

	label = gtk_label_new(_("Any phishing URLs are shown in red, followed by the actual URL."));
	gtk_misc_set_alignment(GTK_MISC(label), 0, 0.5);
	gtk_box_pack_start(GTK_BOX(vbox1), label, FALSE, TRUE, 0);

	scrolledwin = uri_opener_scrolled_win_create();
	hbox_scroll = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(hbox_scroll), scrolledwin, TRUE, TRUE, 0);

	select_all_btn = gtk_button_new_with_label(_("Select All"));
	g_signal_connect(G_OBJECT(select_all_btn), "clicked", G_CALLBACK(uri_opener_select_all_cb), NULL);

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), select_all_btn, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), gtk_label_new(""), TRUE, TRUE, 0);

	gtk_container_add(GTK_CONTAINER(scrolledwin), urilist);
	gtk_box_pack_start(GTK_BOX(vbox1), hbox_scroll, TRUE, TRUE, 0);
	gtk_box_pack_start(GTK_BOX(vbox1), hbox, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox1), hbox1, FALSE, FALSE, 0);

	gtk_widget_show_all(vbox1);
	gtk_container_add(GTK_CONTAINER(window), vbox1);

	if (!geometry.min_height) {
		geometry.min_width = 450;
		geometry.min_height = 300;
	}

	gtk_window_set_geometry_hints(GTK_WINDOW(window), NULL, &geometry, GDK_HINT_MIN_SIZE);
	gtk_widget_set_size_request(window, prefs_common.uriopenerwin_width, prefs_common.uriopenerwin_height);

	opener.window = window;
	opener.hbox_scroll = hbox_scroll;
	opener.hbox1 = hbox1;
	opener.vbox1 = vbox1;
	opener.label = label;
	opener.urilist = urilist;
	opener.scrolledwin = scrolledwin;
	opener.open_btn = open_btn;
	opener.close_btn = close_btn;

}

static void uri_opener_list_view_insert_uri(GtkWidget *list_view, GtkTreeIter *row_iter, ClickableText *uri)
{
	GtkTreeIter iter;
	GtkListStore *list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list_view)));
	gchar *visible = textview_get_visible_uri(opener.msgview->mimeview->textview, uri);

	gchar *label = NULL;

	if (visible && strcmp(visible, uri->uri)) {
		gboolean phishing_attempt = FALSE;
		if (strcmp(visible, uri->uri) != 0 && is_uri_string(visible)) {
			gchar *uri_path;
			gchar *visible_uri_path;

			uri_path = get_uri_path(uri->uri);
			visible_uri_path = get_uri_path(visible);
			if (path_cmp(uri_path, visible_uri_path) != 0)
				phishing_attempt = TRUE;
		}
		if (phishing_attempt) {
			gchar buf[8];

			g_snprintf(buf, sizeof buf, "#%6.6lx", prefs_common.color[COL_LOG_ERROR]);
			label = g_markup_printf_escaped("<span color=\"%s\"><b>%s</b></span>\n%s", buf, visible, uri->uri);
		} else
			label = g_markup_printf_escaped("%s", uri->uri);
	} else
		label = g_markup_printf_escaped("%s", uri->uri);

	if (row_iter == NULL) {
		/* append new */
		gtk_list_store_append(list_store, &iter);
		gtk_list_store_set(list_store, &iter, URI_OPENER_URL, label, URI_OPENER_DATA, uri, -1);
	} else {
		gtk_list_store_set(list_store, row_iter, URI_OPENER_URL, label, URI_OPENER_DATA, uri, -1);
	}
	g_free(visible);
	g_free(label);
}

static void uri_opener_list_view_clear_uris(GtkWidget *list_view)
{
	GtkListStore *list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list_view)));
	gtk_list_store_clear(list_store);
}

static void uri_opener_load_uris(void)
{
	GSList *cur = opener.uris;
	GtkTreeModel *model;
	GtkTreeSelection *selection;
	GtkTreeIter iter;

	uri_opener_list_view_clear_uris(opener.urilist);
	for (; cur; cur = cur->next) {
		ClickableText *uri = (ClickableText *)cur->data;
		uri_opener_list_view_insert_uri(opener.urilist, NULL, uri);
	}

	g_object_ref(opener.urilist);
	gtk_container_remove(GTK_CONTAINER(opener.scrolledwin), opener.urilist);
	gtk_widget_destroy(opener.scrolledwin);

	opener.scrolledwin = uri_opener_scrolled_win_create();
	gtk_container_add(GTK_CONTAINER(opener.scrolledwin), opener.urilist);
	gtk_box_pack_start(GTK_BOX(opener.hbox_scroll), opener.scrolledwin, TRUE, TRUE, 0);
	g_object_unref(opener.urilist);

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(opener.urilist));
	if (!gtk_tree_model_get_iter_first(model, &iter))
		return;
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(opener.urilist));
	gtk_tree_selection_select_iter(selection, &iter);
}

static void uri_opener_close(void)
{
	g_slist_free(opener.uris);
	opener.uris = NULL;
	gtk_window_set_modal(GTK_WINDOW(opener.window), FALSE);
	gtk_widget_hide(opener.window);
}

static void uri_opener_close_cb(GtkWidget *widget, gpointer data)
{
	uri_opener_close();
}

static gboolean key_pressed(GtkWidget *widget, GdkEventKey *event, gpointer data)
{
	if (event) {
		if (event->keyval == GDK_KEY_Escape)
			uri_opener_close();

		if ((event->keyval == GDK_KEY_c || event->keyval == GDK_KEY_x) && (event->state & GDK_CONTROL_MASK)) {
			uri_opener_list_copy_cb(NULL, NULL);
			return TRUE;
		}
	}

	return FALSE;
}

static void uri_opener_double_clicked(GtkTreeView *list_view, GtkTreePath *path, GtkTreeViewColumn *column, gpointer data)
{
	ClickableText *uri;
	GtkTreeIter iter;
	GtkTreeModel *model = gtk_tree_view_get_model(list_view);

	if (!gtk_tree_model_get_iter(model, &iter, path))
		return;

	gtk_tree_model_get(model, &iter, URI_OPENER_DATA, &uri, -1);

	if (!uri)
		return;

	if (textview_uri_security_check(opener.msgview->mimeview->textview, uri, FALSE) == TRUE)
		open_uri(uri->uri, prefs_common_get_uri_cmd());
}

static void uri_opener_open_cb(GtkWidget *widget, gpointer data)
{
	ClickableText *uri;
	GtkTreeIter sel;
	GtkTreeModel *model;
	GtkTreeSelection *selection;
	GList *selected, *cur;

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(opener.urilist));
	selected = gtk_tree_selection_get_selected_rows(selection, &model);
	cm_return_if_fail(selected);

	for (cur = selected; cur != NULL; cur = g_list_next(cur)) {
		if (!gtk_tree_model_get_iter(model, &sel, (GtkTreePath *)cur->data))
			continue;

		gtk_tree_model_get(model, &sel, URI_OPENER_DATA, &uri, -1);
		if (!uri)
			continue;

		if (textview_uri_security_check(opener.msgview->mimeview->textview, uri, FALSE) == TRUE)
			open_uri(uri->uri, prefs_common_get_uri_cmd());
	}

	g_list_foreach(selected, (GFunc) gtk_tree_path_free, NULL);
	g_list_free(selected);
}

static void uri_opener_select_all_cb(GtkWidget *widget, gpointer data)
{
	GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(opener.urilist));
	gtk_tree_selection_select_all(selection);
}

static void uri_opener_list_copy_cb(gpointer action, gpointer data)
{
	ClickableText *uri;
	GtkTreeIter sel;
	GtkTreeModel *model;
	GtkTreeSelection *selection;
	GList *selected, *cur;
	GString *uri_list_str = NULL;

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(opener.urilist));
	selected = gtk_tree_selection_get_selected_rows(selection, &model);
	cm_return_if_fail(selected);

	for (cur = selected; cur != NULL; cur = g_list_next(cur)) {
		if (!gtk_tree_model_get_iter(model, &sel, (GtkTreePath *)cur->data))
			continue;

		gtk_tree_model_get(model, &sel, URI_OPENER_DATA, &uri, -1);
		if (!uri)
			continue;

		if (!uri_list_str)
			uri_list_str = g_string_new((const gchar *)uri->uri);
		else
			g_string_append_printf(uri_list_str, "\n%s", uri->uri);
	}
	if (uri_list_str) {
		GtkClipboard *clip, *clip2;

		if (textview_uri_security_check(opener.msgview->mimeview->textview, uri, TRUE) == TRUE) {
			clip = gtk_widget_get_clipboard(opener.window, GDK_SELECTION_PRIMARY);
			clip2 = gtk_widget_get_clipboard(opener.window, GDK_SELECTION_CLIPBOARD);
			gtk_clipboard_set_text(clip, uri_list_str->str, uri_list_str->len);
			gtk_clipboard_set_text(clip2, uri_list_str->str, uri_list_str->len);
		}
		g_string_free(uri_list_str, TRUE);
	}

	g_list_foreach(selected, (GFunc) gtk_tree_path_free, NULL);
	g_list_free(selected);
}

static gint uri_opener_list_btn_pressed(GtkWidget *widget, GdkEventButton *event, GtkTreeView *list_view)
{
	if (event) {
		/* right-button click */
		if (event->button == 3) {
			GtkTreeModel *model = gtk_tree_view_get_model(list_view);
			GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list_view));
			GList *selected = gtk_tree_selection_get_selected_rows(selection, &model);

			if (!uri_opener_popup_menu) {
				uri_opener_popup_action = cm_menu_create_action_group("UriOpenerPopup", uri_opener_popup_entries, G_N_ELEMENTS(uri_opener_popup_entries), (gpointer)list_view);
				MENUITEM_ADDUI("/Menus", "UriOpenerPopup", "UriOpenerPopup", GTK_UI_MANAGER_MENU)
				    MENUITEM_ADDUI("/Menus/UriOpenerPopup", "Copy", "UriOpenerPopup/Copy", GTK_UI_MANAGER_MENUITEM)
				    uri_opener_popup_menu = gtk_menu_item_get_submenu(GTK_MENU_ITEM(gtk_ui_manager_get_widget(gtkut_ui_manager(), "/Menus/UriOpenerPopup")));
			}

			/* grey out some popup menu item if there is no selected row */
			cm_menu_set_sensitive("UriOpenerPopup/Copy", (selected != NULL));

			gtk_menu_popup(GTK_MENU(uri_opener_popup_menu), NULL, NULL, NULL, NULL, event->button, event->time);
		}
	}
	return FALSE;
}

static gboolean uri_opener_list_popup_menu(GtkWidget *widget, gpointer data)
{
	GtkTreeView *list_view = (GtkTreeView *)data;
	GdkEventButton event;

	event.button = 3;
	event.time = gtk_get_current_event_time();

	uri_opener_list_btn_pressed(NULL, &event, list_view);

	return TRUE;
}
/*
 * vim: noet ts=4 shiftwidth=4 nowrap
 */
