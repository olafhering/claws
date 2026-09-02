/*
 * Claws Mail -- a GTK based, lightweight, and fast e-mail client
 * Copyright (C) 1999-2026 Michael Rasmussen and the Claws Mail Team
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

#include <glib.h>
#include <glib/gi18n.h>

#include "defs.h"

#include <gtk/gtk.h>

#include "gtkutils.h"
#include "combobox.h"
#include "prefs.h"
#include "prefs_gtk.h"
#include "prefswindow.h"
#include "alertpanel.h"
#include "utils.h"
#include "filesel.h"

#include "archiver_prefs.h"
#include "libarchive_archive.h"

#define PREFS_BLOCK_NAME "Archiver"

ArchiverPrefs archiver_prefs;

struct ArchiverPrefsPage {
        PrefsPage page;
        GtkWidget *save_folder;
	GtkWidget *compression_combo;
	GtkWidget *format_combo;
	GtkWidget *recursive_chkbtn;
	GtkWidget *md5sum_chkbtn;
	GtkWidget *rename_chkbtn;
        GtkWidget *unlink_chkbtn;
};

struct ArchiverPrefsPage archiver_prefs_page;

static void create_archiver_prefs_page			(PrefsPage *page,
				      			 GtkWindow *window,
				      			 gpointer   data);
static void destroy_archiver_prefs_page			(PrefsPage *page);
static void save_archiver_prefs				(PrefsPage *page);

static PrefParam param[] = {
	{"save_folder", NULL, &archiver_prefs.save_folder, P_STRING, NULL, NULL, NULL},
	{"compression", "0", &archiver_prefs.compression, P_ENUM, NULL, NULL, NULL},
	{"format", "0", &archiver_prefs.format, P_ENUM, NULL, NULL, NULL},
	{"recursive", "TRUE", &archiver_prefs.recursive, P_BOOL, NULL, NULL, NULL},
	{"md5sum",  "FALSE", &archiver_prefs.md5sum, P_BOOL, NULL, NULL, NULL},
	{"rename", "FALSE", &archiver_prefs.rename, P_BOOL, NULL, NULL, NULL},
	{"unlink", "FALSE", &archiver_prefs.unlink, P_BOOL, NULL, NULL, NULL},

	{NULL, NULL, NULL, P_OTHER, NULL, NULL, NULL}
};

void archiver_prefs_init(void)
{
	static gchar *path[3];
	gchar *rcpath;

	path[0] = _("Plugins");
	path[1] = _("Mail Archiver");
	path[2] = NULL;

        prefs_set_default(param);
	rcpath = g_strconcat(get_rc_dir(), G_DIR_SEPARATOR_S, COMMON_RC, NULL);
        prefs_read_config(param, PREFS_BLOCK_NAME, rcpath, NULL);
	g_free(rcpath);
        
        archiver_prefs_page.page.path = path;
        archiver_prefs_page.page.create_widget = create_archiver_prefs_page;
        archiver_prefs_page.page.destroy_widget = destroy_archiver_prefs_page;
        archiver_prefs_page.page.save_page = save_archiver_prefs;
	archiver_prefs_page.page.weight = 30.0;
        
        prefs_gtk_register_page((PrefsPage *) &archiver_prefs_page);
}

void archiver_prefs_done(void)
{
        prefs_gtk_unregister_page((PrefsPage *) &archiver_prefs_page);
}

static void foldersel_cb(GtkWidget *widget, gpointer data)
{
	struct ArchiverPrefsPage *page = (struct ArchiverPrefsPage *) data;
	gchar *startdir = NULL;
	gchar *dirname;
	gchar *tmp;
	
	if (archiver_prefs.save_folder && *archiver_prefs.save_folder)
		startdir = g_strconcat(archiver_prefs.save_folder,
				       G_DIR_SEPARATOR_S, NULL);
	else
		startdir = g_strdup(get_home_dir());

	dirname = filesel_select_file_save_folder(_("Select destination folder"), startdir);
	if (!dirname) {
		g_free(startdir);
		return;
	}
	if (!is_dir_exist(dirname)) {
		alertpanel_error(_("'%s' is not a directory."),dirname);
		g_free(dirname);
		g_free(startdir);
		return;
	}
	if (dirname[strlen(dirname)-1] == G_DIR_SEPARATOR)
		dirname[strlen(dirname)-1] = '\0';
	g_free(startdir);

	tmp =  g_filename_to_utf8(dirname,-1, NULL, NULL, NULL);
	gtk_entry_set_text(GTK_ENTRY(page->save_folder), tmp);

	g_free(dirname);
	g_free(tmp);
}

static void create_archiver_prefs_page(PrefsPage * _page,
				       GtkWindow *window,
                                       gpointer data)
{
	struct ArchiverPrefsPage *page = (struct ArchiverPrefsPage *) _page;
        GtkWidget *vbox1, *vbox2;
	GtkWidget *hbox1;
	GtkWidget *save_folder_label;
  	GtkWidget *save_folder;
  	GtkWidget *save_folder_select;
	GtkWidget *frame;
	GtkWidget *compression_combo;
	GtkWidget *format_combo;
	GtkListStore *menu;
	GtkTreeIter iter;
	GtkWidget *recursive_chkbtn;
	GtkWidget *md5sum_chkbtn;
	GtkWidget *rename_chkbtn;
        GtkWidget *unlink_chkbtn;

	vbox1 = gtk_box_new(GTK_ORIENTATION_VERTICAL, VSPACING);
	gtk_widget_show (vbox1);
	gtk_container_set_border_width (GTK_CONTAINER (vbox1), VBOX_BORDER);

	vbox2 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	gtk_widget_show (vbox2);
	gtk_box_pack_start (GTK_BOX (vbox1), vbox2, FALSE, FALSE, 0);

  	hbox1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
	gtk_widget_show (hbox1);
	gtk_box_pack_start (GTK_BOX (vbox2), hbox1, FALSE, FALSE, 0);

 	save_folder_label = gtk_label_new(_("Default save folder"));
	gtk_widget_show (save_folder_label);
	gtk_box_pack_start (GTK_BOX (hbox1), save_folder_label, FALSE, FALSE, 0);

  	save_folder = gtk_entry_new ();
	gtk_widget_show (save_folder);
	gtk_box_pack_start (GTK_BOX (hbox1), save_folder, TRUE, TRUE, 0);

	save_folder_select = gtkut_get_browse_directory_btn(_("_Select"));
	gtk_widget_show (save_folder_select);
  	gtk_box_pack_start (GTK_BOX (hbox1), save_folder_select, FALSE, FALSE, 0);
	CLAWS_SET_TIP(save_folder_select,
			     _("Click this button to select the default location for saving archives"));

	g_signal_connect(G_OBJECT(save_folder_select), "clicked", 
			 G_CALLBACK(foldersel_cb), page);

	if (archiver_prefs.save_folder != NULL)
		gtk_entry_set_text(GTK_ENTRY(save_folder),
				   archiver_prefs.save_folder);

	PACK_FRAME (vbox1, frame, _("Default compression"));

	hbox1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
	gtk_widget_show(hbox1);
	gtk_container_set_border_width(GTK_CONTAINER(hbox1), 4);
	gtk_container_add(GTK_CONTAINER(frame), hbox1);

	compression_combo = gtkut_sc_combobox_create(NULL, FALSE);
	menu = GTK_LIST_STORE(gtk_combo_box_get_model(GTK_COMBO_BOX(compression_combo)));
	COMBOBOX_ADD(menu, "GZIP", COMPRESSION_GZIP);
	COMBOBOX_ADD(menu, "BZIP2", COMPRESSION_BZIP);
	COMBOBOX_ADD(menu, "COMPRESS", COMPRESSION_COMPRESS);
#if ARCHIVE_VERSION_NUMBER >= 2006990
	COMBOBOX_ADD(menu, "LZMA", COMPRESSION_LZMA);
	COMBOBOX_ADD(menu, "XZ", COMPRESSION_XZ);
#endif
#if ARCHIVE_VERSION_NUMBER >= 3000000
	COMBOBOX_ADD(menu, "LZIP", COMPRESSION_LZIP);
#endif
#if ARCHIVE_VERSION_NUMBER >= 3001000
	COMBOBOX_ADD(menu, "LRZIP", COMPRESSION_LRZIP);
	COMBOBOX_ADD(menu, "LZOP", COMPRESSION_LZOP);
	COMBOBOX_ADD(menu, "GRZIP", COMPRESSION_GRZIP);
#endif
#if ARCHIVE_VERSION_NUMBER >= 3001900
	COMBOBOX_ADD(menu, "LZ4", COMPRESSION_LZ4);
#endif
#if ARCHIVE_VERSION_NUMBER >= 3004000
	COMBOBOX_ADD(menu, "ZSTD", COMPRESSION_ZSTD);
#endif
	COMBOBOX_ADD(menu, _("None"), COMPRESSION_NONE);
	gtk_widget_show(compression_combo);
	gtk_box_pack_start(GTK_BOX (hbox1), compression_combo, FALSE, FALSE, 0);
	CLAWS_SET_TIP(compression_combo,
		      _("Choose the default compression method"));
	combobox_select_by_data(GTK_COMBO_BOX(compression_combo),
				archiver_prefs.compression);

	PACK_FRAME (vbox1, frame, _("Default format"));

	hbox1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
	gtk_widget_show(hbox1);
	gtk_container_set_border_width(GTK_CONTAINER(hbox1), 4);
	gtk_container_add(GTK_CONTAINER(frame), hbox1);

	format_combo = gtkut_sc_combobox_create(NULL, FALSE);
	menu = GTK_LIST_STORE(gtk_combo_box_get_model(GTK_COMBO_BOX(format_combo)));
	COMBOBOX_ADD(menu, "TAR", FORMAT_TAR);
	COMBOBOX_ADD(menu, "SHAR", FORMAT_SHAR);
	COMBOBOX_ADD(menu, "CPIO", FORMAT_CPIO);
	COMBOBOX_ADD(menu, "PAX", FORMAT_PAX);
	gtk_widget_show(format_combo);
	gtk_box_pack_start(GTK_BOX (hbox1), format_combo, FALSE, FALSE, 0);
	CLAWS_SET_TIP(format_combo,
		      _("Choose the default archive format"));
	combobox_select_by_data(GTK_COMBO_BOX(format_combo),
				archiver_prefs.format);

	PACK_FRAME (vbox1, frame, _("Default miscellaneous options"));

	hbox1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
	gtk_widget_show(hbox1);
	gtk_container_set_border_width(GTK_CONTAINER(hbox1), 4);
	gtk_container_add(GTK_CONTAINER(frame), hbox1);

	PACK_CHECK_BUTTON(hbox1, recursive_chkbtn, _("Recursive"));
	CLAWS_SET_TIP(recursive_chkbtn,
		_("Choose this option to include subfolders in the archives by default"));
	PACK_CHECK_BUTTON(hbox1, md5sum_chkbtn, _("MD5sum"));
	CLAWS_SET_TIP(md5sum_chkbtn,
		_("Choose this option to add MD5 checksums for each file in the archives by default.\n"
		  "Be aware though, that this dramatically increases the time it\n"
		  "will take to create the archives"));

	PACK_CHECK_BUTTON(hbox1, rename_chkbtn, _("Rename"));
	CLAWS_SET_TIP(rename_chkbtn,
		_("Choose this option to use descriptive names for each file in the archive.\n"
		  "The naming scheme: date_from@to@subject.\n"
		  "Names will be truncated to max 96 characters"));

	PACK_CHECK_BUTTON(hbox1, unlink_chkbtn, _("Delete"));
	CLAWS_SET_TIP(unlink_chkbtn,
		_("Choose this option to delete mails after archiving"));

	if (archiver_prefs.recursive)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(recursive_chkbtn), TRUE);
	if (archiver_prefs.md5sum)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(md5sum_chkbtn), TRUE);
	if (archiver_prefs.rename)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rename_chkbtn), TRUE);
	if (archiver_prefs.unlink)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(unlink_chkbtn), TRUE);


	page->save_folder = save_folder;
	page->compression_combo = compression_combo;
	page->format_combo = format_combo;
	page->recursive_chkbtn = recursive_chkbtn;
	page->md5sum_chkbtn = md5sum_chkbtn;
	page->rename_chkbtn = rename_chkbtn;
        page->unlink_chkbtn = unlink_chkbtn;

	page->page.widget = vbox1;
}

static void destroy_archiver_prefs_page(PrefsPage *page)
{
	/* Do nothing! */
}

static void save_archiver_prefs(PrefsPage * _page)
{
	struct ArchiverPrefsPage *page = (struct ArchiverPrefsPage *) _page;
        PrefFile *pref_file;
        gchar *rc_file_path = g_strconcat(get_rc_dir(), G_DIR_SEPARATOR_S,
                                          COMMON_RC, NULL);

	archiver_prefs.save_folder = gtk_editable_get_chars(GTK_EDITABLE(page->save_folder), 0, -1);

	archiver_prefs.compression = combobox_get_active_data(GTK_COMBO_BOX(page->compression_combo));

	archiver_prefs.format = combobox_get_active_data(GTK_COMBO_BOX(page->format_combo));

	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(page->recursive_chkbtn)))
		archiver_prefs.recursive = TRUE;
	else
		archiver_prefs.recursive = FALSE;
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(page->md5sum_chkbtn)))
		archiver_prefs.md5sum = TRUE;
	else
		archiver_prefs.md5sum = FALSE;
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(page->rename_chkbtn)))
		archiver_prefs.rename = TRUE;
	else
		archiver_prefs.rename = FALSE;
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(page->unlink_chkbtn)))
		archiver_prefs.unlink = TRUE;
	else
		archiver_prefs.unlink = FALSE;


        pref_file = prefs_write_open(rc_file_path);
        g_free(rc_file_path);
        
        if (!(pref_file) ||
	    (prefs_set_block_label(pref_file, PREFS_BLOCK_NAME) < 0))
          return;
        
        if (prefs_write_param(param, pref_file->fp) < 0) {
          g_warning("failed to write Archiver plugin configuration");
          prefs_file_close_revert(pref_file);
          return;
        }
        if (fprintf(pref_file->fp, "\n") < 0) {
		FILE_OP_ERROR(rc_file_path, "fprintf");
		prefs_file_close_revert(pref_file);
	} else
	        prefs_file_close(pref_file);

}
