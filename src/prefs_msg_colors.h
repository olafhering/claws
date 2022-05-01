/*
 * Sylpheed -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 2004-2012 Hiroyuki Yamamoto and the Claws Mail team
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

#ifndef PREFS_MSG_COLORS_H
#define PREFS_MSG_COLORS_H

#include "colorlabel.h"

typedef struct _ColorlabelPrefs ColorlabelPrefs;
typedef struct _ColorlabelPrefsWidgets ColorlabelPrefsWidgets;

struct _ColorlabelPrefs {
	gulong color;
	gchar *label;

};

struct _ColorlabelPrefsWidgets {
	GtkWidget *foo;
	GtkWidget *bar;
};

void prefs_msg_colors_init(void);
void prefs_msg_colors_done(void);

#endif /* PREFS_MSG_COLORS_H */
