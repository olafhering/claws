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

#ifdef HAVE_CONFIG_H
#include "config.h"
#include "claws-features.h"
#endif

#include "defs.h"

#include <glib.h>
#include <glib/gi18n.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef G_OS_WIN32
#include <sys/time.h>
#endif

#include "recv.h"
#include "socket.h"
#include "utils.h"

static RecvUIFunc recv_ui_func;
static gpointer recv_ui_func_data;

void recv_set_ui_func(RecvUIFunc func, gpointer data)
{
	recv_ui_func = func;
	recv_ui_func_data = data;
}
/*
 * vim: noet ts=4 shiftwidth=4 nowrap
 */
