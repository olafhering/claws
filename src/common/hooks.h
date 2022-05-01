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

#ifndef HOOKS_H
#define HOOKS_H

#include <glib.h>

#define HOOK_NONE 0

typedef gboolean (*SylpheedHookFunction) (gpointer source, gpointer userdata);

gulong hooks_register_hook(const gchar *hooklist_name, SylpheedHookFunction hook_func, gpointer userdata);
void hooks_unregister_hook(const gchar *hooklist_name, gulong hook_id);
gboolean hooks_invoke(const gchar *hooklist_name, gpointer source);

#endif /* HOOKS_H */
