/* Python plugin for Claws Mail
 * Copyright (C) 2009 Holger Berndt
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

#ifndef COMPOSEWINDOWTYPE_H
#define COMPOSEWINDOWTYPE_H

#include <Python.h>
#include <glib.h>

#include "compose.h"

gboolean cmpy_add_composewindow(PyObject *module);

PyObject *clawsmail_compose_new(PyObject *module, Compose *compose);

#endif /* COMPOSEWINDOWTYPE_H */
