/* GTK - The GIMP Toolkit
 * Copyright (C) 1995-1997 Peter Mattis, Spencer Kimball, Josh MacDonald, 
 * Copyright (C) 1997-1998 Jay Painter <jpaint@serv.net><jpaint@gimp.org>  
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/*
 * Modified by the GTK+ Team and others 1997-2000.  See the AUTHORS
 * file for a list of people on the GTK+ Team.  See the ChangeLog
 * files for a list of changes.  These files are distributed with
 * GTK+ at ftp://ftp.gtk.org/pub/gtk/. 
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include <gtk/gtk.h>
#include "claws-marshal.h"
#include "gtkcmclist.h"
#include <gdk/gdkkeysyms.h>
#include "utils.h"
#include "gtkutils.h"

/* length of button_actions array */
#define MAX_BUTTON 5

/* the number rows memchunk expands at a time */
#define CMCLIST_OPTIMUM_SIZE 64

/* the width of the column resize windows */
#define DRAG_WIDTH  6

/* minimum allowed width of a column */
#define COLUMN_MIN_WIDTH 5

/* this defigns the base grid spacing */
#define CELL_SPACING 1

/* added the horizontal space at the beginning and end of a row*/
#define COLUMN_INSET 3

/* used for auto-scrolling */
#define SCROLL_TIME  100

/* gives the top pixel of the given row in context of
 * the clist's voffset */
#define ROW_TOP_YPIXEL(clist, row) (((clist)->row_height * (row)) + \
				    (((row) + 1) * CELL_SPACING) + \
				    (clist)->voffset)

/* returns the row index from a y pixel location in the 
 * context of the clist's voffset */
#define ROW_FROM_YPIXEL(clist, y)  (((y) - (clist)->voffset) / \
				    ((clist)->row_height + CELL_SPACING))

/* gives the left pixel of the given column in context of
 * the clist's hoffset */
#define COLUMN_LEFT_XPIXEL(clist, colnum)  ((clist)->column[(colnum)].area.x + \
					    (clist)->hoffset)

static void gtk_cmclist_scrollable_init (GtkScrollableInterface *iface);

/* returns the column index from a x pixel location in the 
 * context of the clist's hoffset */
static inline gint
COLUMN_FROM_XPIXEL (GtkCMCList * clist,
		    gint x)
{
  gint i, cx;

  for (i = 0; i < clist->columns; i++)
    if (clist->column[i].visible)
      {
	cx = clist->column[i].area.x + clist->hoffset;

	if (x >= (cx - (COLUMN_INSET + CELL_SPACING)) &&
	    x <= (cx + clist->column[i].area.width + COLUMN_INSET))
	  return i;
      }

  /* no match */
  return -1;
}

/* returns the top pixel of the given row in the context of
 * the list height */
#define ROW_TOP(clist, row)        (((clist)->row_height + CELL_SPACING) * (row))

/* returns the left pixel of the given column in the context of
 * the list width */
#define COLUMN_LEFT(clist, colnum) ((clist)->column[(colnum)].area.x)

/* returns the total height of the list */
#define LIST_HEIGHT(clist)         (((clist)->row_height * ((clist)->rows)) + \
				    (CELL_SPACING * ((clist)->rows + 1)))


/* returns the total width of the list */
static inline gint
LIST_WIDTH (GtkCMCList * clist) 
{
  gint last_column;

  for (last_column = clist->columns - 1;
       last_column >= 0 && !clist->column[last_column].visible; last_column--);

  if (last_column >= 0)
    return (clist->column[last_column].area.x +
	    clist->column[last_column].area.width +
	    COLUMN_INSET + CELL_SPACING);
  return 0;
}

/* returns the GList item for the nth row */
#define	ROW_ELEMENT(clist, row)	(((row) == (clist)->rows - 1) ? \
				 (clist)->row_list_end : \
				 g_list_nth ((clist)->row_list, (row)))


/* redraw the list if it's not frozen */
#define CLIST_UNFROZEN(clist)     (((GtkCMCList*) (clist))->freeze_count == 0)
#define	CLIST_REFRESH(clist)	G_STMT_START { \
  if (CLIST_UNFROZEN (clist)) \
    GTK_CMCLIST_GET_CLASS (clist)->refresh ((GtkCMCList*) (clist)); \
} G_STMT_END


/* Signals */
enum {
  SELECT_ROW,
  UNSELECT_ROW,
  ROW_MOVE,
  CLICK_COLUMN,
  RESIZE_COLUMN,
  TOGGLE_FOCUS_ROW,
  SELECT_ALL,
  UNSELECT_ALL,
  UNDO_SELECTION,
  START_SELECTION,
  END_SELECTION,
  TOGGLE_ADD_MODE,
  EXTEND_SELECTION,
  SCROLL_VERTICAL,
  SCROLL_HORIZONTAL,
  ABORT_COLUMN_RESIZE,
  LAST_SIGNAL
};

enum {
  SYNC_REMOVE,
  SYNC_INSERT
};

enum {
  ARG_0,
  ARG_N_COLUMNS,
  ARG_SHADOW_TYPE,
  ARG_SELECTION_MODE,
  ARG_ROW_HEIGHT,
  ARG_TITLES_ACTIVE,
  ARG_REORDERABLE,
  ARG_USE_DRAG_ICONS,
  ARG_SORT_TYPE,
  ARG_HADJUSTMENT,
  ARG_VADJUSTMENT,
  ARG_HSCROLL_POLICY,
  ARG_VSCROLL_POLICY
};

/* GtkCMCList Methods */
static void     gtk_cmclist_class_init  (GtkCMCListClass         *klass);
static void     gtk_cmclist_init        (GtkCMCList              *clist);
static GObject* gtk_cmclist_constructor (GType                  type,
				       guint                  n_construct_properties,
				       GObjectConstructParam *construct_params);

/* GtkObject Methods */
static void gtk_cmclist_destroy  (GtkWidget *object);
static void gtk_cmclist_finalize (GObject   *object);
static void gtk_cmclist_set_arg  (GObject *object,
				guint      arg_id,
				const GValue *value,
				GParamSpec *spec);
static void gtk_cmclist_get_arg  (GObject *object,
				guint      arg_id,
				GValue *value,
				GParamSpec *spec);

/* GtkWidget Methods */
static void gtk_cmclist_realize         (GtkWidget        *widget);
static void gtk_cmclist_unrealize       (GtkWidget        *widget);
static void gtk_cmclist_map             (GtkWidget        *widget);
static void gtk_cmclist_unmap           (GtkWidget        *widget);
static gint gtk_cmclist_draw            (GtkWidget *widget,
                                         cairo_t *event);
static gint gtk_cmclist_button_press    (GtkWidget        *widget,
				       GdkEventButton   *event);
static gint gtk_cmclist_button_release  (GtkWidget        *widget,
				       GdkEventButton   *event);
static gint gtk_cmclist_motion          (GtkWidget        *widget, 
			               GdkEventMotion   *event);
static void gtk_cmclist_get_preferred_height (GtkWidget *widget,
                                 gint      *minimal_height,
                                 gint      *natural_height);
static void gtk_cmclist_get_preferred_width (GtkWidget *widget,
                                 gint      *minimal_width,
                                 gint      *natural_width);
static void gtk_cmclist_size_request    (GtkWidget        *widget,
				       GtkRequisition   *requisition);
static void gtk_cmclist_size_allocate   (GtkWidget        *widget,
				       GtkAllocation    *allocation);
static void gtk_cmclist_undraw_focus      (GtkWidget        *widget);
static void gtk_cmclist_draw_focus      (GtkWidget        *widget);
static gint gtk_cmclist_focus_in        (GtkWidget        *widget,
				       GdkEventFocus    *event);
static gint gtk_cmclist_focus_out       (GtkWidget        *widget,
				       GdkEventFocus    *event);
static gint gtk_cmclist_focus           (GtkWidget        *widget,
				       GtkDirectionType  direction);
static void gtk_cmclist_set_focus_child (GtkContainer     *container,
				       GtkWidget        *child);
static void gtk_cmclist_style_set       (GtkWidget        *widget,
				       GtkStyle         *previous_style);
static void gtk_cmclist_drag_begin      (GtkWidget        *widget,
				       GdkDragContext   *context);
static gint gtk_cmclist_drag_motion     (GtkWidget        *widget,
				       GdkDragContext   *context,
				       gint              x,
				       gint              y,
				       guint             time);
static void gtk_cmclist_drag_leave      (GtkWidget        *widget,
				       GdkDragContext   *context,
				       guint             time);
static void gtk_cmclist_drag_end        (GtkWidget        *widget,
				       GdkDragContext   *context);
static gboolean gtk_cmclist_drag_drop   (GtkWidget      *widget,
				       GdkDragContext *context,
				       gint            x,
				       gint            y,
				       guint           time);
static void gtk_cmclist_drag_data_get   (GtkWidget        *widget,
				       GdkDragContext   *context,
				       GtkSelectionData *selection_data,
				       guint             info,
				       guint             time);
static void gtk_cmclist_drag_data_received (GtkWidget        *widget,
					  GdkDragContext   *context,
					  gint              x,
					  gint              y,
					  GtkSelectionData *selection_data,
					  guint             info,
					  guint             time);

/* GtkContainer Methods */
static void gtk_cmclist_forall          (GtkContainer  *container,
			               gboolean       include_internals,
			               GtkCallback    callback,
			               gpointer       callback_data);

/* Selection */
static void toggle_row                (GtkCMCList      *clist,
			               gint           row,
			               gint           column,
			               GdkEvent      *event);
static void real_select_row           (GtkCMCList      *clist,
			               gint           row,
			               gint           column,
			               GdkEvent      *event);
static void real_unselect_row         (GtkCMCList      *clist,
			               gint           row,
			               gint           column,
			               GdkEvent      *event);
static void update_extended_selection (GtkCMCList      *clist,
				       gint           row);
static GList *selection_find          (GtkCMCList      *clist,
			               gint           row_number,
			               GList         *row_list_element);
static void real_select_all           (GtkCMCList      *clist);
static void real_unselect_all         (GtkCMCList      *clist);
static void move_vertical             (GtkCMCList      *clist,
			               gint           row,
			               gfloat         align);
static void move_horizontal           (GtkCMCList      *clist,
			               gint           diff);
static void real_undo_selection       (GtkCMCList      *clist);
static void fake_unselect_all         (GtkCMCList      *clist,
			               gint           row);
static void fake_toggle_row           (GtkCMCList      *clist,
			               gint           row);
static void resync_selection          (GtkCMCList      *clist,
			               GdkEvent      *event);
static void sync_selection            (GtkCMCList      *clist,
	                               gint           row,
                                       gint           mode);
static void set_anchor                (GtkCMCList      *clist,
			               gboolean       add_mode,
			               gint           anchor,
			               gint           undo_anchor);
static void start_selection           (GtkCMCList      *clist);
static void end_selection             (GtkCMCList      *clist);
static void toggle_add_mode           (GtkCMCList      *clist);
static void toggle_focus_row          (GtkCMCList      *clist);
static void extend_selection          (GtkCMCList      *clist,
			               GtkScrollType  scroll_type,
			               gfloat         position,
			               gboolean       auto_start_selection);
static gint get_selection_info        (GtkCMCList       *clist,
				       gint            x,
				       gint            y,
				       gint           *row,
				       gint           *column);

/* Scrolling */
static void move_focus_row     (GtkCMCList      *clist,
			        GtkScrollType  scroll_type,
			        gfloat         position);
static void scroll_horizontal  (GtkCMCList      *clist,
			        GtkScrollType  scroll_type,
			        gfloat         position);
static void scroll_vertical    (GtkCMCList      *clist,
			        GtkScrollType  scroll_type,
			        gfloat         position);
static void move_horizontal    (GtkCMCList      *clist,
				gint           diff);
static void move_vertical      (GtkCMCList      *clist,
				gint           row,
				gfloat         align);
static gint horizontal_timeout (GtkCMCList      *clist);
static gint vertical_timeout   (GtkCMCList      *clist);
static void remove_grab        (GtkCMCList      *clist);


/* Resize Columns */
static void draw_xor_line             (GtkCMCList       *clist);
static gint new_column_width          (GtkCMCList       *clist,
			               gint            column,
			               gint           *x);
static void column_auto_resize        (GtkCMCList       *clist,
				       GtkCMCListRow    *clist_row,
				       gint            column,
				       gint            old_width);
static void real_resize_column        (GtkCMCList       *clist,
				       gint            column,
				       gint            width);
static void abort_column_resize       (GtkCMCList       *clist);
static void cell_size_request         (GtkCMCList       *clist,
			               GtkCMCListRow    *clist_row,
			               gint            column,
				       GtkRequisition *requisition);

/* Buttons */
static void column_button_create      (GtkCMCList       *clist,
				       gint            column);
static void column_button_clicked     (GtkWidget      *widget,
				       gpointer        data);

/* Adjustments */
static void adjust_adjustments        (GtkCMCList       *clist,
				       gboolean        block_resize);
static void vadjustment_value_changed (GtkAdjustment  *adjustment,
				       gpointer        data);
static void hadjustment_value_changed (GtkAdjustment  *adjustment,
				       gpointer        data);

/* Drawing */
static void get_cell_style   (GtkCMCList      *clist,
			      GtkCMCListRow   *clist_row,
			      gint           state,
			      gint           column,
			      GtkStyle     **style);
static gint draw_cell_pixbuf (GdkWindow     *window,
			      GdkRectangle  *clip_rectangle,
			      cairo_t	    *cr,
			      GdkPixbuf     *pixbuf,
			      gint           x,
			      gint           y,
			      gint           width,
			      gint           height);
static void draw_row         (GtkCMCList      *clist,
			      GdkRectangle  *area,
			      gint           row,
			      GtkCMCListRow   *clist_row);
static void draw_rows        (GtkCMCList      *clist,
			      GdkRectangle  *area);
static void clist_refresh    (GtkCMCList      *clist);
     
/* Size Allocation / Requisition */
static void size_allocate_title_buttons (GtkCMCList *clist);
static void size_allocate_columns       (GtkCMCList *clist,
					 gboolean  block_resize);
static gint list_requisition_width      (GtkCMCList *clist);

/* Memory Allocation/Distruction Routines */
static GtkCMCListColumn *columns_new (GtkCMCList      *clist);
static void column_title_new       (GtkCMCList      *clist,
			            gint           column,
			            const gchar   *title);
static void columns_delete         (GtkCMCList      *clist);
static GtkCMCListRow *row_new        (GtkCMCList      *clist);
static void row_delete             (GtkCMCList      *clist,
			            GtkCMCListRow   *clist_row);
static void set_cell_contents      (GtkCMCList      *clist,
			            GtkCMCListRow   *clist_row,
				    gint           column,
				    GtkCMCellType    type,
				    const gchar   *text,
				    guint8         spacing,
				    GdkPixbuf     *pixbuf);
static gint real_insert_row        (GtkCMCList      *clist,
				    gint           row,
				    gchar         *text[]);
static void real_remove_row        (GtkCMCList      *clist,
				    gint           row);
static void real_clear             (GtkCMCList      *clist);

/* Sorting */
static gint default_compare        (GtkCMCList      *clist,
			            gconstpointer  row1,
			            gconstpointer  row2);
static void real_sort_list         (GtkCMCList      *clist);
static GList *gtk_cmclist_merge      (GtkCMCList      *clist,
				    GList         *a,
				    GList         *b);
static GList *gtk_cmclist_mergesort  (GtkCMCList      *clist,
				    GList         *list,
				    gint           num);
/* Misc */
static gboolean title_focus_in   (GtkCMCList *clist,
				  gint      dir);
static gboolean title_focus_move (GtkCMCList *clist,
				  gint      dir);

static void real_row_move             (GtkCMCList  *clist,
			               gint       source_row,
			               gint       dest_row);
static gint column_title_passive_func (GtkWidget *widget, 
				       GdkEvent  *event,
				       gpointer   data);
static void drag_dest_cell            (GtkCMCList         *clist,
				       gint              x,
				       gint              y,
				       GtkCMCListDestInfo *dest_info);



static guint clist_signals[LAST_SIGNAL] = {0};

static const GtkTargetEntry clist_target_table = { "gtk-clist-drag-reorder", 0, 0};

G_DEFINE_TYPE_WITH_CODE (GtkCMCList, gtk_cmclist, GTK_TYPE_CONTAINER,
                         G_IMPLEMENT_INTERFACE (GTK_TYPE_SCROLLABLE,
                         gtk_cmclist_scrollable_init))

static void
gtk_cmclist_class_init (GtkCMCListClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  GtkWidgetClass *widget_class;
  GtkContainerClass *container_class;
  GtkBindingSet *binding_set;

  object_class->constructor = gtk_cmclist_constructor;

  widget_class = (GtkWidgetClass *) klass;
  container_class = (GtkContainerClass *) klass;

  object_class->finalize = gtk_cmclist_finalize;
  widget_class->destroy = gtk_cmclist_destroy;
  object_class->set_property = gtk_cmclist_set_arg;
  object_class->get_property = gtk_cmclist_get_arg;
  

  widget_class->realize = gtk_cmclist_realize;
  widget_class->unrealize = gtk_cmclist_unrealize;
  widget_class->map = gtk_cmclist_map;
  widget_class->unmap = gtk_cmclist_unmap;
  widget_class->button_press_event = gtk_cmclist_button_press;
  widget_class->button_release_event = gtk_cmclist_button_release;
  widget_class->motion_notify_event = gtk_cmclist_motion;
  widget_class->draw = gtk_cmclist_draw;

  widget_class->get_preferred_width = gtk_cmclist_get_preferred_width;
  widget_class->get_preferred_height = gtk_cmclist_get_preferred_height;
  widget_class->size_allocate = gtk_cmclist_size_allocate;
  widget_class->focus_in_event = gtk_cmclist_focus_in;
  widget_class->focus_out_event = gtk_cmclist_focus_out;
  widget_class->style_set = gtk_cmclist_style_set;
  widget_class->drag_begin = gtk_cmclist_drag_begin;
  widget_class->drag_end = gtk_cmclist_drag_end;
  widget_class->drag_motion = gtk_cmclist_drag_motion;
  widget_class->drag_leave = gtk_cmclist_drag_leave;
  widget_class->drag_drop = gtk_cmclist_drag_drop;
  widget_class->drag_data_get = gtk_cmclist_drag_data_get;
  widget_class->drag_data_received = gtk_cmclist_drag_data_received;
  widget_class->focus = gtk_cmclist_focus;
  
  /* container_class->add = NULL; use the default GtkContainerClass warning */
  /* container_class->remove=NULL; use the default GtkContainerClass warning */

  container_class->forall = gtk_cmclist_forall;
  container_class->set_focus_child = gtk_cmclist_set_focus_child;

  klass->refresh = clist_refresh;
  klass->select_row = real_select_row;
  klass->unselect_row = real_unselect_row;
  klass->row_move = real_row_move;
  klass->undo_selection = real_undo_selection;
  klass->resync_selection = resync_selection;
  klass->selection_find = selection_find;
  klass->click_column = NULL;
  klass->resize_column = real_resize_column;
  klass->draw_row = draw_row;
  klass->insert_row = real_insert_row;
  klass->remove_row = real_remove_row;
  klass->clear = real_clear;
  klass->sort_list = real_sort_list;
  klass->select_all = real_select_all;
  klass->unselect_all = real_unselect_all;
  klass->fake_unselect_all = fake_unselect_all;
  klass->scroll_horizontal = scroll_horizontal;
  klass->scroll_vertical = scroll_vertical;
  klass->extend_selection = extend_selection;
  klass->toggle_focus_row = toggle_focus_row;
  klass->toggle_add_mode = toggle_add_mode;
  klass->start_selection = start_selection;
  klass->end_selection = end_selection;
  klass->abort_column_resize = abort_column_resize;
  klass->set_cell_contents = set_cell_contents;
  klass->cell_size_request = cell_size_request;

  g_object_class_install_property (object_class,
				ARG_N_COLUMNS,
				g_param_spec_uint ("n-columns",
				"N-Columns",
				"N-Columns",
				1,
				G_MAXINT,
				1,
				G_PARAM_READWRITE|G_PARAM_CONSTRUCT_ONLY));
  g_object_class_install_property (object_class,
				ARG_SHADOW_TYPE,
				g_param_spec_enum ("shadow-type",
				"shadow-type",
				"shadow-type",
				GTK_TYPE_SHADOW_TYPE, 0,
				G_PARAM_READWRITE));
  g_object_class_install_property (object_class,
				ARG_SELECTION_MODE,
				g_param_spec_enum ("selection-mode",
				"selection-mode",
				"selection-mode",
				GTK_TYPE_SELECTION_MODE, 0,
				G_PARAM_READWRITE));
  g_object_class_install_property (object_class,
				ARG_ROW_HEIGHT,
				g_param_spec_uint ("row-height",
				"row-height",
				"row-height",
				0,
				G_MAXINT,
				0,
				G_PARAM_READWRITE));
  g_object_class_install_property (object_class,
				ARG_REORDERABLE,
				g_param_spec_boolean ("reorderable",
				"reorderable",
				"reorderable",
				TRUE,
				G_PARAM_READWRITE));
  g_object_class_install_property (object_class,
				ARG_TITLES_ACTIVE,
				g_param_spec_boolean ("titles-active",
				"titles-active",
				"titles-active",
				TRUE,
				G_PARAM_READWRITE));
  g_object_class_install_property (object_class,
				ARG_USE_DRAG_ICONS,
				g_param_spec_boolean ("use-drag-icons",
				"use-drag-icons",
				"use-drag-icons",
				TRUE,
				G_PARAM_READWRITE));
  g_object_class_install_property (object_class,
				ARG_SORT_TYPE,
				g_param_spec_enum ("sort-type",
				"sort-type",
				"sort-type",
				GTK_TYPE_SORT_TYPE, 0,
				G_PARAM_READWRITE));
  /* Scrollable interface properties */
  g_object_class_override_property (object_class, ARG_HADJUSTMENT, "hadjustment");
  g_object_class_override_property (object_class, ARG_VADJUSTMENT, "vadjustment");
  g_object_class_override_property (object_class, ARG_HSCROLL_POLICY, "hscroll-policy");
  g_object_class_override_property (object_class, ARG_VSCROLL_POLICY, "vscroll-policy");

  clist_signals[SELECT_ROW] =
 		g_signal_new ("select_row",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (GtkCMCListClass, select_row),
			      NULL, NULL,
			      claws_marshal_VOID__INT_INT_BOXED,
			      G_TYPE_NONE, 3,
			      G_TYPE_INT,
			      G_TYPE_INT,
			      GDK_TYPE_EVENT | G_SIGNAL_TYPE_STATIC_SCOPE);
  clist_signals[UNSELECT_ROW] =
 		g_signal_new ("unselect_row",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (GtkCMCListClass, unselect_row),
			      NULL, NULL,
			      claws_marshal_VOID__INT_INT_BOXED,
			      G_TYPE_NONE, 3,
			      G_TYPE_INT,
			      G_TYPE_INT,
			      GDK_TYPE_EVENT);
  clist_signals[ROW_MOVE] =
 		g_signal_new ("row_move",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (GtkCMCListClass, row_move),
			      NULL, NULL,
			      claws_marshal_VOID__INT_INT,
			      G_TYPE_NONE, 2, G_TYPE_INT, G_TYPE_INT);
  clist_signals[CLICK_COLUMN] =
 		g_signal_new ("click_column",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (GtkCMCListClass, click_column),
			      NULL, NULL,
			      claws_marshal_VOID__INT,
		    	      G_TYPE_NONE, 1, G_TYPE_INT);
  clist_signals[RESIZE_COLUMN] =
 		g_signal_new ("resize_column",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (GtkCMCListClass, resize_column),
			      NULL, NULL,
			      claws_marshal_VOID__INT_INT,
		    	      G_TYPE_NONE, 2, G_TYPE_INT, G_TYPE_INT);

  clist_signals[TOGGLE_FOCUS_ROW] =
 		g_signal_new ("toggle_focus_row",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
			      G_STRUCT_OFFSET (GtkCMCListClass, toggle_focus_row),
			      NULL, NULL,
			      claws_marshal_VOID__VOID,
		    	      G_TYPE_NONE, 0);
  clist_signals[SELECT_ALL] =
 		g_signal_new ("select_all",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
			      G_STRUCT_OFFSET (GtkCMCListClass, select_all),
			      NULL, NULL,
			      claws_marshal_VOID__VOID,
		    	      G_TYPE_NONE, 0);
  clist_signals[UNSELECT_ALL] =
 		g_signal_new ("unselect_all",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
			      G_STRUCT_OFFSET (GtkCMCListClass, unselect_all),
			      NULL, NULL,
			      claws_marshal_VOID__VOID,
		    	      G_TYPE_NONE, 0);
  clist_signals[UNDO_SELECTION] =
 		g_signal_new ("undo_selection",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
			      G_STRUCT_OFFSET (GtkCMCListClass, undo_selection),
			      NULL, NULL,
			      claws_marshal_VOID__VOID,
		    	      G_TYPE_NONE, 0);
  clist_signals[START_SELECTION] =
 		g_signal_new ("start_selection",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
			      G_STRUCT_OFFSET (GtkCMCListClass, start_selection),
			      NULL, NULL,
			      claws_marshal_VOID__VOID,
		    	      G_TYPE_NONE, 0);
  clist_signals[END_SELECTION] =
 		g_signal_new ("end_selection",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
			      G_STRUCT_OFFSET (GtkCMCListClass, end_selection),
			      NULL, NULL,
			      claws_marshal_VOID__VOID,
		    	      G_TYPE_NONE, 0);
  clist_signals[TOGGLE_ADD_MODE] =
 		g_signal_new ("toggle_add_mode",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
			      G_STRUCT_OFFSET (GtkCMCListClass, toggle_add_mode),
			      NULL, NULL,
			      claws_marshal_VOID__VOID,
		    	      G_TYPE_NONE, 0);
  clist_signals[EXTEND_SELECTION] =
 		g_signal_new ("extend_selection",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
			      G_STRUCT_OFFSET (GtkCMCListClass, extend_selection),
			      NULL, NULL,
			      claws_marshal_VOID__ENUM_FLOAT_BOOLEAN,
		    	      G_TYPE_NONE, 3, GTK_TYPE_SCROLL_TYPE, G_TYPE_FLOAT, G_TYPE_BOOLEAN);
  clist_signals[SCROLL_VERTICAL] =
 		g_signal_new ("scroll_vertical",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
			      G_STRUCT_OFFSET (GtkCMCListClass, scroll_vertical),
			      NULL, NULL,
			      claws_marshal_VOID__ENUM_FLOAT,
		    	      G_TYPE_NONE, 2, GTK_TYPE_SCROLL_TYPE, G_TYPE_FLOAT);
  clist_signals[SCROLL_HORIZONTAL] =
 		g_signal_new ("scroll_horizontal",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
			      G_STRUCT_OFFSET (GtkCMCListClass, scroll_horizontal),
			      NULL, NULL,
			      claws_marshal_VOID__ENUM_FLOAT,
		    	      G_TYPE_NONE, 2, GTK_TYPE_SCROLL_TYPE, G_TYPE_FLOAT);
  clist_signals[ABORT_COLUMN_RESIZE] =
 		g_signal_new ("abort_column_resize",
			      G_TYPE_FROM_CLASS (object_class),
			      G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
			      G_STRUCT_OFFSET (GtkCMCListClass, abort_column_resize),
			      NULL, NULL,
			      claws_marshal_VOID__VOID,
		    	      G_TYPE_NONE, 0);

  binding_set = gtk_binding_set_by_class (klass);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Up, 0,
			        "scroll_vertical", 2,
				G_TYPE_ENUM, GTK_SCROLL_STEP_BACKWARD,
				G_TYPE_FLOAT, 0.0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Up, 0,
				"scroll_vertical", 2,
				G_TYPE_ENUM, GTK_SCROLL_STEP_BACKWARD,
				G_TYPE_FLOAT, 0.0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Down, 0,
				"scroll_vertical", 2,
				G_TYPE_ENUM, GTK_SCROLL_STEP_FORWARD,
				G_TYPE_FLOAT, 0.0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Down, 0,
				"scroll_vertical", 2,
				G_TYPE_ENUM, GTK_SCROLL_STEP_FORWARD,
				G_TYPE_FLOAT, 0.0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Page_Up, 0,
				"scroll_vertical", 2,
				G_TYPE_ENUM, GTK_SCROLL_PAGE_BACKWARD,
				G_TYPE_FLOAT, 0.0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Page_Up, 0,
				"scroll_vertical", 2,
				G_TYPE_ENUM, GTK_SCROLL_PAGE_BACKWARD,
				G_TYPE_FLOAT, 0.0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Page_Down, 0,
				"scroll_vertical", 2,
				G_TYPE_ENUM, GTK_SCROLL_PAGE_FORWARD,
				G_TYPE_FLOAT, 0.0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Page_Down, 0,
				"scroll_vertical", 2,
				G_TYPE_ENUM, GTK_SCROLL_PAGE_FORWARD,
				G_TYPE_FLOAT, 0.0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Home, GDK_CONTROL_MASK,
				"scroll_vertical", 2,
				G_TYPE_ENUM, GTK_SCROLL_JUMP,
				G_TYPE_FLOAT, 0.0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Home, GDK_CONTROL_MASK,
				"scroll_vertical", 2,
				G_TYPE_ENUM, GTK_SCROLL_JUMP,
				G_TYPE_FLOAT, 0.0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_End, GDK_CONTROL_MASK,
				"scroll_vertical", 2,
				G_TYPE_ENUM, GTK_SCROLL_JUMP,
				G_TYPE_FLOAT, 1.0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_End, GDK_CONTROL_MASK,
				"scroll_vertical", 2,
				G_TYPE_ENUM, GTK_SCROLL_JUMP,
				G_TYPE_FLOAT, 1.0);
  
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Up, GDK_SHIFT_MASK,
				"extend_selection", 3,
				G_TYPE_ENUM, GTK_SCROLL_STEP_BACKWARD,
				G_TYPE_FLOAT, 0.0, G_TYPE_BOOLEAN, TRUE);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Up, GDK_SHIFT_MASK,
				"extend_selection", 3,
				G_TYPE_ENUM, GTK_SCROLL_STEP_BACKWARD,
				G_TYPE_FLOAT, 0.0, G_TYPE_BOOLEAN, TRUE);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Down, GDK_SHIFT_MASK,
				"extend_selection", 3,
				G_TYPE_ENUM, GTK_SCROLL_STEP_FORWARD,
				G_TYPE_FLOAT, 0.0, G_TYPE_BOOLEAN, TRUE);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Down, GDK_SHIFT_MASK,
				"extend_selection", 3,
				G_TYPE_ENUM, GTK_SCROLL_STEP_FORWARD,
				G_TYPE_FLOAT, 0.0, G_TYPE_BOOLEAN, TRUE);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Page_Up, GDK_SHIFT_MASK,
				"extend_selection", 3,
				G_TYPE_ENUM, GTK_SCROLL_PAGE_BACKWARD,
				G_TYPE_FLOAT, 0.0, G_TYPE_BOOLEAN, TRUE);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Page_Up, GDK_SHIFT_MASK,
				"extend_selection", 3,
				G_TYPE_ENUM, GTK_SCROLL_PAGE_BACKWARD,
				G_TYPE_FLOAT, 0.0, G_TYPE_BOOLEAN, TRUE);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Page_Down, GDK_SHIFT_MASK,
				"extend_selection", 3,
				G_TYPE_ENUM, GTK_SCROLL_PAGE_FORWARD,
				G_TYPE_FLOAT, 0.0, G_TYPE_BOOLEAN, TRUE);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Page_Down, GDK_SHIFT_MASK,
				"extend_selection", 3,
				G_TYPE_ENUM, GTK_SCROLL_PAGE_FORWARD,
				G_TYPE_FLOAT, 0.0, G_TYPE_BOOLEAN, TRUE);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Home,
				GDK_SHIFT_MASK | GDK_CONTROL_MASK,
				"extend_selection", 3,
				G_TYPE_ENUM, GTK_SCROLL_JUMP,
				G_TYPE_FLOAT, 0.0, G_TYPE_BOOLEAN, TRUE);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Home,
                                GDK_SHIFT_MASK | GDK_CONTROL_MASK,
				"extend_selection", 3,
				G_TYPE_ENUM, GTK_SCROLL_JUMP,
				G_TYPE_FLOAT, 0.0, G_TYPE_BOOLEAN, TRUE);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_End,
				GDK_SHIFT_MASK | GDK_CONTROL_MASK,
				"extend_selection", 3,
				G_TYPE_ENUM, GTK_SCROLL_JUMP,
				G_TYPE_FLOAT, 1.0, G_TYPE_BOOLEAN, TRUE);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_End,
				GDK_SHIFT_MASK | GDK_CONTROL_MASK,
				"extend_selection", 3,
				G_TYPE_ENUM, GTK_SCROLL_JUMP,
				G_TYPE_FLOAT, 1.0, G_TYPE_BOOLEAN, TRUE);

  
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Left, 0,
				"scroll_horizontal", 2,
				G_TYPE_ENUM, GTK_SCROLL_STEP_BACKWARD,
				G_TYPE_FLOAT, 0.0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Left, 0,
				"scroll_horizontal", 2,
				G_TYPE_ENUM, GTK_SCROLL_STEP_BACKWARD,
				G_TYPE_FLOAT, 0.0);
  
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Right, 0,
				"scroll_horizontal", 2,
				G_TYPE_ENUM, GTK_SCROLL_STEP_FORWARD,
				G_TYPE_FLOAT, 0.0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Right, 0,
				"scroll_horizontal", 2,
				G_TYPE_ENUM, GTK_SCROLL_STEP_FORWARD,
				G_TYPE_FLOAT, 0.0);

  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Home, 0,
				"scroll_horizontal", 2,
				G_TYPE_ENUM, GTK_SCROLL_JUMP,
				G_TYPE_FLOAT, 0.0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Home, 0,
				"scroll_horizontal", 2,
				G_TYPE_ENUM, GTK_SCROLL_JUMP,
				G_TYPE_FLOAT, 0.0);
  
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_End, 0,
				"scroll_horizontal", 2,
				G_TYPE_ENUM, GTK_SCROLL_JUMP,
				G_TYPE_FLOAT, 1.0);

  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_End, 0,
				"scroll_horizontal", 2,
				G_TYPE_ENUM, GTK_SCROLL_JUMP,
				G_TYPE_FLOAT, 1.0);
  
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Escape, 0,
				"undo_selection", 0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Escape, 0,
				"abort_column_resize", 0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_space, 0,
				"toggle_focus_row", 0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Space, 0,
				"toggle_focus_row", 0);  
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_space, GDK_CONTROL_MASK,
				"toggle_add_mode", 0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Space, GDK_CONTROL_MASK,
				"toggle_add_mode", 0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_slash, GDK_CONTROL_MASK,
				"select_all", 0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_KP_Divide, GDK_CONTROL_MASK,
				"select_all", 0);
  gtk_binding_entry_add_signal (binding_set, '\\', GDK_CONTROL_MASK,
				"unselect_all", 0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Shift_L,
				GDK_RELEASE_MASK | GDK_SHIFT_MASK,
				"end_selection", 0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Shift_R,
				GDK_RELEASE_MASK | GDK_SHIFT_MASK,
				"end_selection", 0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Shift_L,
				GDK_RELEASE_MASK | GDK_SHIFT_MASK |
				GDK_CONTROL_MASK,
				"end_selection", 0);
  gtk_binding_entry_add_signal (binding_set, GDK_KEY_Shift_R,
				GDK_RELEASE_MASK | GDK_SHIFT_MASK |
				GDK_CONTROL_MASK,
				"end_selection", 0);
}

static void
gtk_cmclist_set_arg (GObject *object,
				guint      arg_id,
				const GValue *value,
				GParamSpec *spec)
{
  GtkCMCList *clist;

  clist = GTK_CMCLIST (object);

  switch (arg_id)
    {
    case ARG_N_COLUMNS: /* only set at construction time */
      clist->columns = MAX (1, g_value_get_uint (value));
      break;
    case ARG_SHADOW_TYPE:
      gtk_cmclist_set_shadow_type (clist, g_value_get_enum (value));
      break;
    case ARG_SELECTION_MODE:
      gtk_cmclist_set_selection_mode (clist, g_value_get_enum (value));
      break;
    case ARG_ROW_HEIGHT:
      gtk_cmclist_set_row_height (clist, g_value_get_uint (value));
      break;
    case ARG_REORDERABLE:
      gtk_cmclist_set_reorderable (clist, g_value_get_boolean (value));
      break;
    case ARG_TITLES_ACTIVE:
      if (g_value_get_boolean (value))
	gtk_cmclist_column_titles_active (clist);
      else
	gtk_cmclist_column_titles_passive (clist);
      break;
    case ARG_USE_DRAG_ICONS:
      gtk_cmclist_set_use_drag_icons (clist, g_value_get_boolean (value));
      break;
    case ARG_SORT_TYPE:
      gtk_cmclist_set_sort_type (clist, g_value_get_enum (value));
      break;
    case ARG_HADJUSTMENT:
      gtk_cmclist_set_hadjustment (clist, g_value_get_object (value));
      break;
    case ARG_VADJUSTMENT:
      gtk_cmclist_set_vadjustment (clist, g_value_get_object (value));
      break;
    case ARG_HSCROLL_POLICY:
    case ARG_VSCROLL_POLICY:
      break;
    }
}

static void
gtk_cmclist_get_arg (GObject *object,
				guint      arg_id,
				GValue *value,
				GParamSpec *spec)
{
  GtkCMCList *clist;

  clist = GTK_CMCLIST (object);

  switch (arg_id)
    {
      guint i;

    case ARG_N_COLUMNS:
      g_value_set_uint(value, clist->columns);
      break;
    case ARG_SHADOW_TYPE:
      g_value_set_enum(value, clist->shadow_type);
      break;
    case ARG_SELECTION_MODE:
      g_value_set_enum(value, clist->selection_mode);
      break;
    case ARG_ROW_HEIGHT:
      g_value_set_uint(value, GTK_CMCLIST_ROW_HEIGHT_SET(clist) ? clist->row_height : 0);
      break;
    case ARG_REORDERABLE:
      g_value_set_boolean(value, GTK_CMCLIST_REORDERABLE (clist));
      break;
    case ARG_TITLES_ACTIVE:
      g_value_set_boolean(value, TRUE);
      for (i = 0; i < clist->columns; i++)
	if (clist->column[i].button &&
	    !gtk_widget_get_sensitive (clist->column[i].button))
	  {
	    g_value_set_boolean(value, FALSE);
	    break;
	  }
      break;
    case ARG_USE_DRAG_ICONS:
      g_value_set_boolean(value, GTK_CMCLIST_USE_DRAG_ICONS (clist));
      break;
    case ARG_SORT_TYPE:
      g_value_set_enum(value, clist->sort_type);
      break;
    case ARG_HADJUSTMENT:
      g_value_set_object(value, gtk_cmclist_get_hadjustment(clist));
      break;
    case ARG_VADJUSTMENT:
      g_value_set_object(value, gtk_cmclist_get_vadjustment(clist));
      break;
    case ARG_HSCROLL_POLICY:
    case ARG_VSCROLL_POLICY:
      g_value_set_enum(value, GTK_SCROLL_NATURAL);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, arg_id, spec);
      break;
    }
}

static void
gtk_cmclist_init (GtkCMCList *clist)
{
  clist->flags = 0;

  gtk_widget_set_has_window (GTK_WIDGET(clist), TRUE);
  gtk_widget_set_can_focus (GTK_WIDGET(clist), TRUE);
  GTK_CMCLIST_SET_FLAG (clist, CMCLIST_DRAW_DRAG_LINE);
  GTK_CMCLIST_SET_FLAG (clist, CMCLIST_USE_DRAG_ICONS);

  clist->freeze_count = 0;

  clist->rows = 0;
  clist->row_height = 0;
  clist->row_list = NULL;
  clist->row_list_end = NULL;

  clist->columns = 0;

  clist->title_window = NULL;
  clist->column_title_area.x = 0;
  clist->column_title_area.y = 0;
  clist->column_title_area.width = 1;
  clist->column_title_area.height = 1;

  clist->clist_window = NULL;
  clist->clist_window_width = 1;
  clist->clist_window_height = 1;

  clist->hoffset = 0;
  clist->voffset = 0;

  clist->shadow_type = GTK_SHADOW_IN;
  clist->vadjustment = NULL;
  clist->hadjustment = NULL;

  clist->button_actions[0] = GTK_CMBUTTON_SELECTS | GTK_CMBUTTON_DRAGS;
  clist->button_actions[1] = GTK_CMBUTTON_IGNORED;
  clist->button_actions[2] = GTK_CMBUTTON_IGNORED;
  clist->button_actions[3] = GTK_CMBUTTON_IGNORED;
  clist->button_actions[4] = GTK_CMBUTTON_IGNORED;

  clist->cursor_drag = NULL;
  clist->x_drag = 0;

  clist->selection_mode = GTK_SELECTION_SINGLE;
  clist->selection = NULL;
  clist->selection_end = NULL;
  clist->undo_selection = NULL;
  clist->undo_unselection = NULL;

  clist->focus_row = -1;
  clist->focus_header_column = -1;
  clist->undo_anchor = -1;

  clist->anchor = -1;
  clist->anchor_state = GTK_STATE_SELECTED;
  clist->drag_pos = -1;
  clist->htimer = 0;
  clist->vtimer = 0;

  clist->click_cell.row = -1;
  clist->click_cell.column = -1;

  clist->compare = default_compare;
  clist->sort_type = GTK_SORT_ASCENDING;
  clist->sort_column = 0;

  clist->drag_highlight_row = -1;
}

/* Constructor */
static GObject*
gtk_cmclist_constructor (GType                  type,
		       guint                  n_construct_properties,
		       GObjectConstructParam *construct_properties)
{
  GObject *object = G_OBJECT_CLASS (gtk_cmclist_parent_class)->constructor (type,
								n_construct_properties,
								construct_properties);
  GtkCMCList *clist = GTK_CMCLIST (object);
  
  /* allocate memory for columns */
  clist->column = columns_new (clist);
  
  /* there needs to be at least one column button 
   * because there is alot of code that will break if it
   * isn't there
   */
  column_button_create (clist, 0);

  clist->draw_now = 1;
  
  return object;
}

/* GTKCLIST PUBLIC INTERFACE
 *   gtk_cmclist_new
 *   gtk_cmclist_new_with_titles
 *   gtk_cmclist_set_hadjustment
 *   gtk_cmclist_set_vadjustment
 *   gtk_cmclist_get_hadjustment
 *   gtk_cmclist_get_vadjustment
 *   gtk_cmclist_set_shadow_type
 *   gtk_cmclist_set_selection_mode
 *   gtk_cmclist_freeze
 *   gtk_cmclist_thaw
 */
GtkWidget*
gtk_cmclist_new (gint columns)
{
  return gtk_cmclist_new_with_titles (columns, NULL);
}
 
GtkWidget*
gtk_cmclist_new_with_titles (gint   columns,
			   gchar *titles[])
{
  GtkCMCList *clist;

  clist = g_object_new (GTK_TYPE_CMCLIST,
			"n_columns", columns,
			NULL);
  if (titles)
    {
      guint i;

      for (i = 0; i < clist->columns; i++)
	gtk_cmclist_set_column_title (clist, i, titles[i]);
      gtk_cmclist_column_titles_show (clist);
    }
  else
    gtk_cmclist_column_titles_hide (clist);

  return GTK_WIDGET (clist);
}

void
gtk_cmclist_set_hadjustment (GtkCMCList      *clist,
			   GtkAdjustment *adjustment)
{
  GtkAdjustment *old_adjustment;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));
  if (adjustment)
    cm_return_if_fail (GTK_IS_ADJUSTMENT (adjustment));
  
  if (clist->hadjustment == adjustment)
    return;
  
  old_adjustment = clist->hadjustment;

  if (clist->hadjustment)
    {
      g_signal_handlers_disconnect_matched(G_OBJECT (clist->hadjustment), G_SIGNAL_MATCH_DATA,
		      	0, 0, 0, 0, clist);

      g_object_unref (G_OBJECT (clist->hadjustment));
    }

  clist->hadjustment = adjustment;

  if (clist->hadjustment)
    {
      g_object_ref_sink (clist->hadjustment);
      g_signal_connect (G_OBJECT (clist->hadjustment), "value_changed",
			  G_CALLBACK( hadjustment_value_changed),
			  (gpointer) clist);
    }

  if (!clist->hadjustment || !old_adjustment)
    gtk_widget_queue_resize (GTK_WIDGET (clist));
}

GtkAdjustment *
gtk_cmclist_get_hadjustment (GtkCMCList *clist)
{
  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), NULL);

  return clist->hadjustment;
}

void
gtk_cmclist_set_vadjustment (GtkCMCList      *clist,
			   GtkAdjustment *adjustment)
{
  GtkAdjustment *old_adjustment;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));
  if (adjustment)
    cm_return_if_fail (GTK_IS_ADJUSTMENT (adjustment));

  if (clist->vadjustment == adjustment)
    return;
  
  old_adjustment = clist->vadjustment;

  if (clist->vadjustment)
    {
      g_signal_handlers_disconnect_matched(G_OBJECT (clist->vadjustment), G_SIGNAL_MATCH_DATA,
		      	0, 0, 0, 0, clist);
      g_object_unref (G_OBJECT (clist->vadjustment));
    }

  clist->vadjustment = adjustment;

  if (clist->vadjustment)
    {
      g_object_ref_sink (clist->vadjustment);

      g_signal_connect (G_OBJECT (clist->vadjustment), "value_changed",
			  G_CALLBACK(vadjustment_value_changed),
			  (gpointer) clist);
    }

  if (!clist->vadjustment || !old_adjustment)
    gtk_widget_queue_resize (GTK_WIDGET (clist));
}

GtkAdjustment *
gtk_cmclist_get_vadjustment (GtkCMCList *clist)
{
  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), NULL);

  return clist->vadjustment;
}

void
gtk_cmclist_set_shadow_type (GtkCMCList      *clist,
			   GtkShadowType  type)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  clist->shadow_type = type;

  if (gtk_widget_get_visible (GTK_WIDGET(clist)))
    gtk_widget_queue_resize (GTK_WIDGET (clist));
}

void
gtk_cmclist_set_selection_mode (GtkCMCList         *clist,
			      GtkSelectionMode  mode)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));
  cm_return_if_fail (mode != GTK_SELECTION_NONE);

  if (mode == clist->selection_mode)
    return;

  clist->selection_mode = mode;
  clist->anchor = -1;
  clist->anchor_state = GTK_STATE_SELECTED;
  clist->drag_pos = -1;
  clist->undo_anchor = clist->focus_row;

  g_list_free (clist->undo_selection);
  g_list_free (clist->undo_unselection);
  clist->undo_selection = NULL;
  clist->undo_unselection = NULL;

  switch (mode)
    {
    case GTK_SELECTION_MULTIPLE:
      return;
    case GTK_SELECTION_BROWSE:
    case GTK_SELECTION_SINGLE:
      gtk_cmclist_unselect_all (clist);
      break;
    default:
      /* Someone set it by hand */
      g_assert_not_reached ();
    }
}

void
gtk_cmclist_freeze (GtkCMCList *clist)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  clist->freeze_count++;
}

void
gtk_cmclist_thaw (GtkCMCList *clist)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (clist->freeze_count)
    {
      clist->freeze_count--;
      CLIST_REFRESH (clist);
    }
}

/* PUBLIC COLUMN FUNCTIONS
 *   gtk_cmclist_column_titles_show
 *   gtk_cmclist_column_titles_hide
 *   gtk_cmclist_column_title_active
 *   gtk_cmclist_column_title_passive
 *   gtk_cmclist_column_titles_active
 *   gtk_cmclist_column_titles_passive
 *   gtk_cmclist_set_column_title
 *   gtk_cmclist_get_column_title
 *   gtk_cmclist_set_column_widget
 *   gtk_cmclist_set_column_justification
 *   gtk_cmclist_set_column_visibility
 *   gtk_cmclist_set_column_resizeable
 *   gtk_cmclist_set_column_auto_resize
 *   gtk_cmclist_optimal_column_width
 *   gtk_cmclist_set_column_width
 *   gtk_cmclist_set_column_min_width
 *   gtk_cmclist_set_column_max_width
 */
void
gtk_cmclist_column_titles_show (GtkCMCList *clist)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (!GTK_CMCLIST_SHOW_TITLES(clist))
    {
      GTK_CMCLIST_SET_FLAG (clist, CMCLIST_SHOW_TITLES);
      if (clist->title_window)
	gdk_window_show (clist->title_window);
      gtk_widget_queue_resize (GTK_WIDGET (clist));
    }
}

void 
gtk_cmclist_column_titles_hide (GtkCMCList *clist)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (GTK_CMCLIST_SHOW_TITLES(clist))
    {
      GTK_CMCLIST_UNSET_FLAG (clist, CMCLIST_SHOW_TITLES);
      if (clist->title_window)
	gdk_window_hide (clist->title_window);
      gtk_widget_queue_resize (GTK_WIDGET (clist));
    }
}

void
gtk_cmclist_column_title_active (GtkCMCList *clist,
			       gint      column)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (column < 0 || column >= clist->columns)
    return;
  if (!clist->column[column].button || !clist->column[column].button_passive)
    return;

  clist->column[column].button_passive = FALSE;

  g_signal_handlers_disconnect_matched(G_OBJECT (clist->column[column].button), G_SIGNAL_MATCH_FUNC,
		    0, 0, 0, column_title_passive_func, 0);

  gtk_widget_set_can_focus (clist->column[column].button, TRUE);
  if (gtk_widget_get_visible (GTK_WIDGET(clist)))
    gtk_widget_queue_draw (clist->column[column].button);
}

void
gtk_cmclist_column_title_passive (GtkCMCList *clist,
				gint      column)
{
  GtkToggleButton *button;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (column < 0 || column >= clist->columns)
    return;
  if (!clist->column[column].button || clist->column[column].button_passive)
    return;

  button = GTK_TOGGLE_BUTTON (clist->column[column].button);

  clist->column[column].button_passive = TRUE;

  if (gtk_toggle_button_get_active(button))
	g_signal_connect(G_OBJECT (clist->column[column].button),
			 "button-release-event",
			 G_CALLBACK(column_title_passive_func),
			 NULL);
  if (gtk_widget_is_focus(gtk_bin_get_child(GTK_BIN(button))))
	g_signal_connect(G_OBJECT (clist->column[column].button),
			 "leave-notify-event",
			 G_CALLBACK(column_title_passive_func),
			 NULL);

  g_signal_connect (G_OBJECT (clist->column[column].button), "event",
		      G_CALLBACK(column_title_passive_func), NULL);

  gtk_widget_set_can_focus (clist->column[column].button, FALSE);
  if (gtk_widget_get_visible (GTK_WIDGET(clist)))
    gtk_widget_queue_draw (clist->column[column].button);
}

void
gtk_cmclist_column_titles_active (GtkCMCList *clist)
{
  gint i;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  for (i = 0; i < clist->columns; i++)
    gtk_cmclist_column_title_active (clist, i);
}

void
gtk_cmclist_column_titles_passive (GtkCMCList *clist)
{
  gint i;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  for (i = 0; i < clist->columns; i++)
    gtk_cmclist_column_title_passive (clist, i);
}

void
gtk_cmclist_set_column_title (GtkCMCList    *clist,
			    gint         column,
			    const gchar *title)
{
  gint new_button = 0;
  GtkWidget *old_widget;
  GtkWidget *alignment = NULL;
  GtkWidget *label;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (column < 0 || column >= clist->columns)
    return;

  /* if the column button doesn't currently exist,
   * it has to be created first */
  if (!clist->column[column].button)
    {
      column_button_create (clist, column);
      new_button = 1;
    }

  column_title_new (clist, column, title);

  /* remove and destroy the old widget */
  old_widget = gtk_bin_get_child (GTK_BIN (clist->column[column].button));
  if (old_widget)
    gtk_container_remove (GTK_CONTAINER (clist->column[column].button), old_widget);

  /* create new alignment based no column justification */
  switch (clist->column[column].justification)
    {
    case GTK_JUSTIFY_LEFT:
      alignment = gtk_alignment_new (0.0, 0.5, 0.0, 0.0);
      break;

    case GTK_JUSTIFY_RIGHT:
      alignment = gtk_alignment_new (1.0, 0.5, 0.0, 0.0);
      break;

    case GTK_JUSTIFY_CENTER:
      alignment = gtk_alignment_new (0.5, 0.5, 0.0, 0.0);
      break;

    case GTK_JUSTIFY_FILL:
      alignment = gtk_alignment_new (0.5, 0.5, 0.0, 0.0);
      break;
    }

  gtk_widget_push_composite_child ();
  label = gtk_label_new (clist->column[column].title);
  gtk_widget_pop_composite_child ();
  gtk_container_add (GTK_CONTAINER (alignment), label);
  gtk_container_add (GTK_CONTAINER (clist->column[column].button), alignment);
  gtk_widget_show (label);
  gtk_widget_show (alignment);

  /* if this button didn't previously exist, then the
   * column button positions have to be re-computed */
  if (gtk_widget_get_visible (GTK_WIDGET(clist)) && new_button)
    size_allocate_title_buttons (clist);
}

gchar *
gtk_cmclist_get_column_title (GtkCMCList *clist,
			    gint      column)
{
  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), NULL);

  if (column < 0 || column >= clist->columns)
    return NULL;

  return clist->column[column].title;
}

void
gtk_cmclist_set_column_widget (GtkCMCList  *clist,
			     gint       column,
			     GtkWidget *widget)
{
  gint new_button = 0;
  GtkWidget *old_widget;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (column < 0 || column >= clist->columns)
    return;

  /* if the column button doesn't currently exist,
   * it has to be created first */
  if (!clist->column[column].button)
    {
      column_button_create (clist, column);
      new_button = 1;
    }

  column_title_new (clist, column, NULL);

  /* remove and destroy the old widget */
  old_widget = gtk_bin_get_child (GTK_BIN (clist->column[column].button));
  if (old_widget)
    gtk_container_remove (GTK_CONTAINER (clist->column[column].button),
			  old_widget);

  /* add and show the widget */
  if (widget)
    {
      gtk_container_add (GTK_CONTAINER (clist->column[column].button), widget);
      gtk_widget_show (widget);
    }

  /* if this button didn't previously exist, then the
   * column button positions have to be re-computed */
  if (gtk_widget_get_visible (GTK_WIDGET(clist)) && new_button)
    size_allocate_title_buttons (clist);
}

GtkWidget *
gtk_cmclist_get_column_widget (GtkCMCList *clist,
			     gint      column)
{
  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), NULL);

  if (column < 0 || column >= clist->columns)
    return NULL;

  if (clist->column[column].button)
	return gtk_bin_get_child (GTK_BIN (clist->column[column].button));

  return NULL;
}

void
gtk_cmclist_set_column_justification (GtkCMCList         *clist,
				    gint              column,
				    GtkJustification  justification)
{
  GtkWidget *alignment;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (column < 0 || column >= clist->columns)
    return;

  clist->column[column].justification = justification;

  /* change the alinment of the button title if it's not a
   * custom widget */
  if (clist->column[column].title)
    {
      alignment = gtk_bin_get_child (GTK_BIN (clist->column[column].button));

      switch (clist->column[column].justification)
	{
	case GTK_JUSTIFY_LEFT:
	  gtk_alignment_set (GTK_ALIGNMENT (alignment), 0.0, 0.5, 0.0, 0.0);
	  break;

	case GTK_JUSTIFY_RIGHT:
	  gtk_alignment_set (GTK_ALIGNMENT (alignment), 1.0, 0.5, 0.0, 0.0);
	  break;

	case GTK_JUSTIFY_CENTER:
	  gtk_alignment_set (GTK_ALIGNMENT (alignment), 0.5, 0.5, 0.0, 0.0);
	  break;

	case GTK_JUSTIFY_FILL:
	  gtk_alignment_set (GTK_ALIGNMENT (alignment), 0.5, 0.5, 0.0, 0.0);
	  break;

	default:
	  break;
	}
    }

  if (CLIST_UNFROZEN (clist))
    draw_rows (clist, NULL);
}

void
gtk_cmclist_set_column_visibility (GtkCMCList *clist,
				 gint      column,
				 gboolean  visible)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (column < 0 || column >= clist->columns)
    return;
  if (clist->column[column].visible == visible)
    return;

  /* don't hide last visible column */
  if (!visible)
    {
      gint i;
      gint vis_columns = 0;

      for (i = 0, vis_columns = 0; i < clist->columns && vis_columns < 2; i++)
	if (clist->column[i].visible)
	  vis_columns++;

      if (vis_columns < 2)
	return;
    }

  clist->column[column].visible = visible;

  if (clist->column[column].button)
    {
      if (visible)
	gtk_widget_show (clist->column[column].button);
      else
	gtk_widget_hide (clist->column[column].button);
    }
  
  gtk_widget_queue_resize (GTK_WIDGET(clist));
}

void
gtk_cmclist_set_column_resizeable (GtkCMCList *clist,
				 gint      column,
				 gboolean  resizeable)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (column < 0 || column >= clist->columns)
    return;
  if (clist->column[column].resizeable == resizeable)
    return;

  clist->column[column].resizeable = resizeable;
  if (resizeable)
    clist->column[column].auto_resize = FALSE;

  if (gtk_widget_get_visible (GTK_WIDGET(clist)))
    size_allocate_title_buttons (clist);
}

void
gtk_cmclist_set_column_auto_resize (GtkCMCList *clist,
				  gint      column,
				  gboolean  auto_resize)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (column < 0 || column >= clist->columns)
    return;
  if (clist->column[column].auto_resize == auto_resize)
    return;

  clist->column[column].auto_resize = auto_resize;
  if (auto_resize)
    {
      clist->column[column].resizeable = FALSE;
      if (!GTK_CMCLIST_AUTO_RESIZE_BLOCKED (clist))
	{
	  gint width;

	  width = gtk_cmclist_optimal_column_width (clist, column);
	  gtk_cmclist_set_column_width (clist, column, width);
	}
    }

  if (gtk_widget_get_visible (GTK_WIDGET(clist)))
    size_allocate_title_buttons (clist);
}

gint
gtk_cmclist_columns_autosize (GtkCMCList *clist)
{
  gint i;
  gint width;

  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), 0);

  gtk_cmclist_freeze (clist);
  width = 0;
  for (i = 0; i < clist->columns; i++)
    {
      gtk_cmclist_set_column_width (clist, i,
				  gtk_cmclist_optimal_column_width (clist, i));

      width += clist->column[i].width;
    }

  gtk_cmclist_thaw (clist);
  return width;
}

gint
gtk_cmclist_optimal_column_width (GtkCMCList *clist,
				gint      column)
{
  GtkRequisition requisition;
  GList *list;
  gint width;

  cm_return_val_if_fail (GTK_CMCLIST (clist), 0);

  if (column < 0 || column >= clist->columns)
    return 0;

  if (GTK_CMCLIST_SHOW_TITLES(clist) && clist->column[column].button)
    {
      gtk_widget_get_requisition (clist->column[column].button, &requisition);
      width = requisition.width
#if 0
	     (CELL_SPACING + (2 * COLUMN_INSET)))
#endif
		;
    }
  else
    width = 0;

  for (list = clist->row_list; list; list = list->next)
    {
  GTK_CMCLIST_GET_CLASS (clist)->cell_size_request
	(clist, GTK_CMCLIST_ROW (list), column, &requisition);
      width = MAX (width, requisition.width);
    }

  return width;
}

void
gtk_cmclist_set_column_width (GtkCMCList *clist,
			    gint      column,
			    gint      width)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (column < 0 || column >= clist->columns)
    return;

  g_signal_emit (G_OBJECT (clist), clist_signals[RESIZE_COLUMN], 0,
		   column, width);
}

void
gtk_cmclist_set_column_min_width (GtkCMCList *clist,
				gint      column,
				gint      min_width)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (column < 0 || column >= clist->columns)
    return;
  if (clist->column[column].min_width == min_width)
    return;

  if (clist->column[column].max_width >= 0  &&
      clist->column[column].max_width < min_width)
    clist->column[column].min_width = clist->column[column].max_width;
  else
    clist->column[column].min_width = min_width;

  if (clist->column[column].area.width < clist->column[column].min_width)
    gtk_cmclist_set_column_width (clist, column,clist->column[column].min_width);
}

void
gtk_cmclist_set_column_max_width (GtkCMCList *clist,
				gint      column,
				gint      max_width)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (column < 0 || column >= clist->columns)
    return;
  if (clist->column[column].max_width == max_width)
    return;

  if (clist->column[column].min_width >= 0 && max_width >= 0 &&
      clist->column[column].min_width > max_width)
    clist->column[column].max_width = clist->column[column].min_width;
  else
    clist->column[column].max_width = max_width;
  
  if (clist->column[column].area.width > clist->column[column].max_width)
    gtk_cmclist_set_column_width (clist, column,clist->column[column].max_width);
}

/* PRIVATE COLUMN FUNCTIONS
 *   column_auto_resize
 *   real_resize_column
 *   abort_column_resize
 *   size_allocate_title_buttons
 *   size_allocate_columns
 *   list_requisition_width
 *   new_column_width
 *   column_button_create
 *   column_button_clicked
 *   column_title_passive_func
 */
static void
column_auto_resize (GtkCMCList    *clist,
		    GtkCMCListRow *clist_row,
		    gint         column,
		    gint         old_width)
{
  /* resize column if needed for auto_resize */
  GtkRequisition requisition;

  if (!clist->column[column].auto_resize ||
      GTK_CMCLIST_AUTO_RESIZE_BLOCKED (clist))
    return;

  if (clist_row)
    GTK_CMCLIST_GET_CLASS (clist)->cell_size_request (clist, clist_row,
						   column, &requisition);
  else
    requisition.width = 0;

  if (requisition.width > clist->column[column].width)
    gtk_cmclist_set_column_width (clist, column, requisition.width);
  else if (requisition.width < old_width &&
	   old_width == clist->column[column].width)
    {
      GList *list;
      gint new_width = 0;

      /* run a "gtk_cmclist_optimal_column_width" but break, if
       * the column doesn't shrink */
      if (GTK_CMCLIST_SHOW_TITLES(clist) && clist->column[column].button)
    {
	gtk_widget_get_requisition (clist->column[column].button, &requisition);
	new_width = (requisition.width -
		     (CELL_SPACING + (2 * COLUMN_INSET)));
    }
      else
	new_width = 0;

      for (list = clist->row_list; list; list = list->next)
	{
	  GTK_CMCLIST_GET_CLASS (clist)->cell_size_request
	    (clist, GTK_CMCLIST_ROW (list), column, &requisition);
	  new_width = MAX (new_width, requisition.width);
	  if (new_width == clist->column[column].width)
	    break;
	}
      if (new_width < clist->column[column].width)
	gtk_cmclist_set_column_width
	  (clist, column, MAX (new_width, clist->column[column].min_width));
    }
}

static void
real_resize_column (GtkCMCList *clist,
		    gint      column,
		    gint      width)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (column < 0 || column >= clist->columns)
    return;
  
  if (width < MAX (COLUMN_MIN_WIDTH, clist->column[column].min_width))
    width = MAX (COLUMN_MIN_WIDTH, clist->column[column].min_width);
  if (clist->column[column].max_width >= 0 &&
      width > clist->column[column].max_width)
    width = clist->column[column].max_width;

  clist->column[column].width = width;
  clist->column[column].width_set = TRUE;

  /* FIXME: this is quite expensive to do if the widget hasn't
   *        been size_allocated yet, and pointless. Should
   *        a flag be kept
   */
  size_allocate_columns (clist, TRUE);
  size_allocate_title_buttons (clist);

  CLIST_REFRESH (clist);
}

static void
abort_column_resize (GtkCMCList *clist)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (!GTK_CMCLIST_IN_DRAG(clist))
    return;

  GTK_CMCLIST_UNSET_FLAG (clist, CMCLIST_IN_DRAG);
  gtk_grab_remove (GTK_WIDGET (clist));
  gdk_display_pointer_ungrab (gtk_widget_get_display (GTK_WIDGET (clist)),
			      GDK_CURRENT_TIME);
  clist->drag_pos = -1;

  if (clist->x_drag >= 0 && clist->x_drag <= clist->clist_window_width - 1)
    clist_refresh(clist);
}

static void
size_allocate_title_buttons (GtkCMCList *clist)
{
  GtkAllocation button_allocation;
  gint last_column;
  gint last_button = 0;
  gint i;

  if (!gtk_widget_get_realized (GTK_WIDGET(clist)))
    return;

	/* we're too early, the widget is not yet ready */
	if (clist->column_title_area.height <= 1)
		return;

  button_allocation.x = clist->hoffset;
  button_allocation.y = 0;
  button_allocation.width = 0;
  button_allocation.height = clist->column_title_area.height;

  /* find last visible column */
  for (last_column = clist->columns - 1; last_column >= 0; last_column--)
    if (clist->column[last_column].visible)
      break;

  for (i = 0; i < last_column; i++)
    {
      if (!clist->column[i].visible)
	{
	  last_button = i + 1;
	  gdk_window_hide (clist->column[i].window);
	  continue;
	}

      button_allocation.width += (clist->column[i].area.width +
				  CELL_SPACING + 2 * COLUMN_INSET);

      if (!clist->column[i + 1].button)
	{
	  gdk_window_hide (clist->column[i].window);
	  continue;
	}

      gtk_widget_size_allocate (clist->column[last_button].button,
				&button_allocation);
      button_allocation.x += button_allocation.width;
      button_allocation.width = 0;

      if (clist->column[last_button].resizeable)
	{
	  gdk_window_show (clist->column[last_button].window);
	  gdk_window_move_resize (clist->column[last_button].window,
				  button_allocation.x - (DRAG_WIDTH / 2), 
				  0, DRAG_WIDTH,
				  clist->column_title_area.height);
	}
      else
	gdk_window_hide (clist->column[last_button].window);

      last_button = i + 1;
    }

  button_allocation.width += (clist->column[last_column].area.width +
			      2 * (CELL_SPACING + COLUMN_INSET));
  gtk_widget_size_allocate (clist->column[last_button].button,
			    &button_allocation);

  if (clist->column[last_button].resizeable)
    {
      button_allocation.x += button_allocation.width;

      gdk_window_show (clist->column[last_button].window);
      gdk_window_move_resize (clist->column[last_button].window,
			      button_allocation.x - (DRAG_WIDTH / 2), 
			      0, DRAG_WIDTH, clist->column_title_area.height);
    }
  else
    gdk_window_hide (clist->column[last_button].window);
}

static void
size_allocate_columns (GtkCMCList *clist,
		       gboolean  block_resize)
{
  GtkRequisition requisition;
  gint xoffset = CELL_SPACING + COLUMN_INSET;
  gint last_column;
  gint i;

  /* find last visible column and calculate correct column width */
  for (last_column = clist->columns - 1;
       last_column >= 0 && !clist->column[last_column].visible; last_column--);

  if (last_column < 0)
    return;

  for (i = 0; i <= last_column; i++)
    {
      if (!clist->column[i].visible)
	continue;
      clist->column[i].area.x = xoffset;
      if (clist->column[i].width_set)
	{
	  if (!block_resize && GTK_CMCLIST_SHOW_TITLES(clist) &&
	      clist->column[i].auto_resize && clist->column[i].button)
	    {
	      gint width;

	      gtk_widget_get_requisition (clist->column[i].button, &requisition);
	      width = (requisition.width -
		       (CELL_SPACING + (2 * COLUMN_INSET)));

	      if (width > clist->column[i].width)
		gtk_cmclist_set_column_width (clist, i, width);
	    }

	  clist->column[i].area.width = clist->column[i].width;
	  xoffset += clist->column[i].width + CELL_SPACING + (2* COLUMN_INSET);
	}
      else if (GTK_CMCLIST_SHOW_TITLES(clist) && clist->column[i].button)
	{
	  gtk_widget_get_requisition (clist->column[i].button, &requisition);
	  clist->column[i].area.width =
	    requisition.width -
	    (CELL_SPACING + (2 * COLUMN_INSET));
	  xoffset += requisition.width;
	}
    }

  clist->column[last_column].area.width = clist->column[last_column].area.width
    + MAX (0, clist->clist_window_width + COLUMN_INSET - xoffset);
}

static gint
list_requisition_width (GtkCMCList *clist) 
{
  GtkRequisition requisition;
  gint width = CELL_SPACING;
  gint i;

  for (i = clist->columns - 1; i >= 0; i--)
    {
      if (!clist->column[i].visible)
	continue;

      if (clist->column[i].width_set)
	width += clist->column[i].width + CELL_SPACING + (2 * COLUMN_INSET);
      else if (GTK_CMCLIST_SHOW_TITLES(clist) && clist->column[i].button)
    {
	gtk_widget_get_requisition (clist->column[i].button, &requisition);
	width += requisition.width;
    }
    }

  return width;
}

/* this function returns the new width of the column being resized given
 * the column and x position of the cursor; the x cursor position is passed
 * in as a pointer and automagicly corrected if it's beyond min/max limits */
static gint
new_column_width (GtkCMCList *clist,
		  gint      column,
		  gint     *x)
{
  gint xthickness = gtk_widget_get_style (GTK_WIDGET (clist))->xthickness;
  gint width;
  gint cx;
  gint dx;
  gint last_column;

  /* first translate the x position from widget->window
   * to clist->clist_window */
  cx = *x - xthickness;

  for (last_column = clist->columns - 1;
       last_column >= 0 && !clist->column[last_column].visible; last_column--);

  /* calculate new column width making sure it doesn't end up
   * less than the minimum width */
  dx = (COLUMN_LEFT_XPIXEL (clist, column) + COLUMN_INSET +
	(column < last_column) * CELL_SPACING);
  width = cx - dx;

  if (width < MAX (COLUMN_MIN_WIDTH, clist->column[column].min_width))
    {
      width = MAX (COLUMN_MIN_WIDTH, clist->column[column].min_width);
      cx = dx + width;
      *x = cx + xthickness;
    }
  else if (clist->column[column].max_width >= COLUMN_MIN_WIDTH &&
	   width > clist->column[column].max_width)
    {
      width = clist->column[column].max_width;
      cx = dx + clist->column[column].max_width;
      *x = cx + xthickness;
    }      

  if (cx < 0 || cx > clist->clist_window_width)
    *x = -1;

  return width;
}

static void
column_button_create (GtkCMCList *clist,
		      gint      column)
{
  GtkWidget *button;

  gtk_widget_push_composite_child ();
  button = clist->column[column].button = gtk_button_new ();
  GtkRcStyle *style = gtk_rc_style_new();
  style->ythickness = 0;
  gtk_widget_modify_style(clist->column[column].button, style);
  g_object_unref(style);
  gtk_container_set_border_width(GTK_CONTAINER(button), 0);
  gtk_widget_pop_composite_child ();

  if (gtk_widget_get_realized (GTK_WIDGET(clist)) && clist->title_window)
    gtk_widget_set_parent_window (clist->column[column].button,
				  clist->title_window);
  gtk_widget_set_parent (button, GTK_WIDGET (clist));

  g_signal_connect (G_OBJECT (button), "clicked",
		      G_CALLBACK(column_button_clicked),
		      (gpointer) clist);
  gtk_widget_show (button);
}

static void
column_button_clicked (GtkWidget *widget,
		       gpointer   data)
{
  gint i;
  GtkCMCList *clist;

  cm_return_if_fail (widget != NULL);
  cm_return_if_fail (GTK_IS_CMCLIST (data));

  clist = GTK_CMCLIST (data);

  /* find the column who's button was pressed */
  for (i = 0; i < clist->columns; i++)
    if (clist->column[i].button == widget)
      break;

  g_signal_emit (G_OBJECT (clist), clist_signals[CLICK_COLUMN], 0, i);
}

static gint
column_title_passive_func (GtkWidget *widget, 
			   GdkEvent  *event,
			   gpointer   data)
{
  cm_return_val_if_fail (event != NULL, FALSE);
  
  switch (event->type)
    {
    case GDK_MOTION_NOTIFY:
    case GDK_BUTTON_PRESS:
    case GDK_2BUTTON_PRESS:
    case GDK_3BUTTON_PRESS:
    case GDK_BUTTON_RELEASE:
    case GDK_ENTER_NOTIFY:
    case GDK_LEAVE_NOTIFY:
      return TRUE;
    default:
      break;
    }
  return FALSE;
}


/* PUBLIC CELL FUNCTIONS
 *   gtk_cmclist_get_cell_type
 *   gtk_cmclist_set_text
 *   gtk_cmclist_get_text
 *   gtk_cmclist_set_pixbuf
 *   gtk_cmclist_get_pixbuf
 *   gtk_cmclist_set_pixtext
 *   gtk_cmclist_get_pixtext
 *   gtk_cmclist_set_shift
 */
GtkCMCellType 
gtk_cmclist_get_cell_type (GtkCMCList *clist,
			 gint      row,
			 gint      column)
{
  GtkCMCListRow *clist_row;

  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), -1);

  if (row < 0 || row >= clist->rows)
    return -1;
  if (column < 0 || column >= clist->columns)
    return -1;

  clist_row = ROW_ELEMENT (clist, row)->data;

  return clist_row->cell[column].type;
}

void
gtk_cmclist_set_text (GtkCMCList    *clist,
		    gint         row,
		    gint         column,
		    const gchar *text)
{
  GtkCMCListRow *clist_row;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (row < 0 || row >= clist->rows)
    return;
  if (column < 0 || column >= clist->columns)
    return;

  clist_row = ROW_ELEMENT (clist, row)->data;

  /* if text is null, then the cell is empty */
  GTK_CMCLIST_GET_CLASS (clist)->set_cell_contents
    (clist, clist_row, column, GTK_CMCELL_TEXT, text, 0, NULL);

  /* redraw the list if it's not frozen */
  if (CLIST_UNFROZEN (clist))
    {
      if (gtk_cmclist_row_is_visible (clist, row) != GTK_VISIBILITY_NONE)
	GTK_CMCLIST_GET_CLASS (clist)->draw_row (clist, NULL, row, clist_row);
    }
}

gint
gtk_cmclist_get_text (GtkCMCList  *clist,
		    gint       row,
		    gint       column,
		    gchar    **text)
{
  GtkCMCListRow *clist_row;

  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), 0);

  if (row < 0 || row >= clist->rows)
    return 0;
  if (column < 0 || column >= clist->columns)
    return 0;

  clist_row = ROW_ELEMENT (clist, row)->data;

  if (clist_row->cell[column].type != GTK_CMCELL_TEXT)
    return 0;

  if (text)
    *text = GTK_CMCELL_TEXT (clist_row->cell[column])->text;

  return 1;
}

void
gtk_cmclist_set_pixbuf (GtkCMCList  *clist,
		      gint       row,
		      gint       column,
		      GdkPixbuf *pixbuf)
{
  GtkCMCListRow *clist_row;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (row < 0 || row >= clist->rows)
    return;
  if (column < 0 || column >= clist->columns)
    return;

  clist_row = ROW_ELEMENT (clist, row)->data;
  
  g_object_ref (pixbuf);
  
  GTK_CMCLIST_GET_CLASS (clist)->set_cell_contents
    (clist, clist_row, column, GTK_CMCELL_PIXBUF, NULL, 0, pixbuf);

  /* redraw the list if it's not frozen */
  if (CLIST_UNFROZEN (clist))
    {
      if (gtk_cmclist_row_is_visible (clist, row) != GTK_VISIBILITY_NONE)
	GTK_CMCLIST_GET_CLASS (clist)->draw_row (clist, NULL, row, clist_row);
    }
}

gint
gtk_cmclist_get_pixbuf (GtkCMCList   *clist,
		      gint        row,
		      gint        column,
		      GdkPixbuf **pixbuf)
{
  GtkCMCListRow *clist_row;

  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), 0);

  if (row < 0 || row >= clist->rows)
    return 0;
  if (column < 0 || column >= clist->columns)
    return 0;

  clist_row = ROW_ELEMENT (clist, row)->data;

  if (clist_row->cell[column].type != GTK_CMCELL_PIXBUF)
    return 0;

  if (pixbuf)
  {
    *pixbuf = GTK_CMCELL_PIXBUF (clist_row->cell[column])->pixbuf;
  }

  return 1;
}

void
gtk_cmclist_set_pixtext (GtkCMCList    *clist,
		       gint         row,
		       gint         column,
		       const gchar *text,
		       guint8       spacing,
		       GdkPixbuf   *pixbuf)
{
  GtkCMCListRow *clist_row;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (row < 0 || row >= clist->rows)
    return;
  if (column < 0 || column >= clist->columns)
    return;

  clist_row = ROW_ELEMENT (clist, row)->data;
  
  g_object_ref (pixbuf);
  GTK_CMCLIST_GET_CLASS (clist)->set_cell_contents
    (clist, clist_row, column, GTK_CMCELL_PIXTEXT, text, spacing, pixbuf);

  /* redraw the list if it's not frozen */
  if (CLIST_UNFROZEN (clist))
    {
      if (gtk_cmclist_row_is_visible (clist, row) != GTK_VISIBILITY_NONE)
	GTK_CMCLIST_GET_CLASS (clist)->draw_row (clist, NULL, row, clist_row);
    }
}

gint
gtk_cmclist_get_pixtext (GtkCMCList   *clist,
		       gint        row,
		       gint        column,
		       gchar     **text,
		       guint8     *spacing,
		       GdkPixbuf **pixbuf)
{
  GtkCMCListRow *clist_row;

  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), 0);

  if (row < 0 || row >= clist->rows)
    return 0;
  if (column < 0 || column >= clist->columns)
    return 0;

  clist_row = ROW_ELEMENT (clist, row)->data;

  if (clist_row->cell[column].type != GTK_CMCELL_PIXTEXT)
    return 0;

  if (text)
    *text = GTK_CMCELL_PIXTEXT (clist_row->cell[column])->text;
  if (spacing)
    *spacing = GTK_CMCELL_PIXTEXT (clist_row->cell[column])->spacing;
  if (pixbuf)
    *pixbuf = GTK_CMCELL_PIXTEXT (clist_row->cell[column])->pixbuf;

  return 1;
}

void
gtk_cmclist_set_shift (GtkCMCList *clist,
		     gint      row,
		     gint      column,
		     gint      vertical,
		     gint      horizontal)
{
  GtkRequisition requisition = { 0 };
  GtkCMCListRow *clist_row;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (row < 0 || row >= clist->rows)
    return;
  if (column < 0 || column >= clist->columns)
    return;

  clist_row = ROW_ELEMENT (clist, row)->data;

  if (clist->column[column].auto_resize &&
      !GTK_CMCLIST_AUTO_RESIZE_BLOCKED (clist))
    GTK_CMCLIST_GET_CLASS (clist)->cell_size_request (clist, clist_row,
						   column, &requisition);

  clist_row->cell[column].vertical = vertical;
  clist_row->cell[column].horizontal = horizontal;

  column_auto_resize (clist, clist_row, column, requisition.width);

  if (CLIST_UNFROZEN (clist) && gtk_cmclist_row_is_visible (clist, row) != GTK_VISIBILITY_NONE)
    GTK_CMCLIST_GET_CLASS (clist)->draw_row (clist, NULL, row, clist_row);
}

/* PRIVATE CELL FUNCTIONS
 *   set_cell_contents
 *   cell_size_request
 */
static void
set_cell_contents (GtkCMCList    *clist,
		   GtkCMCListRow *clist_row,
		   gint         column,
		   GtkCMCellType  type,
		   const gchar *text,
		   guint8       spacing,
		   GdkPixbuf   *pixbuf)
{
  GtkRequisition requisition;
  gchar *old_text = NULL;
  GdkPixbuf *old_pixbuf = NULL;
  
  cm_return_if_fail (GTK_IS_CMCLIST (clist));
  cm_return_if_fail (clist_row != NULL);

  if (clist->column[column].auto_resize &&
      !GTK_CMCLIST_AUTO_RESIZE_BLOCKED (clist))
    GTK_CMCLIST_GET_CLASS (clist)->cell_size_request (clist, clist_row,
						   column, &requisition);

  switch (clist_row->cell[column].type)
    {
    case GTK_CMCELL_EMPTY:
      break;
    case GTK_CMCELL_TEXT:
      old_text = GTK_CMCELL_TEXT (clist_row->cell[column])->text;
      break;
    case GTK_CMCELL_PIXBUF:
      old_pixbuf = GTK_CMCELL_PIXBUF (clist_row->cell[column])->pixbuf;
      break;
    case GTK_CMCELL_PIXTEXT:
      old_text = GTK_CMCELL_PIXTEXT (clist_row->cell[column])->text;
      old_pixbuf = GTK_CMCELL_PIXTEXT (clist_row->cell[column])->pixbuf;
      break;
    case GTK_CMCELL_WIDGET:
      /* unimplemented */
      break;
    default:
      break;
    }

  clist_row->cell[column].type = GTK_CMCELL_EMPTY;

  /* Note that pixbuf and mask were already ref'ed by the caller
   */
  switch (type)
    {
    case GTK_CMCELL_TEXT:
      if (text)
	{
	  clist_row->cell[column].type = GTK_CMCELL_TEXT;
	  GTK_CMCELL_TEXT (clist_row->cell[column])->text = g_strdup (text);
	}
      break;
    case GTK_CMCELL_PIXBUF:
      if (pixbuf)
	{
	  clist_row->cell[column].type = GTK_CMCELL_PIXBUF;
	  GTK_CMCELL_PIXBUF (clist_row->cell[column])->pixbuf = pixbuf;
	}
      break;
    case GTK_CMCELL_PIXTEXT:
      if (text && pixbuf)
	{
	  clist_row->cell[column].type = GTK_CMCELL_PIXTEXT;
	  GTK_CMCELL_PIXTEXT (clist_row->cell[column])->text = g_strdup (text);
	  GTK_CMCELL_PIXTEXT (clist_row->cell[column])->spacing = spacing;
	  GTK_CMCELL_PIXTEXT (clist_row->cell[column])->pixbuf = pixbuf;
	}
      break;
    default:
      break;
    }

  if (clist->column[column].auto_resize &&
      !GTK_CMCLIST_AUTO_RESIZE_BLOCKED (clist))
    column_auto_resize (clist, clist_row, column, requisition.width);

  g_free (old_text);
  if (old_pixbuf)
    g_object_unref (old_pixbuf);
}

PangoLayout *
_gtk_cmclist_create_cell_layout (GtkCMCList       *clist,
			       GtkCMCListRow    *clist_row,
			       gint            column)
{
  PangoLayout *layout;
  GtkStyle *style;
  GtkCMCell *cell;
  gchar *text;
  
  get_cell_style (clist, clist_row, GTK_STATE_NORMAL, column, &style);


  cell = &clist_row->cell[column];
  switch (cell->type)
    {
    case GTK_CMCELL_TEXT:
    case GTK_CMCELL_PIXTEXT:
      text = ((cell->type == GTK_CMCELL_PIXTEXT) ?
	      GTK_CMCELL_PIXTEXT (*cell)->text :
	      GTK_CMCELL_TEXT (*cell)->text);

      if (!text)
	return NULL;
      
      layout = gtk_widget_create_pango_layout (GTK_WIDGET (clist),
					       ((cell->type == GTK_CMCELL_PIXTEXT) ?
						GTK_CMCELL_PIXTEXT (*cell)->text :
						GTK_CMCELL_TEXT (*cell)->text));
      pango_layout_set_font_description (layout, style->font_desc);
      
      return layout;
      
    default:
      return NULL;
    }
}

static void
cell_size_request (GtkCMCList       *clist,
		   GtkCMCListRow    *clist_row,
		   gint            column,
		   GtkRequisition *requisition)
{
  gint width;
  gint height;
  PangoLayout *layout;
  PangoRectangle logical_rect;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));
  cm_return_if_fail (requisition != NULL);

  layout = _gtk_cmclist_create_cell_layout (clist, clist_row, column);
  if (layout)
    {
      pango_layout_get_pixel_extents (layout, NULL, &logical_rect);
      
      requisition->width = logical_rect.width;
      requisition->height = logical_rect.height;
      
      g_object_unref (G_OBJECT (layout));
    }
  else
    {
      requisition->width  = 0;
      requisition->height = 0;
    }

  if (layout && clist_row->cell[column].type == GTK_CMCELL_PIXTEXT)
    requisition->width += GTK_CMCELL_PIXTEXT (clist_row->cell[column])->spacing;

  switch (clist_row->cell[column].type)
    {
    case GTK_CMCELL_PIXTEXT:
      width = gdk_pixbuf_get_width(GTK_CMCELL_PIXTEXT (clist_row->cell[column])->pixbuf);
      height = gdk_pixbuf_get_height(GTK_CMCELL_PIXTEXT (clist_row->cell[column])->pixbuf);
      requisition->width += width;
      requisition->height = MAX (requisition->height, height);      
      break;
    case GTK_CMCELL_PIXBUF:
      width = gdk_pixbuf_get_width(GTK_CMCELL_PIXBUF (clist_row->cell[column])->pixbuf);
      height = gdk_pixbuf_get_height(GTK_CMCELL_PIXBUF (clist_row->cell[column])->pixbuf);
      requisition->width += width;
      requisition->height = MAX (requisition->height, height);
      break;
      
    default:
      break;
    }

  requisition->width  += clist_row->cell[column].horizontal;
  requisition->height += clist_row->cell[column].vertical;
}

/* PUBLIC INSERT/REMOVE ROW FUNCTIONS
 *   gtk_cmclist_prepend
 *   gtk_cmclist_append
 *   gtk_cmclist_insert
 *   gtk_cmclist_remove
 *   gtk_cmclist_clear
 */
gint
gtk_cmclist_prepend (GtkCMCList    *clist,
		   gchar       *text[])
{
  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), -1);
  cm_return_val_if_fail (text != NULL, -1);

  return GTK_CMCLIST_GET_CLASS (clist)->insert_row (clist, 0, text);
}

gint
gtk_cmclist_append (GtkCMCList    *clist,
		  gchar       *text[])
{
  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), -1);
  cm_return_val_if_fail (text != NULL, -1);

  return GTK_CMCLIST_GET_CLASS (clist)->insert_row (clist, clist->rows, text);
}

gint
gtk_cmclist_insert (GtkCMCList    *clist,
		  gint         row,
		  gchar       *text[])
{
  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), -1);
  cm_return_val_if_fail (text != NULL, -1);

  if (row < 0 || row > clist->rows)
    row = clist->rows;

  return GTK_CMCLIST_GET_CLASS (clist)->insert_row (clist, row, text);
}

void
gtk_cmclist_remove (GtkCMCList *clist,
		  gint      row)
{
  GTK_CMCLIST_GET_CLASS (clist)->remove_row (clist, row);
}

void
gtk_cmclist_clear (GtkCMCList *clist)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));
  
  GTK_CMCLIST_GET_CLASS (clist)->clear (clist);
}

/* PRIVATE INSERT/REMOVE ROW FUNCTIONS
 *   real_insert_row
 *   real_remove_row
 *   real_clear
 *   real_row_move
 */
static gint
real_insert_row (GtkCMCList *clist,
		 gint      row,
		 gchar    *text[])
{
  gint i;
  GtkCMCListRow *clist_row;

  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), -1);
  cm_return_val_if_fail (text != NULL, -1);

  /* return if out of bounds */
  if (row < 0 || row > clist->rows)
    return -1;

  /* create the row */
  clist_row = row_new (clist);

  /* set the text in the row's columns */
  for (i = 0; i < clist->columns; i++)
    if (text[i])
      GTK_CMCLIST_GET_CLASS (clist)->set_cell_contents
	(clist, clist_row, i, GTK_CMCELL_TEXT, text[i], 0, NULL);

  if (!clist->rows)
    {
      clist->row_list = g_list_append (clist->row_list, clist_row);
      clist->row_list_end = clist->row_list;
    }
  else
    {
      if (GTK_CMCLIST_AUTO_SORT(clist))   /* override insertion pos */
	{
	  GList *work;
	  
	  row = 0;
	  work = clist->row_list;
	  
	  if (clist->sort_type == GTK_SORT_ASCENDING)
	    {
	      while (row < clist->rows &&
		     clist->compare (clist, clist_row,
				     GTK_CMCLIST_ROW (work)) > 0)
		{
		  row++;
		  work = work->next;
		}
	    }
	  else
	    {
	      while (row < clist->rows &&
		     clist->compare (clist, clist_row,
				     GTK_CMCLIST_ROW (work)) < 0)
		{
		  row++;
		  work = work->next;
		}
	    }
	}
      
      /* reset the row end pointer if we're inserting at the end of the list */
      if (row == clist->rows)
	clist->row_list_end = (g_list_append (clist->row_list_end,
					      clist_row))->next;
      else
	clist->row_list = g_list_insert (clist->row_list, clist_row, row);

    }
  clist->rows++;

  if (row < ROW_FROM_YPIXEL (clist, 0))
    clist->voffset -= (clist->row_height + CELL_SPACING);

  /* syncronize the selection list */
  sync_selection (clist, row, SYNC_INSERT);

  if (clist->rows == 1)
    {
      clist->focus_row = 0;
      if (clist->selection_mode == GTK_SELECTION_BROWSE)
	gtk_cmclist_select_row (clist, 0, -1);
    }

  /* redraw the list if it isn't frozen */
  if (CLIST_UNFROZEN (clist))
    {
      adjust_adjustments (clist, FALSE);

      if (gtk_cmclist_row_is_visible (clist, row) != GTK_VISIBILITY_NONE)
	draw_rows (clist, NULL);
    }

  return row;
}

static void
real_remove_row (GtkCMCList *clist,
		 gint      row)
{
  gint was_visible;
  GList *list;
  GtkCMCListRow *clist_row;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  /* return if out of bounds */
  if (row < 0 || row > (clist->rows - 1))
    return;

  was_visible = (gtk_cmclist_row_is_visible (clist, row) != GTK_VISIBILITY_NONE);

  /* get the row we're going to delete */
  list = ROW_ELEMENT (clist, row);
  g_assert (list != NULL);
  clist_row = list->data;

  /* if we're removing a selected row, we have to make sure
   * it's properly unselected, and then sync up the clist->selected
   * list to reflect the deincrimented indexies of rows after the
   * removal */
  if (clist_row->state == GTK_STATE_SELECTED)
    g_signal_emit (G_OBJECT (clist), clist_signals[UNSELECT_ROW], 0,
		     row, -1, NULL);

  sync_selection (clist, row, SYNC_REMOVE);

  /* reset the row end pointer if we're removing at the end of the list */
  clist->rows--;
  if (clist->row_list == list)
    clist->row_list = g_list_next (list);
  if (clist->row_list_end == list)
    clist->row_list_end = g_list_previous (list);
  list = g_list_remove (list, clist_row);

  if (row < ROW_FROM_YPIXEL (clist, 0))
    clist->voffset += clist->row_height + CELL_SPACING;

  if (clist->selection_mode == GTK_SELECTION_BROWSE && !clist->selection &&
      clist->focus_row >= 0)
    g_signal_emit (G_OBJECT (clist), clist_signals[SELECT_ROW], 0,
		     clist->focus_row, -1, NULL);

  /* toast the row */
  row_delete (clist, clist_row);

  /* redraw the row if it isn't frozen */
  if (CLIST_UNFROZEN (clist))
    {
      adjust_adjustments (clist, FALSE);

      if (was_visible)
	draw_rows (clist, NULL);
    }
}

static void
real_clear (GtkCMCList *clist)
{
  GList *list;
  GList *free_list;
  GtkRequisition requisition;
  gint i;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  /* free up the selection list */
  g_list_free (clist->selection);
  g_list_free (clist->undo_selection);
  g_list_free (clist->undo_unselection);

  clist->selection = NULL;
  clist->selection_end = NULL;
  clist->undo_selection = NULL;
  clist->undo_unselection = NULL;
  clist->voffset = 0;
  clist->focus_row = -1;
  clist->anchor = -1;
  clist->undo_anchor = -1;
  clist->anchor_state = GTK_STATE_SELECTED;
  clist->drag_pos = -1;

  /* remove all the rows */
  GTK_CMCLIST_SET_FLAG (clist, CMCLIST_AUTO_RESIZE_BLOCKED);
  free_list = clist->row_list;
  clist->row_list = NULL;
  clist->row_list_end = NULL;
  clist->rows = 0;
  for (list = free_list; list; list = list->next)
    row_delete (clist, GTK_CMCLIST_ROW (list));
  g_list_free (free_list);
  GTK_CMCLIST_UNSET_FLAG (clist, CMCLIST_AUTO_RESIZE_BLOCKED);
  for (i = 0; i < clist->columns; i++)
    if (clist->column[i].auto_resize)
      {
	if (GTK_CMCLIST_SHOW_TITLES(clist) && clist->column[i].button)
    {
	gtk_widget_get_requisition (clist->column[i].button, &requisition);
	  gtk_cmclist_set_column_width
	    (clist, i, (requisition.width -
			(CELL_SPACING + (2 * COLUMN_INSET))));
    }
	else
	  gtk_cmclist_set_column_width (clist, i, 0);
      }
  /* zero-out the scrollbars */
  if (clist->vadjustment)
    {
      gtk_adjustment_set_value (clist->vadjustment, 0.0);
      CLIST_REFRESH (clist);
    }
  else
    gtk_widget_queue_resize (GTK_WIDGET (clist));
}

static void
real_row_move (GtkCMCList *clist,
	       gint      source_row,
	       gint      dest_row)
{
  GtkCMCListRow *clist_row;
  GList *list;
  gint first, last;
  gint d;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (GTK_CMCLIST_AUTO_SORT(clist))
    return;

  if (source_row < 0 || source_row >= clist->rows ||
      dest_row   < 0 || dest_row   >= clist->rows ||
      source_row == dest_row)
    return;

  gtk_cmclist_freeze (clist);

  /* unlink source row */
  clist_row = ROW_ELEMENT (clist, source_row)->data;
  if (source_row == clist->rows - 1)
    clist->row_list_end = clist->row_list_end->prev;
  clist->row_list = g_list_remove (clist->row_list, clist_row);
  clist->rows--;

  /* relink source row */
  clist->row_list = g_list_insert (clist->row_list, clist_row, dest_row);
  if (dest_row == clist->rows)
    clist->row_list_end = clist->row_list_end->next;
  clist->rows++;

  /* sync selection */
  if (source_row > dest_row)
    {
      first = dest_row;
      last  = source_row;
      d = 1;
    }
  else
    {
      first = source_row;
      last  = dest_row;
      d = -1;
    }

  for (list = clist->selection; list; list = list->next)
    {
      if (list->data == GINT_TO_POINTER (source_row))
	list->data = GINT_TO_POINTER (dest_row);
      else if (first <= GPOINTER_TO_INT (list->data) &&
	       last >= GPOINTER_TO_INT (list->data))
	list->data = GINT_TO_POINTER (GPOINTER_TO_INT (list->data) + d);
    }
  
  if (clist->focus_row == source_row)
    clist->focus_row = dest_row;
  else if (clist->focus_row > first)
    clist->focus_row += d;

  gtk_cmclist_thaw (clist);
}

/* PUBLIC ROW FUNCTIONS
 *   gtk_cmclist_moveto
 *   gtk_cmclist_set_row_height
 *   gtk_cmclist_set_row_data
 *   gtk_cmclist_set_row_data_full
 *   gtk_cmclist_get_row_data
 *   gtk_cmclist_find_row_from_data
 *   gtk_cmclist_swap_rows
 *   gtk_cmclist_row_move
 *   gtk_cmclist_row_is_visible
 *   gtk_cmclist_set_foreground
 *   gtk_cmclist_set_background
 */
void
gtk_cmclist_moveto (GtkCMCList *clist,
		  gint      row,
		  gint      column,
		  gfloat    row_align,
		  gfloat    col_align)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (row < -1 || row >= clist->rows)
    return;
  if (column < -1 || column >= clist->columns)
    return;

  row_align = CLAMP (row_align, 0, 1);
  col_align = CLAMP (col_align, 0, 1);

  /* adjust horizontal scrollbar */
  if (clist->hadjustment && column >= 0)
    {
      gint x;

      x = (COLUMN_LEFT (clist, column) - CELL_SPACING - COLUMN_INSET -
	   (col_align * (clist->clist_window_width - 2 * COLUMN_INSET -
			 CELL_SPACING - clist->column[column].area.width)));
      if (x < 0)
	gtk_adjustment_set_value (clist->hadjustment, 0.0);
      else if (x > LIST_WIDTH (clist) - clist->clist_window_width)
	gtk_adjustment_set_value 
	  (clist->hadjustment, LIST_WIDTH (clist) - clist->clist_window_width);
      else
	gtk_adjustment_set_value (clist->hadjustment, x);
    }

  /* adjust vertical scrollbar */
  if (clist->vadjustment && row >= 0)
    move_vertical (clist, row, row_align);
}

void
gtk_cmclist_set_row_height (GtkCMCList *clist,
			  guint     height)
{
  GtkStyle *style;
  GtkWidget *widget;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  widget = GTK_WIDGET (clist);

  style = gtk_widget_get_style (widget);

  if (height > 0)
    {
      clist->row_height = height;
      GTK_CMCLIST_SET_FLAG (clist, CMCLIST_ROW_HEIGHT_SET);
    }
  else
    {
      GTK_CMCLIST_UNSET_FLAG (clist, CMCLIST_ROW_HEIGHT_SET);
      clist->row_height = 0;
    }

  if (style->font_desc)
    {
      PangoContext *context = gtk_widget_get_pango_context (widget);
      PangoFontMetrics *metrics;

      metrics = pango_context_get_metrics (context,
					   style->font_desc,
					   pango_context_get_language (context));

      if (!GTK_CMCLIST_ROW_HEIGHT_SET(clist))
	{
	  clist->row_height = (pango_font_metrics_get_ascent (metrics) +
			       pango_font_metrics_get_descent (metrics));
	  clist->row_height = PANGO_PIXELS (clist->row_height) + 1;
	}

      pango_font_metrics_unref (metrics);
    }

  CLIST_REFRESH (clist);
}

void
gtk_cmclist_set_row_data (GtkCMCList *clist,
			gint      row,
			gpointer  data)
{
  gtk_cmclist_set_row_data_full (clist, row, data, NULL);
}

void
gtk_cmclist_set_row_data_full (GtkCMCList         *clist,
			     gint              row,
			     gpointer          data,
			     GDestroyNotify  destroy)
{
  GtkCMCListRow *clist_row;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (row < 0 || row > (clist->rows - 1))
    return;

  clist_row = ROW_ELEMENT (clist, row)->data;

  if (clist_row->destroy)
    clist_row->destroy (clist_row->data);
  
  clist_row->data = data;
  clist_row->destroy = destroy;
}

gpointer
gtk_cmclist_get_row_data (GtkCMCList *clist,
			gint      row)
{
  GtkCMCListRow *clist_row;

  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), NULL);

  if (row < 0 || row > (clist->rows - 1))
    return NULL;

  clist_row = ROW_ELEMENT (clist, row)->data;
  return clist_row->data;
}

gint
gtk_cmclist_find_row_from_data (GtkCMCList *clist,
			      gpointer  data)
{
  GList *list;
  gint n;

  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), -1);

  for (n = 0, list = clist->row_list; list; n++, list = list->next)
    if (GTK_CMCLIST_ROW (list)->data == data)
      return n;

  return -1;
}

void 
gtk_cmclist_swap_rows (GtkCMCList *clist,
		     gint      row1, 
		     gint      row2)
{
  gint first, last;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));
  cm_return_if_fail (row1 != row2);

  if (GTK_CMCLIST_AUTO_SORT(clist))
    return;

  gtk_cmclist_freeze (clist);

  first = MIN (row1, row2);
  last  = MAX (row1, row2);

  gtk_cmclist_row_move (clist, last, first);
  gtk_cmclist_row_move (clist, first + 1, last);
  
  gtk_cmclist_thaw (clist);
}

void
gtk_cmclist_row_move (GtkCMCList *clist,
		    gint      source_row,
		    gint      dest_row)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (GTK_CMCLIST_AUTO_SORT(clist))
    return;

  if (source_row < 0 || source_row >= clist->rows ||
      dest_row   < 0 || dest_row   >= clist->rows ||
      source_row == dest_row)
    return;

  g_signal_emit (G_OBJECT (clist), clist_signals[ROW_MOVE], 0,
		   source_row, dest_row);
}

GtkVisibility
gtk_cmclist_row_is_visible (GtkCMCList *clist,
			  gint      row)
{
  gint top;

  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), 0);

  if (row < 0 || row >= clist->rows)
    return GTK_VISIBILITY_NONE;

  if (clist->row_height == 0)
    return GTK_VISIBILITY_NONE;

  if (row < ROW_FROM_YPIXEL (clist, 0))
    return GTK_VISIBILITY_NONE;

  if (row > ROW_FROM_YPIXEL (clist, clist->clist_window_height))
    return GTK_VISIBILITY_NONE;

  top = ROW_TOP_YPIXEL (clist, row);

  if ((top < 0)
      || ((top + clist->row_height) >= clist->clist_window_height))
    return GTK_VISIBILITY_PARTIAL;

  return GTK_VISIBILITY_FULL;
}

gboolean
gtk_cmclist_row_is_above_viewport (GtkCMCList *clist,
				gint row)
{
	cm_return_val_if_fail(GTK_IS_CMCLIST (clist), 0);

	if (row < 0 || row >= clist->rows)
		return FALSE;

	if (clist->row_height == 0)
		return FALSE;

	if (row < ROW_FROM_YPIXEL (clist, 0))
		return TRUE;

	return FALSE;
}

gboolean
gtk_cmclist_row_is_below_viewport (GtkCMCList *clist,
				gint row)
{
	cm_return_val_if_fail(GTK_IS_CMCLIST (clist), 0);

	if (row < 0 || row >= clist->rows)
		return FALSE;

	if (clist->row_height == 0)
		return FALSE;

	if (row > ROW_FROM_YPIXEL (clist, clist->clist_window_height))
		return TRUE;

	return FALSE;
}

void
gtk_cmclist_set_foreground (GtkCMCList       *clist,
			  gint            row,
			  const GdkColor *color)
{
  GtkCMCListRow *clist_row;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (row < 0 || row >= clist->rows)
    return;

  clist_row = ROW_ELEMENT (clist, row)->data;

  if (color)
    {
      clist_row->foreground = *color;
      clist_row->fg_set = TRUE;
    }
  else
    clist_row->fg_set = FALSE;

  if (CLIST_UNFROZEN (clist) && gtk_cmclist_row_is_visible (clist, row) != GTK_VISIBILITY_NONE)
    GTK_CMCLIST_GET_CLASS (clist)->draw_row (clist, NULL, row, clist_row);
}

void
gtk_cmclist_set_background (GtkCMCList       *clist,
			  gint            row,
			  const GdkColor *color)
{
  GtkCMCListRow *clist_row;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (row < 0 || row >= clist->rows)
    return;

  clist_row = ROW_ELEMENT (clist, row)->data;

  if (color)
    {
      clist_row->background = *color;
      clist_row->bg_set = TRUE;
    }
  else
    clist_row->bg_set = FALSE;

  if (CLIST_UNFROZEN (clist)
      && (gtk_cmclist_row_is_visible (clist, row) != GTK_VISIBILITY_NONE))
    GTK_CMCLIST_GET_CLASS (clist)->draw_row (clist, NULL, row, clist_row);
}

/* PUBLIC ROW/CELL STYLE FUNCTIONS
 *   gtk_cmclist_set_cell_style
 *   gtk_cmclist_get_cell_style
 *   gtk_cmclist_set_row_style
 *   gtk_cmclist_get_row_style
 */
void
gtk_cmclist_set_cell_style (GtkCMCList *clist,
			  gint      row,
			  gint      column,
			  GtkStyle *style)
{
  GtkRequisition requisition = { 0 };
  GtkCMCListRow *clist_row;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (row < 0 || row >= clist->rows)
    return;
  if (column < 0 || column >= clist->columns)
    return;

  clist_row = ROW_ELEMENT (clist, row)->data;

  if (clist_row->cell[column].style == style)
    return;

  if (clist->column[column].auto_resize &&
      !GTK_CMCLIST_AUTO_RESIZE_BLOCKED (clist))
    GTK_CMCLIST_GET_CLASS (clist)->cell_size_request (clist, clist_row,
						   column, &requisition);

  if (clist_row->cell[column].style)
    {
      if (gtk_widget_get_realized (GTK_WIDGET(clist)))
        gtk_style_detach (clist_row->cell[column].style);
      g_object_unref (clist_row->cell[column].style);
    }

  clist_row->cell[column].style = style;

  if (clist_row->cell[column].style)
    {
      g_object_ref (clist_row->cell[column].style);
      
      if (gtk_widget_get_realized (GTK_WIDGET(clist)))
        clist_row->cell[column].style =
	  gtk_style_attach (clist_row->cell[column].style,
			    clist->clist_window);
    }

  column_auto_resize (clist, clist_row, column, requisition.width);

  /* redraw the list if it's not frozen */
  if (CLIST_UNFROZEN (clist))
    {
      if (gtk_cmclist_row_is_visible (clist, row) != GTK_VISIBILITY_NONE)
	GTK_CMCLIST_GET_CLASS (clist)->draw_row (clist, NULL, row, clist_row);
    }
}

GtkStyle *
gtk_cmclist_get_cell_style (GtkCMCList *clist,
			  gint      row,
			  gint      column)
{
  GtkCMCListRow *clist_row;

  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), NULL);

  if (row < 0 || row >= clist->rows || column < 0 || column >= clist->columns)
    return NULL;

  clist_row = ROW_ELEMENT (clist, row)->data;

  return clist_row->cell[column].style;
}

void
gtk_cmclist_set_row_style (GtkCMCList *clist,
			 gint      row,
			 GtkStyle *style)
{
  GtkRequisition requisition;
  GtkCMCListRow *clist_row;
  gint *old_width;
  gint i;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (row < 0 || row >= clist->rows)
    return;

  clist_row = ROW_ELEMENT (clist, row)->data;

  if (clist_row->style == style)
    return;

  old_width = g_new (gint, clist->columns);

  if (!GTK_CMCLIST_AUTO_RESIZE_BLOCKED (clist))
    {
      for (i = 0; i < clist->columns; i++)
	if (clist->column[i].auto_resize)
	  {
	    GTK_CMCLIST_GET_CLASS (clist)->cell_size_request (clist, clist_row,
							   i, &requisition);
	    old_width[i] = requisition.width;
	  }
    }

  if (clist_row->style)
    {
      if (gtk_widget_get_realized (GTK_WIDGET(clist)))
        gtk_style_detach (clist_row->style);
      g_object_unref (clist_row->style);
    }

  clist_row->style = style;

  if (clist_row->style)
    {
      g_object_ref (clist_row->style);
      
      if (gtk_widget_get_realized (GTK_WIDGET(clist)))
        clist_row->style = gtk_style_attach (clist_row->style,
					     clist->clist_window);
    }

  if (GTK_CMCLIST_AUTO_RESIZE_BLOCKED (clist))
    for (i = 0; i < clist->columns; i++)
      column_auto_resize (clist, clist_row, i, old_width[i]);

  g_free (old_width);

  /* redraw the list if it's not frozen */
  if (CLIST_UNFROZEN (clist))
    {
      if (gtk_cmclist_row_is_visible (clist, row) != GTK_VISIBILITY_NONE)
	GTK_CMCLIST_GET_CLASS (clist)->draw_row (clist, NULL, row, clist_row);
    }
}

GtkStyle *
gtk_cmclist_get_row_style (GtkCMCList *clist,
			 gint      row)
{
  GtkCMCListRow *clist_row;

  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), NULL);

  if (row < 0 || row >= clist->rows)
    return NULL;

  clist_row = ROW_ELEMENT (clist, row)->data;

  return clist_row->style;
}

/* PUBLIC SELECTION FUNCTIONS
 *   gtk_cmclist_set_selectable
 *   gtk_cmclist_get_selectable
 *   gtk_cmclist_select_row
 *   gtk_cmclist_unselect_row
 *   gtk_cmclist_select_all
 *   gtk_cmclist_unselect_all
 *   gtk_cmclist_undo_selection
 */
void
gtk_cmclist_set_selectable (GtkCMCList *clist,
			  gint      row,
			  gboolean  selectable)
{
  GtkCMCListRow *clist_row;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (row < 0 || row >= clist->rows)
    return;

  clist_row = ROW_ELEMENT (clist, row)->data;

  if (selectable == clist_row->selectable)
    return;

  clist_row->selectable = selectable;

  if (!selectable && clist_row->state == GTK_STATE_SELECTED)
    {
      if (clist->anchor >= 0 &&
	  clist->selection_mode == GTK_SELECTION_MULTIPLE)
	{
	  clist->drag_button = 0;
	  remove_grab (clist);
	  GTK_CMCLIST_GET_CLASS (clist)->resync_selection (clist, NULL);
	}
      g_signal_emit (G_OBJECT (clist), clist_signals[UNSELECT_ROW], 0,
		       row, -1, NULL);
    }      
}

gboolean
gtk_cmclist_get_selectable (GtkCMCList *clist,
			  gint      row)
{
  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), FALSE);

  if (row < 0 || row >= clist->rows)
    return FALSE;

  return GTK_CMCLIST_ROW (ROW_ELEMENT (clist, row))->selectable;
}

void
gtk_cmclist_select_row (GtkCMCList *clist,
		      gint      row,
		      gint      column)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (row < 0 || row >= clist->rows)
    return;
  if (column < -1 || column >= clist->columns)
    return;

  g_signal_emit (G_OBJECT (clist), clist_signals[SELECT_ROW], 0,
		   row, column, NULL);
}

void
gtk_cmclist_unselect_row (GtkCMCList *clist,
			gint      row,
			gint      column)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (row < 0 || row >= clist->rows)
    return;
  if (column < -1 || column >= clist->columns)
    return;

  g_signal_emit (G_OBJECT (clist), clist_signals[UNSELECT_ROW], 0,
		   row, column, NULL);
}

void
gtk_cmclist_select_all (GtkCMCList *clist)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  GTK_CMCLIST_GET_CLASS (clist)->select_all (clist);
}

void
gtk_cmclist_unselect_all (GtkCMCList *clist)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  GTK_CMCLIST_GET_CLASS (clist)->unselect_all (clist);
}

void
gtk_cmclist_undo_selection (GtkCMCList *clist)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (clist->selection_mode == GTK_SELECTION_MULTIPLE &&
      (clist->undo_selection || clist->undo_unselection))
    g_signal_emit (G_OBJECT (clist), clist_signals[UNDO_SELECTION], 0);
}

/* PRIVATE SELECTION FUNCTIONS
 *   selection_find
 *   toggle_row
 *   fake_toggle_row
 *   toggle_focus_row
 *   toggle_add_mode
 *   real_select_row
 *   real_unselect_row
 *   real_select_all
 *   real_unselect_all
 *   fake_unselect_all
 *   real_undo_selection
 *   set_anchor
 *   resync_selection
 *   update_extended_selection
 *   start_selection
 *   end_selection
 *   extend_selection
 *   sync_selection
 */
static GList *
selection_find (GtkCMCList *clist,
		gint      row_number,
		GList    *row_list_element)
{
  return g_list_find (clist->selection, GINT_TO_POINTER (row_number));
}

static void
toggle_row (GtkCMCList *clist,
	    gint      row,
	    gint      column,
	    GdkEvent *event)
{
  GtkCMCListRow *clist_row;

  switch (clist->selection_mode)
    {
    case GTK_SELECTION_MULTIPLE:
    case GTK_SELECTION_SINGLE:
      clist_row = ROW_ELEMENT (clist, row)->data;

      if (!clist_row)
	return;

      if (clist_row->state == GTK_STATE_SELECTED)
	{
	  g_signal_emit (G_OBJECT (clist), clist_signals[UNSELECT_ROW], 0,
			   row, column, event);
	  return;
	}
      break;
    case GTK_SELECTION_BROWSE:
      g_signal_emit (G_OBJECT (clist), clist_signals[SELECT_ROW], 0,
		       row, column, event);
      break;
    default:
      g_assert_not_reached ();
    }
}

static void
fake_toggle_row (GtkCMCList *clist,
		 gint      row)
{
  GList *work;

  work = ROW_ELEMENT (clist, row);

  if (!work || !GTK_CMCLIST_ROW (work)->selectable)
    return;
  
  if (GTK_CMCLIST_ROW (work)->state == GTK_STATE_NORMAL)
    clist->anchor_state = GTK_CMCLIST_ROW (work)->state = GTK_STATE_SELECTED;
  else
    clist->anchor_state = GTK_CMCLIST_ROW (work)->state = GTK_STATE_NORMAL;
  
  if (CLIST_UNFROZEN (clist) &&
      gtk_cmclist_row_is_visible (clist, row) != GTK_VISIBILITY_NONE)
    GTK_CMCLIST_GET_CLASS (clist)->draw_row (clist, NULL, row,
					  GTK_CMCLIST_ROW (work));
}

static gboolean
clist_has_grab (GtkCMCList *clist)
{
  return (gtk_widget_has_grab (GTK_WIDGET(clist)) &&
	  gtkut_pointer_is_grabbed(GTK_WIDGET(clist)));
}

static void
toggle_focus_row (GtkCMCList *clist)
{
  cm_return_if_fail (clist != 0);
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (clist_has_grab (clist) ||
      clist->focus_row < 0 || clist->focus_row >= clist->rows)
    return;

  switch (clist->selection_mode)
    {
    case  GTK_SELECTION_SINGLE:
      toggle_row (clist, clist->focus_row, 0, NULL);
      break;
    case GTK_SELECTION_MULTIPLE:
      g_list_free (clist->undo_selection);
      g_list_free (clist->undo_unselection);
      clist->undo_selection = NULL;
      clist->undo_unselection = NULL;

      clist->anchor = clist->focus_row;
      clist->drag_pos = clist->focus_row;
      clist->undo_anchor = clist->focus_row;
      
      if (GTK_CMCLIST_ADD_MODE(clist))
	fake_toggle_row (clist, clist->focus_row);
      else
	GTK_CMCLIST_GET_CLASS (clist)->fake_unselect_all (clist,clist->focus_row);

      GTK_CMCLIST_GET_CLASS (clist)->resync_selection (clist, NULL);
      break;
    default:
      break;
    }
}

static void
toggle_add_mode (GtkCMCList *clist)
{
  cm_return_if_fail (clist != 0);
  cm_return_if_fail (GTK_IS_CMCLIST (clist));
  
  if (clist_has_grab (clist) ||
      clist->selection_mode != GTK_SELECTION_MULTIPLE)
    return;

  gtk_cmclist_undraw_focus (GTK_WIDGET (clist));
  if (!GTK_CMCLIST_ADD_MODE(clist))
    {
      GTK_CMCLIST_SET_FLAG (clist, CMCLIST_ADD_MODE);
    }
  else
    {
      GTK_CMCLIST_UNSET_FLAG (clist, CMCLIST_ADD_MODE);
      clist->anchor_state = GTK_STATE_SELECTED;
    }
  gtk_cmclist_draw_focus (GTK_WIDGET (clist));
}

static void
real_select_row (GtkCMCList *clist,
		 gint      row,
		 gint      column,
		 GdkEvent *event)
{
  GtkCMCListRow *clist_row;
  GList *list;
  gint sel_row;
  gboolean row_selected;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (row < 0 || row > (clist->rows - 1))
    return;

  switch (clist->selection_mode)
    {
    case GTK_SELECTION_SINGLE:
    case GTK_SELECTION_BROWSE:

      row_selected = FALSE;
      list = clist->selection;

      while (list)
	{
	  sel_row = GPOINTER_TO_INT (list->data);
	  list = list->next;

	  if (row == sel_row)
	    row_selected = TRUE;
	  else
	    g_signal_emit (G_OBJECT (clist), clist_signals[UNSELECT_ROW], 0,
			     sel_row, column, event);
	}

      if (row_selected)
	return;
      
    default:
      break;
    }

  clist_row = ROW_ELEMENT (clist, row)->data;

  if (clist_row->state != GTK_STATE_NORMAL || !clist_row->selectable)
    return;

  clist_row->state = GTK_STATE_SELECTED;
  if (!clist->selection)
    {
      clist->selection = g_list_append (clist->selection,
					GINT_TO_POINTER (row));
      clist->selection_end = clist->selection;
    }
  else
    clist->selection_end = 
      g_list_append (clist->selection_end, GINT_TO_POINTER (row))->next;
  
  if (CLIST_UNFROZEN (clist)
      && (gtk_cmclist_row_is_visible (clist, row) != GTK_VISIBILITY_NONE))
    GTK_CMCLIST_GET_CLASS (clist)->draw_row (clist, NULL, row, clist_row);
}

static void
real_unselect_row (GtkCMCList *clist,
		   gint      row,
		   gint      column,
		   GdkEvent *event)
{
  GtkCMCListRow *clist_row;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (row < 0 || row > (clist->rows - 1))
    return;

  clist_row = ROW_ELEMENT (clist, row)->data;

  if (clist_row->state == GTK_STATE_SELECTED)
    {
      clist_row->state = GTK_STATE_NORMAL;

      if (clist->selection_end && 
	  clist->selection_end->data == GINT_TO_POINTER (row))
	clist->selection_end = clist->selection_end->prev;

      clist->selection = g_list_remove (clist->selection,
					GINT_TO_POINTER (row));
      
      if (CLIST_UNFROZEN (clist)
	  && (gtk_cmclist_row_is_visible (clist, row) != GTK_VISIBILITY_NONE))
	GTK_CMCLIST_GET_CLASS (clist)->draw_row (clist, NULL, row, clist_row);
    }
}

static void
real_select_all (GtkCMCList *clist)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (clist_has_grab (clist))
    return;

  switch (clist->selection_mode)
    {
    case GTK_SELECTION_SINGLE:
    case GTK_SELECTION_BROWSE:
      return;

    case GTK_SELECTION_MULTIPLE:
      g_list_free (clist->undo_selection);
      g_list_free (clist->undo_unselection);
      clist->undo_selection = NULL;
      clist->undo_unselection = NULL;
	  
      if (clist->rows &&
	  ((GtkCMCListRow *) (clist->row_list->data))->state !=
	  GTK_STATE_SELECTED)
	fake_toggle_row (clist, 0);

      clist->anchor_state =  GTK_STATE_SELECTED;
      clist->anchor = 0;
      clist->drag_pos = 0;
      clist->undo_anchor = clist->focus_row;
      update_extended_selection (clist, clist->rows);
      GTK_CMCLIST_GET_CLASS (clist)->resync_selection (clist, NULL);
      return;
    default:
      g_assert_not_reached ();
    }
}

static void
real_unselect_all (GtkCMCList *clist)
{
  GList *list;
  gint i;
 
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (clist_has_grab (clist))
    return;

  switch (clist->selection_mode)
    {
    case GTK_SELECTION_BROWSE:
      if (clist->focus_row >= 0)
	{
	  g_signal_emit (G_OBJECT (clist),
			   clist_signals[SELECT_ROW], 0,
			   clist->focus_row, -1, NULL);
	  return;
	}
      break;
    case GTK_SELECTION_MULTIPLE:
      g_list_free (clist->undo_selection);
      g_list_free (clist->undo_unselection);
      clist->undo_selection = NULL;
      clist->undo_unselection = NULL;

      clist->anchor = -1;
      clist->drag_pos = -1;
      clist->undo_anchor = clist->focus_row;
      break;
    default:
      break;
    }

  list = clist->selection;
  while (list)
    {
      i = GPOINTER_TO_INT (list->data);
      list = list->next;
      g_signal_emit (G_OBJECT (clist),
		       clist_signals[UNSELECT_ROW], 0, i, -1, NULL);
    }
}

static void
fake_unselect_all (GtkCMCList *clist,
		   gint      row)
{
  GList *list;
  GList *work;
  gint i;

  if (row >= 0 && (work = ROW_ELEMENT (clist, row)))
    {
      if (GTK_CMCLIST_ROW (work)->state == GTK_STATE_NORMAL &&
	  GTK_CMCLIST_ROW (work)->selectable)
	{
	  GTK_CMCLIST_ROW (work)->state = GTK_STATE_SELECTED;
	  
	  if (CLIST_UNFROZEN (clist) &&
	      gtk_cmclist_row_is_visible (clist, row) != GTK_VISIBILITY_NONE)
	    GTK_CMCLIST_GET_CLASS (clist)->draw_row (clist, NULL, row,
						  GTK_CMCLIST_ROW (work));
	}  
    }

  clist->undo_selection = clist->selection;
  clist->selection = NULL;
  clist->selection_end = NULL;

  for (list = clist->undo_selection; list; list = list->next)
    {
      if ((i = GPOINTER_TO_INT (list->data)) == row ||
	  !(work = g_list_nth (clist->row_list, i)))
	continue;

      GTK_CMCLIST_ROW (work)->state = GTK_STATE_NORMAL;
      if (CLIST_UNFROZEN (clist) &&
	  gtk_cmclist_row_is_visible (clist, i) != GTK_VISIBILITY_NONE)
	GTK_CMCLIST_GET_CLASS (clist)->draw_row (clist, NULL, i,
					      GTK_CMCLIST_ROW (work));
    }
}

static void
real_undo_selection (GtkCMCList *clist)
{
  GList *work;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (clist_has_grab (clist) ||
      clist->selection_mode != GTK_SELECTION_MULTIPLE)
    return;

  GTK_CMCLIST_GET_CLASS (clist)->resync_selection (clist, NULL);

  if (!(clist->undo_selection || clist->undo_unselection))
    {
      gtk_cmclist_unselect_all (clist);
      return;
    }

  for (work = clist->undo_selection; work; work = work->next)
    g_signal_emit (G_OBJECT (clist), clist_signals[SELECT_ROW], 0,
		     GPOINTER_TO_INT (work->data), -1, NULL);

  for (work = clist->undo_unselection; work; work = work->next)
    {
      /* g_print ("unselect %d\n",GPOINTER_TO_INT (work->data)); */
      g_signal_emit (G_OBJECT (clist), clist_signals[UNSELECT_ROW], 0,
		       GPOINTER_TO_INT (work->data), -1, NULL);
    }

  if (gtk_widget_has_focus(GTK_WIDGET(clist)) && clist->focus_row != clist->undo_anchor)
    {
      gtk_cmclist_undraw_focus (GTK_WIDGET (clist));
      clist->focus_row = clist->undo_anchor;
      gtk_cmclist_draw_focus (GTK_WIDGET (clist));
    }
  else
    clist->focus_row = clist->undo_anchor;
  
  clist->undo_anchor = -1;
 
  g_list_free (clist->undo_selection);
  g_list_free (clist->undo_unselection);
  clist->undo_selection = NULL;
  clist->undo_unselection = NULL;

  if (ROW_TOP_YPIXEL (clist, clist->focus_row) + clist->row_height >
      clist->clist_window_height)
    gtk_cmclist_moveto (clist, clist->focus_row, -1, 1, 0);
  else if (ROW_TOP_YPIXEL (clist, clist->focus_row) < 0)
    gtk_cmclist_moveto (clist, clist->focus_row, -1, 0, 0);
}

static void
set_anchor (GtkCMCList *clist,
	    gboolean  add_mode,
	    gint      anchor,
	    gint      undo_anchor)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));
  
  if (clist->selection_mode != GTK_SELECTION_MULTIPLE || clist->anchor >= 0)
    return;

  g_list_free (clist->undo_selection);
  g_list_free (clist->undo_unselection);
  clist->undo_selection = NULL;
  clist->undo_unselection = NULL;

  if (add_mode)
    fake_toggle_row (clist, anchor);
  else
    {
      GTK_CMCLIST_GET_CLASS (clist)->fake_unselect_all (clist, anchor);
      clist->anchor_state = GTK_STATE_SELECTED;
    }

  clist->anchor = anchor;
  clist->drag_pos = anchor;
  clist->undo_anchor = undo_anchor;
}

static void
resync_selection (GtkCMCList *clist,
		  GdkEvent *event)
{
  gint i;
  gint e;
  gint row;
  GList *list;
  GtkCMCListRow *clist_row;

  if (clist->selection_mode != GTK_SELECTION_MULTIPLE)
    return;

  if (clist->anchor < 0 || clist->drag_pos < 0)
    return;

  gtk_cmclist_freeze (clist);

  i = MIN (clist->anchor, clist->drag_pos);
  e = MAX (clist->anchor, clist->drag_pos);

  if (clist->undo_selection)
    {
      list = clist->selection;
      clist->selection = clist->undo_selection;
      clist->selection_end = g_list_last (clist->selection);
      clist->undo_selection = list;
      list = clist->selection;
      while (list)
	{
	  row = GPOINTER_TO_INT (list->data);
	  list = list->next;
	  if (row < i || row > e)
	    {
	      clist_row = g_list_nth (clist->row_list, row)->data;
	      if (clist_row->selectable)
		{
		  clist_row->state = GTK_STATE_SELECTED;
		  g_signal_emit (G_OBJECT (clist),
				   clist_signals[UNSELECT_ROW], 0,
				   row, -1, event);
		  clist->undo_selection = g_list_prepend
		    (clist->undo_selection, GINT_TO_POINTER (row));
		}
	    }
	}
    }    

  if (clist->anchor < clist->drag_pos)
    {
      for (list = g_list_nth (clist->row_list, i); i <= e;
	   i++, list = list->next)
	if (GTK_CMCLIST_ROW (list)->selectable)
	  {
	    if (g_list_find (clist->selection, GINT_TO_POINTER(i)))
	      {
		if (GTK_CMCLIST_ROW (list)->state == GTK_STATE_NORMAL)
		  {
		    GTK_CMCLIST_ROW (list)->state = GTK_STATE_SELECTED;
		    g_signal_emit (G_OBJECT (clist),
				     clist_signals[UNSELECT_ROW], 0,
				     i, -1, event);
		    clist->undo_selection =
		      g_list_prepend (clist->undo_selection,
				      GINT_TO_POINTER (i));
		  }
	      }
	    else if (GTK_CMCLIST_ROW (list)->state == GTK_STATE_SELECTED)
	      {
		GTK_CMCLIST_ROW (list)->state = GTK_STATE_NORMAL;
		clist->undo_unselection =
		  g_list_prepend (clist->undo_unselection,
				  GINT_TO_POINTER (i));
	      }
	  }
    }
  else
    {
      for (list = g_list_nth (clist->row_list, e); i <= e;
	   e--, list = list->prev)
	if (GTK_CMCLIST_ROW (list)->selectable)
	  {
	    if (g_list_find (clist->selection, GINT_TO_POINTER(e)))
	      {
		if (GTK_CMCLIST_ROW (list)->state == GTK_STATE_NORMAL)
		  {
		    GTK_CMCLIST_ROW (list)->state = GTK_STATE_SELECTED;
		    g_signal_emit (G_OBJECT (clist),
				     clist_signals[UNSELECT_ROW], 0,
				     e, -1, event);
		    clist->undo_selection =
		      g_list_prepend (clist->undo_selection,
				      GINT_TO_POINTER (e));
		  }
	      }
	    else if (GTK_CMCLIST_ROW (list)->state == GTK_STATE_SELECTED)
	      {
		GTK_CMCLIST_ROW (list)->state = GTK_STATE_NORMAL;
		clist->undo_unselection =
		  g_list_prepend (clist->undo_unselection,
				  GINT_TO_POINTER (e));
	      }
	  }
    }
  
  clist->undo_unselection = g_list_reverse (clist->undo_unselection);
  for (list = clist->undo_unselection; list; list = list->next)
    g_signal_emit (G_OBJECT (clist), clist_signals[SELECT_ROW], 0,
		     GPOINTER_TO_INT (list->data), -1, event);

  clist->anchor = -1;
  clist->drag_pos = -1;

  gtk_cmclist_thaw (clist);
}

static void
update_extended_selection (GtkCMCList *clist,
			   gint      row)
{
  gint i;
  GList *list;
  GdkRectangle area;
  gint s1 = -1;
  gint s2 = -1;
  gint e1 = -1;
  gint e2 = -1;
  gint y1 = clist->clist_window_height;
  gint y2 = clist->clist_window_height;
  gint h1 = 0;
  gint h2 = 0;
  gint top;

  if (clist->selection_mode != GTK_SELECTION_MULTIPLE || clist->anchor == -1)
    return;

  if (row < 0)
    row = 0;
  if (row >= clist->rows)
    row = clist->rows - 1;

  /* extending downwards */
  if (row > clist->drag_pos && clist->anchor <= clist->drag_pos)
    {
      s2 = clist->drag_pos + 1;
      e2 = row;
    }
  /* extending upwards */
  else if (row < clist->drag_pos && clist->anchor >= clist->drag_pos)
    {
      s2 = row;
      e2 = clist->drag_pos - 1;
    }
  else if (row < clist->drag_pos && clist->anchor < clist->drag_pos)
    {
      e1 = clist->drag_pos;
      /* row and drag_pos on different sides of anchor :
	 take back the selection between anchor and drag_pos,
         select between anchor and row */
      if (row < clist->anchor)
	{
	  s1 = clist->anchor + 1;
	  s2 = row;
	  e2 = clist->anchor - 1;
	}
      /* take back the selection between anchor and drag_pos */
      else
	s1 = row + 1;
    }
  else if (row > clist->drag_pos && clist->anchor > clist->drag_pos)
    {
      s1 = clist->drag_pos;
      /* row and drag_pos on different sides of anchor :
	 take back the selection between anchor and drag_pos,
         select between anchor and row */
      if (row > clist->anchor)
	{
	  e1 = clist->anchor - 1;
	  s2 = clist->anchor + 1;
	  e2 = row;
	}
      /* take back the selection between anchor and drag_pos */
      else
	e1 = row - 1;
    }

  clist->drag_pos = row;

  area.x = 0;
  area.width = clist->clist_window_width;

  /* restore the elements between s1 and e1 */
  if (s1 >= 0)
    {
      for (i = s1, list = g_list_nth (clist->row_list, i); i <= e1;
	   i++, list = list->next)
	if (GTK_CMCLIST_ROW (list)->selectable)
	  {
	    if (GTK_CMCLIST_GET_CLASS (clist)->selection_find (clist, i, list))
	      GTK_CMCLIST_ROW (list)->state = GTK_STATE_SELECTED;
	    else
	      GTK_CMCLIST_ROW (list)->state = GTK_STATE_NORMAL;
	  }

      top = ROW_TOP_YPIXEL (clist, clist->focus_row);

      if (top + clist->row_height <= 0)
	{
	  area.y = 0;
	  area.height = ROW_TOP_YPIXEL (clist, e1) + clist->row_height;
	  draw_rows (clist, &area);
	  gtk_cmclist_moveto (clist, clist->focus_row, -1, 0, 0);
	}
      else if (top >= clist->clist_window_height)
	{
	  area.y = ROW_TOP_YPIXEL (clist, s1) - 1;
	  area.height = clist->clist_window_height - area.y;
	  draw_rows (clist, &area);
	  gtk_cmclist_moveto (clist, clist->focus_row, -1, 1, 0);
	}
      else if (top < 0)
	gtk_cmclist_moveto (clist, clist->focus_row, -1, 0, 0);
      else if (top + clist->row_height > clist->clist_window_height)
	gtk_cmclist_moveto (clist, clist->focus_row, -1, 1, 0);

      y1 = ROW_TOP_YPIXEL (clist, s1) - 1;
      h1 = (e1 - s1 + 1) * (clist->row_height + CELL_SPACING);
    }

  /* extend the selection between s2 and e2 */
  if (s2 >= 0)
    {
      for (i = s2, list = g_list_nth (clist->row_list, i); i <= e2;
	   i++, list = list->next)
	if (GTK_CMCLIST_ROW (list)->selectable &&
	    GTK_CMCLIST_ROW (list)->state != clist->anchor_state)
	  GTK_CMCLIST_ROW (list)->state = clist->anchor_state;

      top = ROW_TOP_YPIXEL (clist, clist->focus_row);

      if (top + clist->row_height <= 0)
	{
	  area.y = 0;
	  area.height = ROW_TOP_YPIXEL (clist, e2) + clist->row_height;
	  draw_rows (clist, &area);
	  gtk_cmclist_moveto (clist, clist->focus_row, -1, 0, 0);
	}
      else if (top >= clist->clist_window_height)
	{
	  area.y = ROW_TOP_YPIXEL (clist, s2) - 1;
	  area.height = clist->clist_window_height - area.y;
	  draw_rows (clist, &area);
	  gtk_cmclist_moveto (clist, clist->focus_row, -1, 1, 0);
	}
      else if (top < 0)
	gtk_cmclist_moveto (clist, clist->focus_row, -1, 0, 0);
      else if (top + clist->row_height > clist->clist_window_height)
	gtk_cmclist_moveto (clist, clist->focus_row, -1, 1, 0);

      y2 = ROW_TOP_YPIXEL (clist, s2) - 1;
      h2 = (e2 - s2 + 1) * (clist->row_height + CELL_SPACING);
    }

  area.y = MAX (0, MIN (y1, y2));
  if (area.y > clist->clist_window_height)
    area.y = 0;
  area.height = MIN (clist->clist_window_height, h1 + h2);
  if (s1 >= 0 && s2 >= 0)
    area.height += (clist->row_height + CELL_SPACING);
  draw_rows (clist, &area);
}

static void
start_selection (GtkCMCList *clist)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (clist_has_grab (clist))
    return;

  set_anchor (clist, GTK_CMCLIST_ADD_MODE(clist), clist->focus_row,
	      clist->focus_row);
}

static void
end_selection (GtkCMCList *clist)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (gtkut_pointer_is_grabbed (GTK_WIDGET (clist)) &&
      gtk_widget_has_focus (GTK_WIDGET(clist)))
    return;

  GTK_CMCLIST_GET_CLASS (clist)->resync_selection (clist, NULL);
}

static void
extend_selection (GtkCMCList      *clist,
		  GtkScrollType  scroll_type,
		  gfloat         position,
		  gboolean       auto_start_selection)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (clist_has_grab (clist) ||
      clist->selection_mode != GTK_SELECTION_MULTIPLE)
    return;

  if (auto_start_selection)
    set_anchor (clist, GTK_CMCLIST_ADD_MODE(clist), clist->focus_row,
		clist->focus_row);
  else if (clist->anchor == -1)
    return;

  move_focus_row (clist, scroll_type, position);

  if (ROW_TOP_YPIXEL (clist, clist->focus_row) + clist->row_height >
      clist->clist_window_height)
    gtk_cmclist_moveto (clist, clist->focus_row, -1, 1, 0);
  else if (ROW_TOP_YPIXEL (clist, clist->focus_row) < 0)
    gtk_cmclist_moveto (clist, clist->focus_row, -1, 0, 0);

  update_extended_selection (clist, clist->focus_row);
}

static void
sync_selection (GtkCMCList *clist,
		gint      row,
		gint      mode)
{
  GList *list;
  gint d;

  if (mode == SYNC_INSERT)
    d = 1;
  else
    d = -1;
      
  if (clist->focus_row >= row)
    {
      if (d > 0 || clist->focus_row > row)
	clist->focus_row += d;
      if (clist->focus_row == -1 && clist->rows >= 1)
	clist->focus_row = 0;
      else if (d < 0 && clist->focus_row >= clist->rows - 1)
	clist->focus_row = clist->rows - 2;
      else if (clist->focus_row >= clist->rows)	/* Paranoia */
	clist->focus_row = clist->rows - 1;
    }

  GTK_CMCLIST_GET_CLASS (clist)->resync_selection (clist, NULL);

  g_list_free (clist->undo_selection);
  g_list_free (clist->undo_unselection);
  clist->undo_selection = NULL;
  clist->undo_unselection = NULL;

  clist->anchor = -1;
  clist->drag_pos = -1;
  clist->undo_anchor = clist->focus_row;

  list = clist->selection;

  while (list)
    {
      if (GPOINTER_TO_INT (list->data) >= row)
	list->data = ((gchar*) list->data) + d;
      list = list->next;
    }
}

/* GTKOBJECT
 *   gtk_cmclist_destroy
 *   gtk_cmclist_finalize
 */
static void gtk_cmclist_destroy (GtkWidget *object)

{
  gint i;
  GtkCMCList *clist;

  cm_return_if_fail (GTK_IS_CMCLIST (object));

  clist = GTK_CMCLIST (object);

  /* freeze the list */
  clist->freeze_count++;

  /* get rid of all the rows */
  gtk_cmclist_clear (clist);

  /* Since we don't have a _remove method, unparent the children
   * instead of destroying them so the focus will be unset properly.
   * (For other containers, the _remove method takes care of the
   * unparent) The destroy will happen when the refcount drops
   * to zero.
   */

  /* unref adjustments */
  if (clist->hadjustment)
    {
      g_signal_handlers_disconnect_matched(G_OBJECT (clist->hadjustment), G_SIGNAL_MATCH_DATA,
		      	0, 0, 0, 0, clist);
      g_object_unref (G_OBJECT (clist->hadjustment));
      clist->hadjustment = NULL;
    }
  if (clist->vadjustment)
    {
      g_signal_handlers_disconnect_matched(G_OBJECT (clist->vadjustment), G_SIGNAL_MATCH_DATA,
		      	0, 0, 0, 0, clist);
      g_object_unref (G_OBJECT (clist->vadjustment));
      clist->vadjustment = NULL;
    }

  remove_grab (clist);

  /* destroy the column buttons */
  for (i = 0; i < clist->columns; i++)
    if (clist->column[i].button)
      {
	gtk_widget_unparent (clist->column[i].button);
	clist->column[i].button = NULL;
      }

  if (GTK_WIDGET_CLASS (gtk_cmclist_parent_class)->destroy)
    (*GTK_WIDGET_CLASS (gtk_cmclist_parent_class)->destroy) (object);
}

static void
gtk_cmclist_finalize (GObject *object)
{
  GtkCMCList *clist;

  cm_return_if_fail (GTK_IS_CMCLIST (object));

  clist = GTK_CMCLIST (object);

  columns_delete (clist);

  G_OBJECT_CLASS (gtk_cmclist_parent_class)->finalize (object);
}

/* GTKWIDGET
 *   gtk_cmclist_realize
 *   gtk_cmclist_unrealize
 *   gtk_cmclist_map
 *   gtk_cmclist_unmap
 *   gtk_cmclist_draw
 *   gtk_cmclist_style_set
 *   gtk_cmclist_button_press
 *   gtk_cmclist_button_release
 *   gtk_cmclist_motion
 *   gtk_cmclist_size_request
 *   gtk_cmclist_size_allocate
 */
static void
gtk_cmclist_realize (GtkWidget *widget)
{
  GtkAllocation allocation;
  GtkCMCList *clist;
  GtkStyleContext *style_context;
  GtkStateFlags state;
  GtkBorder padding;
  GdkWindow *window;
  GdkWindowAttr attributes;
  GtkCMCListRow *clist_row;
  GList *list;
  gint attributes_mask;
  gint event_mask;
  gint i;
  gint j;

  cm_return_if_fail (GTK_IS_CMCLIST (widget));

  clist = GTK_CMCLIST (widget);

  gtk_widget_set_realized (widget, TRUE);

  gtk_widget_get_allocation (widget, &allocation);
  
  attributes.window_type = GDK_WINDOW_CHILD;
  attributes.x = allocation.x;
  attributes.y = allocation.y;
  attributes.width = allocation.width;
  attributes.height = allocation.height;
  attributes.wclass = GDK_INPUT_OUTPUT;
  attributes.visual = gtk_widget_get_visual (widget);

  event_mask = gtk_widget_get_events (widget);
  attributes_mask = GDK_WA_X | GDK_WA_Y | GDK_WA_VISUAL;

  attributes.event_mask = GDK_VISIBILITY_NOTIFY_MASK;

  /* main window */
  window = gdk_window_new (gtk_widget_get_parent_window (widget),
				   &attributes, attributes_mask);
  gtk_widget_set_window (widget, window);
  gtk_widget_register_window (widget, window);

  style_context = gtk_widget_get_style_context (widget);
  state = gtk_widget_get_state_flags(widget);
  gtk_style_context_set_background (style_context, window);

  /* column-title window */

  attributes.x = clist->column_title_area.x;
  attributes.y = clist->column_title_area.y;
  attributes.width = clist->column_title_area.width;
  attributes.height = clist->column_title_area.height;
 
  clist->title_window = gdk_window_new (window, &attributes,
					attributes_mask);
  gtk_widget_register_window (widget, clist->title_window);

  gtk_style_context_set_background (style_context, clist->title_window);
  gdk_window_show (clist->title_window);

  /* set things up so column buttons are drawn in title window */
  for (i = 0; i < clist->columns; i++)
    if (clist->column[i].button)
      gtk_widget_set_parent_window (clist->column[i].button,
				    clist->title_window);

  /* clist-window */
  gtk_style_context_get_padding(style_context, state, &padding);
  attributes.x = (clist->internal_allocation.x +
                  padding.left);
  attributes.y = (clist->internal_allocation.y +
                  padding.top +
                  clist->column_title_area.height);
  attributes.width = clist->clist_window_width;
  attributes.height = clist->clist_window_height;
  attributes.event_mask = event_mask |
    GDK_SCROLL_MASK |
    GDK_SMOOTH_SCROLL_MASK |
    GDK_POINTER_MOTION_MASK |
    GDK_KEY_RELEASE_MASK |
    GDK_BUTTON_PRESS_MASK |
    GDK_BUTTON_RELEASE_MASK;
  
  clist->clist_window = gdk_window_new (window, &attributes,
					attributes_mask);
  gtk_widget_register_window (widget, clist->clist_window);

  gdk_window_show (clist->clist_window);
  clist->clist_window_width = gdk_window_get_width(clist->clist_window);
  clist->clist_window_height = gdk_window_get_height(clist->clist_window);

  /* create resize windows */
  attributes.wclass = GDK_INPUT_ONLY;
  attributes_mask = GDK_WA_CURSOR;
  attributes.cursor = gdk_cursor_new_for_display (gtk_widget_get_display (widget),
						  GDK_SB_H_DOUBLE_ARROW);
  clist->cursor_drag = attributes.cursor;

  attributes.x =  LIST_WIDTH (clist) + 1;
  attributes.y = 0;
  attributes.width = 0;
  attributes.height = 0;
  attributes.event_mask = event_mask |
    GDK_BUTTON_PRESS_MASK |
    GDK_BUTTON_RELEASE_MASK |
    GDK_POINTER_MOTION_MASK;

  for (i = 0; i < clist->columns; i++)
    {
      clist->column[i].window = gdk_window_new (clist->title_window,
						&attributes, attributes_mask);
      gtk_widget_register_window (widget, clist->column[i].window);
    }

  /* This is slightly less efficient than creating them with the
   * right size to begin with, but easier
   */
  size_allocate_title_buttons (clist);

  /* attach optional row/cell styles, allocate foreground/background colors */
  list = clist->row_list;
  for (i = 0; i < clist->rows; i++)
    {
      clist_row = list->data;
      list = list->next;

      if (clist_row->style)
	clist_row->style = gtk_style_attach (clist_row->style,
					     clist->clist_window);

      for (j = 0; j < clist->columns; j++)
	if  (clist_row->cell[j].style)
	  clist_row->cell[j].style =
	    gtk_style_attach (clist_row->cell[j].style, clist->clist_window);
    }
}

static void
gtk_cmclist_unrealize (GtkWidget *widget)
{
  gint i;
  GtkCMCList *clist;

  cm_return_if_fail (GTK_IS_CMCLIST (widget));

  clist = GTK_CMCLIST (widget);

  /* freeze the list */
  clist->freeze_count++;

  if (gtk_widget_get_mapped (widget))
    gtk_cmclist_unmap (widget);

  gtk_widget_set_mapped (widget, FALSE);

  /* detach optional row/cell styles */
  if (gtk_widget_get_realized (widget))
    {
      GtkCMCListRow *clist_row;
      GList *list;
      gint j;

      list = clist->row_list;
      for (i = 0; i < clist->rows; i++)
	{
	  clist_row = list->data;
	  list = list->next;

	  if (clist_row->style)
	    gtk_style_detach (clist_row->style);
	  for (j = 0; j < clist->columns; j++)
	    if  (clist_row->cell[j].style)
	      gtk_style_detach (clist_row->cell[j].style);
	}
    }

  gdk_cursor_unref (clist->cursor_drag);

  for (i = 0; i < clist->columns; i++)
    {
      if (clist->column[i].button)
	gtk_widget_unrealize (clist->column[i].button);
      if (clist->column[i].window)
	{
	  gtk_widget_unregister_window (widget, clist->column[i].window);
	  gdk_window_destroy (clist->column[i].window);
	  clist->column[i].window = NULL;
	}
    }

  gtk_widget_unregister_window (widget, clist->clist_window);
  gdk_window_destroy (clist->clist_window);
  clist->clist_window = NULL;

  gtk_widget_unregister_window (widget, clist->title_window);
  gdk_window_destroy (clist->title_window);
  clist->title_window = NULL;

  clist->cursor_drag = NULL;

  if (GTK_WIDGET_CLASS (gtk_cmclist_parent_class)->unrealize)
    (* GTK_WIDGET_CLASS (gtk_cmclist_parent_class)->unrealize) (widget);
}

static void
gtk_cmclist_map (GtkWidget *widget)
{
  gint i;
  GtkCMCList *clist;

  cm_return_if_fail (GTK_IS_CMCLIST (widget));

  clist = GTK_CMCLIST (widget);

  if (!gtk_widget_get_mapped (widget))
    {
      gtk_widget_set_mapped (widget, TRUE);

      /* map column buttons */
      for (i = 0; i < clist->columns; i++)
	{
	  if (clist->column[i].button &&
	      gtk_widget_get_visible (clist->column[i].button) &&
	      !gtk_widget_get_mapped (clist->column[i].button))
	    gtk_widget_map (clist->column[i].button);
	}
      
      for (i = 0; i < clist->columns; i++)
	if (clist->column[i].window && clist->column[i].button)
	  {
	    gdk_window_raise (clist->column[i].window);
	    gdk_window_show (clist->column[i].window);
	  }

      gdk_window_show (clist->title_window);
      gdk_window_show (clist->clist_window);
      gdk_window_show (gtk_widget_get_window (widget));

      /* unfreeze the list */
      clist->freeze_count = 0;
    }
}

static void
gtk_cmclist_unmap (GtkWidget *widget)
{
  gint i;
  GtkCMCList *clist;

  cm_return_if_fail (GTK_IS_CMCLIST (widget));

  clist = GTK_CMCLIST (widget);

  if (gtk_widget_get_mapped (widget))
    {
      gtk_widget_set_mapped (widget, FALSE);

      if (clist_has_grab (clist))
	{
	  remove_grab (clist);

	  GTK_CMCLIST_GET_CLASS (widget)->resync_selection (clist, NULL);

	  clist->click_cell.row = -1;
	  clist->click_cell.column = -1;
	  clist->drag_button = 0;

	  if (GTK_CMCLIST_IN_DRAG(clist))
	    {
	      gpointer drag_data;

	      GTK_CMCLIST_UNSET_FLAG (clist, CMCLIST_IN_DRAG);
	      drag_data = g_object_get_data (G_OBJECT (clist),
					       "gtk-site-data");
	      if (drag_data)
	      	g_signal_handlers_unblock_matched(G_OBJECT(clist), G_SIGNAL_MATCH_DATA,
					0, 0, 0, 0, drag_data);
	    }
	}

      for (i = 0; i < clist->columns; i++)
	if (clist->column[i].window)
	  gdk_window_hide (clist->column[i].window);

      gdk_window_hide (clist->clist_window);
      gdk_window_hide (clist->title_window);
      gdk_window_hide (gtk_widget_get_window (widget));

      /* unmap column buttons */
      for (i = 0; i < clist->columns; i++)
	if (clist->column[i].button &&
	    gtk_widget_get_mapped (clist->column[i].button))
	  gtk_widget_unmap (clist->column[i].button);

      /* freeze the list */
      clist->freeze_count++;
    }
}

static gint
gtk_cmclist_draw (GtkWidget *widget,
          cairo_t *cr)
{
  GtkCMCList *clist;

  cm_return_val_if_fail (GTK_IS_CMCLIST (widget), FALSE);
  cm_return_val_if_fail (cr != NULL, FALSE);

  if (gtk_widget_is_drawable (widget))
    {
      clist = GTK_CMCLIST (widget);
      clist->draw_now = 0;

      /* Draw clist_window */
      if (gtk_cairo_should_draw_window (cr, clist->clist_window))
        {
        GdkRectangle area;

        /* The painting area is currently relative to GdkWindow
         * of the entire widget, we're only interested in the
         * part that is inside clist_window. */
        /* First, get geometry of clist_window in coordinates
         * relative to the parent window. */
        gdk_window_get_position(clist->clist_window, &area.x, &area.y);
        area.height = gdk_window_get_height(clist->clist_window);
        area.width = gdk_window_get_width(clist->clist_window);

        /* Store current state of the painting area, as we will
         * want to use it for title_window later. */
        cairo_save(cr);

        /* Now clip the painting area to just the part that is inside
         * clist_window, and call draw_rows() with a GdkRectangle
         * corresponding to that. */
        gdk_cairo_rectangle(cr, &area);
        cairo_clip(cr);

        if (gdk_cairo_get_clip_rectangle (cr, &area))
          {
          gdouble x, y;

          /* Before we pass the area to draw_rows(), we need to
           * transform it to coordinates relative to clist_window.
           * We already made sure that it is entirely inside
           * this window, so no further checks have to be made. */
          gdk_window_coords_from_parent(clist->clist_window, area.x, area.y, &x, &y);
          area.x = x;
          area.y = y;

          draw_rows (clist, &area);
          }

        /* Restore the original painting area for further use. */
        cairo_restore(cr);
        }

      /* Draw title_window - just propagate the draw event
       * to the individual button widgets, they can draw
       * themselves. */
      if (gtk_cairo_should_draw_window (cr, clist->title_window))
        {
          gint i;

          for (i = 0; i < clist->columns; i++)
            {
              if (clist->column[i].button) {
                gtk_container_propagate_draw (GTK_CONTAINER (clist), clist->column[i].button, cr);
              }
            }
        }
       clist->draw_now = 1;
    }
  return FALSE;
}

static void
gtk_cmclist_style_set (GtkWidget *widget,
		     GtkStyle  *previous_style)
{
  GtkCMCList *clist;
  GtkStyleContext *style_context;

  cm_return_if_fail (GTK_IS_CMCLIST (widget));

  if (GTK_WIDGET_CLASS (gtk_cmclist_parent_class)->style_set)
    (*GTK_WIDGET_CLASS (gtk_cmclist_parent_class)->style_set) (widget, previous_style);

  clist = GTK_CMCLIST (widget);

  if (gtk_widget_get_realized (widget))
    {
      style_context = gtk_widget_get_style_context (widget);
      gtk_style_context_set_background (style_context, gtk_widget_get_window (widget));
      gtk_style_context_set_background (style_context, clist->title_window);
    }

  /* Fill in data after widget has correct style */

  /* text properties */
  if (!GTK_CMCLIST_ROW_HEIGHT_SET(clist))
    /* Reset clist->row_height */
    gtk_cmclist_set_row_height (clist, 0);

  /* Column widths */
  if (!GTK_CMCLIST_AUTO_RESIZE_BLOCKED (clist))
    {
      gint width;
      gint i;

      for (i = 0; i < clist->columns; i++)
	if (clist->column[i].auto_resize)
	  {
	    width = gtk_cmclist_optimal_column_width (clist, i);
	    if (width != clist->column[i].width)
	      gtk_cmclist_set_column_width (clist, i, width);
	  }
    }
}

static gint
gtk_cmclist_button_press (GtkWidget      *widget,
			GdkEventButton *event)
{
  gint i;
  GtkCMCList *clist;
  gint x;
  gint y;
  gint row;
  gint column;
  gint button_actions;

  cm_return_val_if_fail (GTK_IS_CMCLIST (widget), FALSE);
  cm_return_val_if_fail (event != NULL, FALSE);

  clist = GTK_CMCLIST (widget);

  button_actions = clist->button_actions[event->button - 1];

  if (button_actions == GTK_CMBUTTON_IGNORED)
    return FALSE;

  /* selections on the list */
  if (event->window == clist->clist_window)
    {
      x = event->x;
      y = event->y;

      if (get_selection_info (clist, x, y, &row, &column))
	{
	  gint old_row = clist->focus_row;

	  if (clist->focus_row == -1)
	    old_row = row;

	  if (event->type == GDK_BUTTON_PRESS)
	    {
	      GdkEventMask mask = ((1 << (4 + event->button)) |
				   GDK_POINTER_MOTION_HINT_MASK |
				   GDK_BUTTON_RELEASE_MASK);

	      if (gdk_pointer_grab (clist->clist_window, FALSE, mask,
				    NULL, NULL, event->time))
		return FALSE;
	      gtk_grab_add (widget);

	      clist->click_cell.row = row;
	      clist->click_cell.column = column;
	      clist->drag_button = event->button;
	    }
	  else
	    {
	      clist->click_cell.row = -1;
	      clist->click_cell.column = -1;

	      clist->drag_button = 0;
	      remove_grab (clist);
	    }

	  if (button_actions & GTK_CMBUTTON_SELECTS)
	    {
	      if (GTK_CMCLIST_ADD_MODE(clist))
		{
		  GTK_CMCLIST_UNSET_FLAG (clist, CMCLIST_ADD_MODE);
		  if (gtk_widget_has_focus(widget))
		    {
		      gtk_cmclist_undraw_focus (widget);
		      clist->focus_row = row;
		      gtk_cmclist_draw_focus (widget);
		    }
		  else
		    {
		      clist->focus_row = row;
		    }
		}
	      else if (row != clist->focus_row)
		{
		  if (gtk_widget_has_focus(widget))
		    {
		      gtk_cmclist_undraw_focus (widget);
		      clist->focus_row = row;
		      gtk_cmclist_draw_focus (widget);
		    }
		  else
		    clist->focus_row = row;
		}
	    }

	  if (!gtk_widget_has_focus(widget))
	    gtk_widget_grab_focus (widget);

	  if (button_actions & GTK_CMBUTTON_SELECTS)
	    {
	      switch (clist->selection_mode)
		{
		case GTK_SELECTION_SINGLE:
		  if (event->type != GDK_BUTTON_PRESS)
		    {
		      g_signal_emit (G_OBJECT (clist),
				       clist_signals[SELECT_ROW], 0,
				       row, column, event);
		      clist->anchor = -1;
		    }
		  else
		    clist->anchor = row;
		  break;
		case GTK_SELECTION_BROWSE:
		  g_signal_emit (G_OBJECT (clist),
				   clist_signals[SELECT_ROW], 0,
				   row, column, event);
		  break;
		case GTK_SELECTION_MULTIPLE:
		  if (event->type != GDK_BUTTON_PRESS)
		    {
		      if (clist->anchor != -1)
			{
			  update_extended_selection (clist, clist->focus_row);
			  GTK_CMCLIST_GET_CLASS (clist)->resync_selection
			    (clist, (GdkEvent *) event);
			}
		      g_signal_emit (G_OBJECT (clist),
				       clist_signals[SELECT_ROW], 0,
				       row, column, event);
		      break;
		    }
	      
		  if (event->state & GDK_CONTROL_MASK)
		    {
		      if (event->state & GDK_SHIFT_MASK)
			{
			  if (clist->anchor < 0)
			    {
			      g_list_free (clist->undo_selection);
			      g_list_free (clist->undo_unselection);
			      clist->undo_selection = NULL;
			      clist->undo_unselection = NULL;
			      clist->anchor = old_row;
			      clist->drag_pos = old_row;
			      clist->undo_anchor = old_row;
			    }
			  update_extended_selection (clist, clist->focus_row);
			}
		      else
			{
			  if (clist->anchor == -1)
			    set_anchor (clist, TRUE, row, old_row);
			  else
			    update_extended_selection (clist,
						       clist->focus_row);
			}
		      break;
		    }

		  if (event->state & GDK_SHIFT_MASK)
		    {
		      set_anchor (clist, FALSE, old_row, old_row);
		      update_extended_selection (clist, clist->focus_row);
		      break;
		    }

		  if (clist->anchor == -1)
		    set_anchor (clist, FALSE, row, old_row);
		  else
		    update_extended_selection (clist, clist->focus_row);
		  break;
		default:
		  break;
		}
	    }
	}
      return TRUE;
    }

  /* press on resize windows */
  for (i = 0; i < clist->columns; i++)
    if (clist->column[i].resizeable && clist->column[i].window &&
	event->window == clist->column[i].window)
      {
	gpointer drag_data;

	if (gdk_pointer_grab (clist->column[i].window, FALSE,
			      GDK_POINTER_MOTION_HINT_MASK |
			      GDK_BUTTON1_MOTION_MASK |
			      GDK_BUTTON_RELEASE_MASK,
			      NULL, NULL, event->time))
	  return FALSE;

	gtk_grab_add (widget);
	GTK_CMCLIST_SET_FLAG (clist, CMCLIST_IN_DRAG);

	/* block attached dnd signal handler */
	drag_data = g_object_get_data (G_OBJECT (clist), "gtk-site-data");
	if (drag_data)
	      	g_signal_handlers_block_matched(G_OBJECT(clist), G_SIGNAL_MATCH_DATA,
					0, 0, 0, 0, drag_data);

	if (!gtk_widget_has_focus(widget))
	  gtk_widget_grab_focus (widget);

	clist->drag_pos = i;
	clist->x_drag = (COLUMN_LEFT_XPIXEL(clist, i) + COLUMN_INSET +
			 clist->column[i].area.width + CELL_SPACING);

        return TRUE;
      }

  return FALSE;
}

static gint
gtk_cmclist_button_release (GtkWidget      *widget,
			  GdkEventButton *event)
{
  GtkCMCList *clist;
  gint button_actions;

  cm_return_val_if_fail (GTK_IS_CMCLIST (widget), FALSE);
  cm_return_val_if_fail (event != NULL, FALSE);

  clist = GTK_CMCLIST (widget);

  button_actions = clist->button_actions[event->button - 1];
  if (button_actions == GTK_CMBUTTON_IGNORED)
    return FALSE;

  /* release on resize windows */
  if (GTK_CMCLIST_IN_DRAG(clist))
    {
      gpointer drag_data;
      gint width;
      gint x;
      gint i;

      i = clist->drag_pos;
      clist->drag_pos = -1;

      /* unblock attached dnd signal handler */
      drag_data = g_object_get_data (G_OBJECT (clist), "gtk-site-data");
      if (drag_data)
	      	g_signal_handlers_unblock_matched(G_OBJECT(clist), G_SIGNAL_MATCH_DATA,
					0, 0, 0, 0, drag_data);

      GTK_CMCLIST_UNSET_FLAG (clist, CMCLIST_IN_DRAG);
      gtk_widget_get_pointer (widget, &x, NULL);
      gtk_grab_remove (widget);
      gdk_display_pointer_ungrab (gtk_widget_get_display (widget), event->time);

      if (clist->x_drag >= 0)
	clist_refresh(clist);

      width = new_column_width (clist, i, &x);
      gtk_cmclist_set_column_width (clist, i, width);

      return TRUE;
    }

  if (clist->drag_button == event->button)
    {
      gint row;
      gint column;

      clist->drag_button = 0;
      clist->click_cell.row = -1;
      clist->click_cell.column = -1;

      remove_grab (clist);

      if (button_actions & GTK_CMBUTTON_SELECTS)
	{
	  switch (clist->selection_mode)
	    {
	    case GTK_SELECTION_MULTIPLE:
	      if (!(event->state & GDK_SHIFT_MASK) ||
		  !gtk_widget_get_can_focus (widget) ||
		  event->x < 0 || event->x >= clist->clist_window_width ||
		  event->y < 0 || event->y >= clist->clist_window_height)
		GTK_CMCLIST_GET_CLASS (clist)->resync_selection
		  (clist, (GdkEvent *) event);
	      break;
	    case GTK_SELECTION_SINGLE:
	      if (get_selection_info (clist, event->x, event->y,
				      &row, &column))
		{
		  if (row >= 0 && row < clist->rows && clist->anchor == row)
		    toggle_row (clist, row, column, (GdkEvent *) event);
		}
	      clist->anchor = -1;
	      break;
	    default:
	      break;
	    }
	}

      return TRUE;
    }
  
  return FALSE;
}

static gint
gtk_cmclist_motion (GtkWidget      *widget,
		  GdkEventMotion *event)
{
  GtkCMCList *clist;
  gint x;
  gint y;
  gint row;
  gint new_width;
  gint button_actions = 0;
  guint value;

  cm_return_val_if_fail (GTK_IS_CMCLIST (widget), FALSE);

  clist = GTK_CMCLIST (widget);
  if (!clist_has_grab (clist))
    return FALSE;

  if (clist->drag_button > 0)
    button_actions = clist->button_actions[clist->drag_button - 1];

  if (GTK_CMCLIST_IN_DRAG(clist))
    {
      if (event->is_hint || event->window != gtk_widget_get_window (widget))
	gtk_widget_get_pointer (widget, &x, NULL);
      else
	x = event->x;
      
      new_width = new_column_width (clist, clist->drag_pos, &x);
      if (x != clist->x_drag)
	{
	  /* x_drag < 0 indicates that the xor line is already invisible */
	  if (clist->x_drag >= 0)
	    clist_refresh(clist);

	  clist->x_drag = x;

	  if (clist->x_drag >= 0)
	    draw_xor_line (clist);
	}

      if (new_width <= MAX (COLUMN_MIN_WIDTH + 1,
			    clist->column[clist->drag_pos].min_width + 1))
	{
	  if (COLUMN_LEFT_XPIXEL (clist, clist->drag_pos) < 0 && x < 0)
	    gtk_cmclist_moveto (clist, -1, clist->drag_pos, 0, 0);
	  return FALSE;
	}
      if (clist->column[clist->drag_pos].max_width >= COLUMN_MIN_WIDTH &&
	  new_width >= clist->column[clist->drag_pos].max_width)
	{
	  if (COLUMN_LEFT_XPIXEL (clist, clist->drag_pos) + new_width >
	      clist->clist_window_width && x < 0)
	    move_horizontal (clist,
			     COLUMN_LEFT_XPIXEL (clist, clist->drag_pos) +
			     new_width - clist->clist_window_width +
			     COLUMN_INSET + CELL_SPACING);
	  return FALSE;
	}
    }

  if (event->is_hint || event->window != clist->clist_window) {
		GdkDisplay *display;
		GdkSeat *seat;

		display = gdk_window_get_display(event->window);
		seat = gdk_display_get_default_seat(display);
		gdk_device_get_position(gdk_seat_get_pointer(seat),
				NULL, &x, &y);
    }
  else
    {
      x = event->x;
      y = event->y;
    }

  if (GTK_CMCLIST_REORDERABLE(clist) && button_actions & GTK_CMBUTTON_DRAGS)
    {
      /* delayed drag start */
      if (event->window == clist->clist_window &&
	  clist->click_cell.row >= 0 && clist->click_cell.column >= 0 &&
	  (y < 0 || y >= clist->clist_window_height ||
	   x < 0 || x >= clist->clist_window_width  ||
	   y < ROW_TOP_YPIXEL (clist, clist->click_cell.row) ||
	   y >= (ROW_TOP_YPIXEL (clist, clist->click_cell.row) +
		 clist->row_height) ||
	   x < COLUMN_LEFT_XPIXEL (clist, clist->click_cell.column) ||
	   x >= (COLUMN_LEFT_XPIXEL(clist, clist->click_cell.column) + 
		 clist->column[clist->click_cell.column].area.width)))
	{
	  GtkTargetList  *target_list;

	  target_list = gtk_target_list_new (&clist_target_table, 1);
	  gtk_drag_begin_with_coordinates(widget, target_list, GDK_ACTION_MOVE,
			  clist->drag_button, (GdkEvent *)event, -1, -1);

	}
      return TRUE;
    }

  /* horizontal autoscrolling */
  if (clist->hadjustment && LIST_WIDTH (clist) > clist->clist_window_width &&
      (x < 0 || x >= clist->clist_window_width))
    {
      if (clist->htimer)
	return FALSE;

      clist->htimer = gdk_threads_add_timeout
	(SCROLL_TIME, (GSourceFunc) horizontal_timeout, clist);
      value = gtk_adjustment_get_value (clist->hadjustment);
      if (!((x < 0 && value == 0) ||
	    (x >= clist->clist_window_width &&
	     value ==
	     LIST_WIDTH (clist) - clist->clist_window_width)))
	{
	  if (x < 0)
	    move_horizontal (clist, -1 + (x/2));
	  else
	    move_horizontal (clist, 1 + (x - clist->clist_window_width) / 2);
	}
    }

  if (GTK_CMCLIST_IN_DRAG(clist))
    return FALSE;

  /* vertical autoscrolling */
  row = ROW_FROM_YPIXEL (clist, y);

  /* don't scroll on last pixel row if it's a cell spacing */
  if (y == clist->clist_window_height - 1 &&
      y == ROW_TOP_YPIXEL (clist, row-1) + clist->row_height)
    return FALSE;

  if (LIST_HEIGHT (clist) > clist->clist_window_height &&
      (y < 0 || y >= clist->clist_window_height))
    {
      if (clist->vtimer)
	return FALSE;
      clist->vtimer = gdk_threads_add_timeout (SCROLL_TIME,
				     (GSourceFunc) vertical_timeout, clist);
      if (clist->drag_button &&
	  ((y < 0 && clist->focus_row == 0) ||
	   (y >= clist->clist_window_height &&
	    clist->focus_row == clist->rows - 1)))
	return FALSE;
    }

  row = CLAMP (row, 0, clist->rows - 1);

  if (button_actions & GTK_CMBUTTON_SELECTS &&
      !g_object_get_data (G_OBJECT (widget), "gtk-site-data"))
    {
      if (row == clist->focus_row)
	return FALSE;

      gtk_cmclist_undraw_focus (widget);
      clist->focus_row = row;
      gtk_cmclist_draw_focus (widget);

      switch (clist->selection_mode)
	{
	case GTK_SELECTION_BROWSE:
	  g_signal_emit (G_OBJECT (clist), clist_signals[SELECT_ROW], 0,
			   clist->focus_row, -1, event);
	  break;
	case GTK_SELECTION_MULTIPLE:
	  update_extended_selection (clist, clist->focus_row);
	  break;
	default:
	  break;
	}
    }
  
  if (ROW_TOP_YPIXEL(clist, row) < 0)
    move_vertical (clist, row, 0);
  else if (ROW_TOP_YPIXEL(clist, row) + clist->row_height >
	   clist->clist_window_height)
    move_vertical (clist, row, 1);

  return FALSE;
}

static void
gtk_cmclist_get_preferred_width (GtkWidget *widget,
                                 gint      *minimal_width,
                                 gint      *natural_width)
{
  GtkRequisition requisition;

  gtk_cmclist_size_request (widget, &requisition);

  *minimal_width = *natural_width = requisition.width;
}

static void
gtk_cmclist_get_preferred_height (GtkWidget *widget,
                                  gint      *minimal_height,
                                  gint      *natural_height)
{
  GtkRequisition requisition;

  gtk_cmclist_size_request (widget, &requisition);

  *minimal_height = *natural_height = requisition.height;
}

static void
gtk_cmclist_size_request (GtkWidget      *widget,
			GtkRequisition *requisition)
{
  GtkCMCList *clist;
  GtkStyle *style;
  gint i;
  guint border_width;
  cm_return_if_fail (GTK_IS_CMCLIST (widget));
  cm_return_if_fail (requisition != NULL);

  clist = GTK_CMCLIST (widget);
  style = gtk_widget_get_style (widget);

  requisition->width = 0;
  requisition->height = 0;

  /* compute the size of the column title (title) area */
  clist->column_title_area.height = 0;
  if (GTK_CMCLIST_SHOW_TITLES(clist)) {
    for (i = 0; i < clist->columns; i++)
      if (clist->column[i].button)
	{
	  GtkRequisition child_requisition;
	  
	  gtk_widget_get_preferred_size(clist->column[i].button,
				   &child_requisition, NULL);
	  clist->column_title_area.height =
	    MAX (clist->column_title_area.height,
		 child_requisition.height);
	}
    //clist->column_title_area.height = font_height;
  }
  border_width = gtk_container_get_border_width (GTK_CONTAINER (widget));
  requisition->width += (style->xthickness +
			 border_width) * 2;
  requisition->height += (clist->column_title_area.height +
			  (style->ythickness +
			   border_width) * 2);

  /* if (!clist->hadjustment) */
  requisition->width += list_requisition_width (clist);
  /* if (!clist->vadjustment) */
  requisition->height += LIST_HEIGHT (clist);
}

static void
gtk_cmclist_size_allocate (GtkWidget     *widget,
			 GtkAllocation *allocation)
{
  GtkStyle *style;
  GtkCMCList *clist;
  GtkAllocation clist_allocation;
  gint border_width;

  cm_return_if_fail (GTK_IS_CMCLIST (widget));
  cm_return_if_fail (allocation != NULL);

  style = gtk_widget_get_style (widget);
  clist = GTK_CMCLIST (widget);
  gtk_widget_set_allocation (widget, allocation);
  border_width = gtk_container_get_border_width (GTK_CONTAINER (widget));

  if (gtk_widget_get_realized (widget))
    {
      gdk_window_move_resize (gtk_widget_get_window (widget),
			      allocation->x + border_width,
			      allocation->y + border_width,
			      allocation->width - border_width * 2,
			      allocation->height - border_width * 2);
    }

  /* use internal allocation structure for all the math
   * because it's easier than always subtracting the container
   * border width */
  clist->internal_allocation.x = 0;
  clist->internal_allocation.y = 0;
  clist->internal_allocation.width = MAX (1, (gint)allocation->width -
					  border_width * 2);
  clist->internal_allocation.height = MAX (1, (gint)allocation->height -
					   border_width * 2);
	
  /* allocate clist window assuming no scrollbars */
  clist_allocation.x = (clist->internal_allocation.x +
			style->xthickness);
  clist_allocation.y = (clist->internal_allocation.y +
			style->ythickness +
			clist->column_title_area.height);
  clist_allocation.width = MAX (1, (gint)clist->internal_allocation.width - 
				(2 * (gint)style->xthickness));
  clist_allocation.height = MAX (1, (gint)clist->internal_allocation.height -
				 (2 * (gint)style->ythickness) -
				 (gint)clist->column_title_area.height);
  
  clist->clist_window_width = clist_allocation.width;
  clist->clist_window_height = clist_allocation.height;
  
  if (gtk_widget_get_realized (widget))
    {
      gdk_window_move_resize (clist->clist_window,
			      clist_allocation.x,
			      clist_allocation.y,
			      clist_allocation.width,
			      clist_allocation.height);
    }
  
  /* position the window which holds the column title buttons */
  clist->column_title_area.x = style->xthickness;
  clist->column_title_area.y = style->ythickness;
  clist->column_title_area.width = clist_allocation.width;
  
  if (gtk_widget_get_realized (widget))
    {
      gdk_window_move_resize (clist->title_window,
			      clist->column_title_area.x,
			      clist->column_title_area.y,
			      clist->column_title_area.width,
			      clist->column_title_area.height);
    }
  
  /* column button allocation */
  size_allocate_columns (clist, FALSE);
  size_allocate_title_buttons (clist);

  adjust_adjustments (clist, TRUE);
}

/* GTKCONTAINER
 *   gtk_cmclist_forall
 */
static void
gtk_cmclist_forall (GtkContainer *container,
		  gboolean      include_internals,
		  GtkCallback   callback,
		  gpointer      callback_data)
{
  GtkCMCList *clist;
  guint i;

  cm_return_if_fail (GTK_IS_CMCLIST (container));
  cm_return_if_fail (callback != NULL);

  if (!include_internals)
    return;

  clist = GTK_CMCLIST (container);
      
  /* callback for the column buttons */
  for (i = 0; i < clist->columns; i++)
    if (clist->column[i].button)
      (*callback) (clist->column[i].button, callback_data);
}

/* PRIVATE DRAWING FUNCTIONS
 *   get_cell_style
 *   draw_cell_pixbuf
 *   draw_row
 *   draw_rows
 *   draw_xor_line
 *   clist_refresh
 */
static void
get_cell_style (GtkCMCList     *clist,
		GtkCMCListRow  *clist_row,
		gint          state,
		gint          column,
		GtkStyle    **style)
{
  GtkStyle *gtkstyle;

  if (clist_row->cell[column].style)
    {
      if (style)
	*style = clist_row->cell[column].style;
    }
  else if (clist_row->style)
    {
      if (style)
	*style = clist_row->style;
    }
  else
    {
      gtkstyle = gtk_widget_get_style (GTK_WIDGET (clist));
      if (style)
	*style = gtkstyle;
    }
}

static gint
draw_cell_pixbuf (GdkWindow    *window,
		  GdkRectangle *clip_rectangle,
		  cairo_t      *cr,
		  GdkPixbuf    *pixbuf,
		  gint          x,
		  gint          y,
		  gint          width,
		  gint          height)
{
  gint xsrc = 0;
  gint ysrc = 0;

  if (!pixbuf || (width == 0 && height == 0))
	return x;

  if (x < clip_rectangle->x)
    {
      xsrc = clip_rectangle->x - x;
      width -= xsrc;
      x = clip_rectangle->x;
    }
  if (x + width > clip_rectangle->x + clip_rectangle->width)
    width = clip_rectangle->x + clip_rectangle->width - x;

  if (y < clip_rectangle->y)
    {
      ysrc = clip_rectangle->y - y;
      height -= ysrc;
      y = clip_rectangle->y;
    }

  if (y + height > clip_rectangle->y + clip_rectangle->height)
    height = clip_rectangle->y + clip_rectangle->height - y;

  gdk_cairo_set_source_pixbuf(cr, pixbuf, x, y);
  cairo_paint(cr);

  return x + MAX (width, 0);
}

static void cairo_dash_from_add_mode(GtkCMCList *clist, cairo_t *cr)
{
	const double dashes[] = { 4.0, 4.0 };
	if (GTK_CMCLIST_ADD_MODE(clist)) 
		cairo_set_dash(cr, dashes, 2, 0);
	else
		cairo_set_dash(cr, NULL, 0, 0);
}

static void
draw_row (GtkCMCList     *clist,
	  GdkRectangle *area,
	  gint          row,
	  GtkCMCListRow  *clist_row)
{
  GtkStyle *style;
  GtkWidget *widget;
  GdkRectangle *rect;
  GdkRectangle row_rectangle;
  GdkRectangle cell_rectangle;
  GdkRectangle clip_rectangle;
  GdkRectangle intersect_rectangle;
  gint last_column;
  gint state;
  gint i;
  cairo_t *cr;
  cm_return_if_fail (clist != NULL);

  if (clist->draw_now) {
      gtk_widget_queue_draw(GTK_WIDGET(clist));
      return;
  }

  /* bail now if we arn't drawable yet */
  if (!gtk_widget_is_drawable (GTK_WIDGET(clist)) || row < 0 || row >= clist->rows)
    return;

  widget = GTK_WIDGET (clist);

  /* if the function is passed the pointer to the row instead of null,
   * it avoids this expensive lookup */
  if (!clist_row)
    clist_row = ROW_ELEMENT (clist, row)->data;

  style = clist_row->style ? clist_row->style : gtk_widget_get_style (widget);

  /* rectangle of the entire row */
  row_rectangle.x = 0;
  row_rectangle.y = ROW_TOP_YPIXEL (clist, row);
  row_rectangle.width = clist->clist_window_width;
  row_rectangle.height = clist->row_height;

  /* rectangle of the cell spacing above the row */
  cell_rectangle.x = 0;
  cell_rectangle.y = row_rectangle.y - CELL_SPACING;
  cell_rectangle.width = row_rectangle.width;
  cell_rectangle.height = CELL_SPACING;

  /* rectangle used to clip drawing operations, its y and height
   * positions only need to be set once, so we set them once here. 
   * the x and width are set withing the drawing loop below once per
   * column */
  clip_rectangle.y = row_rectangle.y;
  clip_rectangle.height = row_rectangle.height;

  state = clist_row->state;
  cr = gdk_cairo_create(clist->clist_window);

  /* draw the cell borders and background */
  if (area)
    {
      rect = &intersect_rectangle;
      if (gdk_rectangle_intersect (area, &cell_rectangle,
				   &intersect_rectangle)) {
		gdk_cairo_rectangle(cr, &intersect_rectangle);
		gdk_cairo_set_source_color(cr, &style->base[GTK_STATE_NORMAL]);
		cairo_fill(cr);
      }

      /* the last row has to clear its bottom cell spacing too */
      if (clist_row == clist->row_list_end->data)
	{
	  cell_rectangle.y += clist->row_height + CELL_SPACING;

	  if (gdk_rectangle_intersect (area, &cell_rectangle,
				       &intersect_rectangle)) {
	     gdk_cairo_rectangle(cr, &intersect_rectangle);
	     gdk_cairo_set_source_color(cr, &style->base[GTK_STATE_NORMAL]);
	     cairo_fill(cr);
	    }
	}

      if (!gdk_rectangle_intersect (area, &row_rectangle,&intersect_rectangle))
	return;

    }
  else
    {
      rect = &clip_rectangle;
      gdk_cairo_rectangle(cr, &cell_rectangle);
      gdk_cairo_set_source_color(cr, &style->base[GTK_STATE_NORMAL]);
      cairo_fill(cr);

      /* the last row has to clear its bottom cell spacing too */
      if (clist_row == clist->row_list_end->data)
	{
	  cell_rectangle.y += clist->row_height + CELL_SPACING;
	  gdk_cairo_rectangle(cr, &cell_rectangle);
	  gdk_cairo_set_source_color(cr, &style->base[GTK_STATE_NORMAL]);
	  cairo_fill(cr);
	}	  
    }
  
  for (last_column = clist->columns - 1;
       last_column >= 0 && !clist->column[last_column].visible; last_column--)
    ;

  /* iterate and draw all the columns (row cells) and draw their contents */
  for (i = 0; i < clist->columns; i++)
    {
      GtkStyle *style;
      PangoLayout *layout;
      PangoRectangle logical_rect;

      gint width;
      gint height;
      gint pixbuf_width;
      gint offset = 0;

      if (!clist->column[i].visible)
	continue;

      get_cell_style (clist, clist_row, state, i, &style);

      clip_rectangle.x = clist->column[i].area.x + clist->hoffset;
      clip_rectangle.width = clist->column[i].area.width;

      /* calculate clipping region clipping region */
      clip_rectangle.x -= COLUMN_INSET + CELL_SPACING;
      clip_rectangle.width += (2 * COLUMN_INSET + CELL_SPACING +
			       (i == last_column) * CELL_SPACING);
      
      if (area && !gdk_rectangle_intersect (area, &clip_rectangle,
					    &intersect_rectangle))
	continue;

      gdk_cairo_rectangle(cr, rect);
      gdk_cairo_set_source_color(cr, &style->base[state]);
      cairo_fill(cr);

      clip_rectangle.x += COLUMN_INSET + CELL_SPACING;
      clip_rectangle.width -= (2 * COLUMN_INSET + CELL_SPACING +
			       (i == last_column) * CELL_SPACING);


      /* calculate real width for column justification */
      
      layout = _gtk_cmclist_create_cell_layout (clist, clist_row, i);
      if (layout)
	{
	  pango_layout_get_pixel_extents (layout, NULL, &logical_rect);
	  width = logical_rect.width;
	}
      else
	width = 0;

      pixbuf_width = 0;
      height = 0;
      offset = 0;
      switch (clist_row->cell[i].type)
	{
	case GTK_CMCELL_PIXBUF:
	  pixbuf_width = gdk_pixbuf_get_width(GTK_CMCELL_PIXBUF (clist_row->cell[i])->pixbuf);
	  height = gdk_pixbuf_get_height(GTK_CMCELL_PIXBUF (clist_row->cell[i])->pixbuf);
	  width += pixbuf_width;
	  break;
	case GTK_CMCELL_PIXTEXT:
	  pixbuf_width = gdk_pixbuf_get_width(GTK_CMCELL_PIXTEXT (clist_row->cell[i])->pixbuf);
	  height = gdk_pixbuf_get_height(GTK_CMCELL_PIXTEXT (clist_row->cell[i])->pixbuf);
	  width += pixbuf_width + GTK_CMCELL_PIXTEXT (clist_row->cell[i])->spacing;
	  break;
	default:
	  break;
	}

      switch (clist->column[i].justification)
	{
	case GTK_JUSTIFY_LEFT:
	  offset = clip_rectangle.x + clist_row->cell[i].horizontal;
	  break;
	case GTK_JUSTIFY_RIGHT:
	  offset = (clip_rectangle.x + clist_row->cell[i].horizontal +
		    clip_rectangle.width - width);
	  break;
	case GTK_JUSTIFY_CENTER:
	case GTK_JUSTIFY_FILL:
	  offset = (clip_rectangle.x + clist_row->cell[i].horizontal +
		    (clip_rectangle.width / 2) - (width / 2));
	  break;
	};

      /* Draw Text and/or Pixbuf */
      switch (clist_row->cell[i].type)
	{
	case GTK_CMCELL_PIXBUF:
	  draw_cell_pixbuf (clist->clist_window, &clip_rectangle, cr,
			    GTK_CMCELL_PIXBUF (clist_row->cell[i])->pixbuf,
			    offset,
			    clip_rectangle.y + clist_row->cell[i].vertical +
			    (clip_rectangle.height - height) / 2,
			    pixbuf_width, height);
	  break;
	case GTK_CMCELL_PIXTEXT:
	  offset =
	    draw_cell_pixbuf (clist->clist_window, &clip_rectangle, cr,
			      GTK_CMCELL_PIXTEXT (clist_row->cell[i])->pixbuf,
			      offset,
			      clip_rectangle.y + clist_row->cell[i].vertical+
			      (clip_rectangle.height - height) / 2,
			      pixbuf_width, height);
	  offset += GTK_CMCELL_PIXTEXT (clist_row->cell[i])->spacing;

	  /* Fall through */
	case GTK_CMCELL_TEXT:
	  if (layout)
	    {
	      gint row_center_offset = (clist->row_height - logical_rect.height - 1) / 2;
	      gdk_cairo_set_source_color(cr, clist_row->fg_set ? &clist_row->foreground : &style->text[state]);
	      cairo_move_to(cr, offset, row_rectangle.y + row_center_offset + clist_row->cell[i].vertical);
	      pango_cairo_show_layout(cr, layout);
              g_object_unref (G_OBJECT (layout));
	    }
	  break;
	default:
	  break;
	}
    }

  /* draw focus rectangle */
  cairo_dash_from_add_mode(clist, cr);
  cairo_set_line_width(cr, 1.0);
  cairo_set_antialias(cr, CAIRO_ANTIALIAS_NONE);
  if (clist->focus_row == row &&
      gtk_widget_get_can_focus (widget) && gtk_widget_has_focus(widget))
    {
      if (!area) {
	cairo_rectangle(cr, row_rectangle.x, row_rectangle.y,
			    row_rectangle.width + 1, row_rectangle.height);
	gdk_cairo_set_source_color(cr, &style->text[GTK_STATE_NORMAL]);
	cairo_stroke(cr);
      }
      else if (gdk_rectangle_intersect (area, &row_rectangle,
					&intersect_rectangle))
	{
	  cairo_rectangle(cr, row_rectangle.x, row_rectangle.y,
			    row_rectangle.width + 1, row_rectangle.height);
	  gdk_cairo_set_source_color(cr, &style->text[GTK_STATE_NORMAL]);
	  cairo_stroke(cr);
	}
    }
    cairo_destroy(cr);

}

static void
draw_rows (GtkCMCList     *clist,
	   GdkRectangle *area)
{
  GList *list;
  GtkCMCListRow *clist_row;
  gint i;
  gint first_row;
  gint last_row;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (clist->row_height == 0 ||
      !gtk_widget_is_drawable (GTK_WIDGET(clist)))
    return;

  if (area)
    {
      first_row = ROW_FROM_YPIXEL (clist, area->y);
      last_row = ROW_FROM_YPIXEL (clist, area->y + area->height);
    }
  else
    {
      first_row = ROW_FROM_YPIXEL (clist, 0);
      last_row = ROW_FROM_YPIXEL (clist, clist->clist_window_height);
    }

   /* this is a small special case which exposes the bottom cell line
    * on the last row -- it might go away if I change the wall the cell
    * spacings are drawn
    */
  if (clist->rows == first_row)
    first_row--;

  list = ROW_ELEMENT (clist, first_row);
  i = first_row;
  while (list)
    {
      clist_row = list->data;
      list = list->next;

      if (i > last_row)
	return;

      GTK_CMCLIST_GET_CLASS (clist)->draw_row (clist, NULL, i, clist_row);
      i++;
    }

  if (!area) {
    if (!clist->draw_now) {
      int w, h, y;
      cairo_t *cr;
      w = gdk_window_get_width(clist->clist_window);
      h = gdk_window_get_height(clist->clist_window);
      cr = gdk_cairo_create(clist->clist_window);
      y = ROW_TOP_YPIXEL (clist, i);
      gdk_cairo_set_source_color(cr, &gtk_widget_get_style(GTK_WIDGET(clist))->base[GTK_STATE_NORMAL]);
      cairo_rectangle(cr, 0, y, w, h - y);
      cairo_fill(cr);
      cairo_destroy(cr);
    } else {
      gtk_widget_queue_draw(GTK_WIDGET(clist));
    }
  }
}

static void                          
draw_xor_line (GtkCMCList *clist)
{
  cairo_t *cr;
  cr = gdk_cairo_create(clist->clist_window);
  cairo_set_line_width(cr, 1.0);
  cairo_move_to(cr, clist->x_drag,
		 gtk_widget_get_style (GTK_WIDGET(clist))->ythickness);
  cairo_line_to(cr, clist->x_drag,
                 clist->column_title_area.height +
		 clist->clist_window_height + 1);
  cairo_stroke(cr);
  cairo_destroy(cr);
}

static void
clist_refresh (GtkCMCList *clist)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));
  
  if (CLIST_UNFROZEN (clist))
    { 
      adjust_adjustments (clist, FALSE);
      draw_rows (clist, NULL);
    }
}

/* get cell from coordinates
 *   get_selection_info
 *   gtk_cmclist_get_selection_info
 */
static gint
get_selection_info (GtkCMCList *clist,
		    gint      x,
		    gint      y,
		    gint     *row,
		    gint     *column)
{
  gint trow, tcol;

  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), 0);

  /* bounds checking, return false if the user clicked 
   * on a blank area */
  trow = ROW_FROM_YPIXEL (clist, y);
  if (trow >= clist->rows)
    return 0;

  if (row)
    *row = trow;

  tcol = COLUMN_FROM_XPIXEL (clist, x);
  if (tcol >= clist->columns)
    return 0;

  if (column)
    *column = tcol;

  return 1;
}

gint
gtk_cmclist_get_selection_info (GtkCMCList *clist, 
			      gint      x, 
			      gint      y, 
			      gint     *row, 
			      gint     *column)
{
  cm_return_val_if_fail (GTK_IS_CMCLIST (clist), 0);
  return get_selection_info (clist, x, y, row, column);
}

/* PRIVATE ADJUSTMENT FUNCTIONS
 *   adjust_adjustments
 *   vadjustment_changed
 *   hadjustment_changed
 *   vadjustment_value_changed
 *   hadjustment_value_changed 
 *   check_exposures
 */
static void
adjust_adjustments (GtkCMCList *clist,
		    gboolean  block_resize)
{
  if (clist->vadjustment)
    {
      g_object_freeze_notify(G_OBJECT(clist->vadjustment));
      gtk_adjustment_set_page_size (clist->vadjustment, clist->clist_window_height);
      gtk_adjustment_set_step_increment (clist->vadjustment, clist->row_height);
      gtk_adjustment_set_page_increment (clist->vadjustment,
	MAX (clist->clist_window_height - clist->row_height,
	     clist->clist_window_height / 2));
      gtk_adjustment_set_lower (clist->vadjustment, 0);
      gtk_adjustment_set_upper (clist->vadjustment, LIST_HEIGHT (clist));
      g_object_thaw_notify(G_OBJECT(clist->vadjustment));

      if ((clist->clist_window_height - clist->voffset) > LIST_HEIGHT (clist) ||
	  (clist->voffset + (gint)gtk_adjustment_get_value (clist->vadjustment)) != 0)
	{
	  gtk_adjustment_set_value (clist->vadjustment,
	   MAX (0, (LIST_HEIGHT (clist) - clist->clist_window_height)));
	  g_signal_emit_by_name (G_OBJECT (clist->vadjustment),
				   "value_changed");
	}
      g_signal_emit_by_name (G_OBJECT (clist->vadjustment), "changed");
    }

  if (clist->hadjustment)
    {
      g_object_freeze_notify(G_OBJECT(clist->hadjustment));
      gtk_adjustment_set_page_size (clist->hadjustment, clist->clist_window_width);
      gtk_adjustment_set_step_increment (clist->hadjustment, 10);
      gtk_adjustment_set_page_increment (clist->hadjustment,
	MAX (clist->clist_window_width -
         gtk_adjustment_get_step_increment (clist->hadjustment),
	     clist->clist_window_width / 2));
      gtk_adjustment_set_lower (clist->hadjustment, 0);
      gtk_adjustment_set_upper (clist->hadjustment, LIST_WIDTH (clist));
      g_object_thaw_notify(G_OBJECT(clist->hadjustment));

      if ((clist->clist_window_width - clist->hoffset) > LIST_WIDTH (clist) ||
	  (clist->hoffset + (gint)gtk_adjustment_get_value (clist->hadjustment)) != 0)
	{
	  gtk_adjustment_set_value (clist->hadjustment, MAX (0, (LIST_WIDTH (clist) -
					       clist->clist_window_width)));
	  g_signal_emit_by_name (G_OBJECT (clist->hadjustment),
				   "value_changed");
	}
      g_signal_emit_by_name (G_OBJECT (clist->hadjustment), "changed");
    }

  if (!block_resize && (!clist->vadjustment || !clist->hadjustment))
    {
      GtkWidget *widget;
      GtkRequisition requisition;
      GtkAllocation allocation;

      widget = GTK_WIDGET (clist);
      gtk_widget_get_preferred_size(widget, &requisition, NULL);
      gtk_widget_get_allocation (widget, &allocation);

      if ((!clist->hadjustment &&
	   requisition.width != allocation.width) ||
	  (!clist->vadjustment &&
	   requisition.height != allocation.height))
	gtk_widget_queue_resize (widget);
    }
}

static void
vadjustment_value_changed (GtkAdjustment *adjustment,
			   gpointer       data)
{
  GtkCMCList *clist;
  gint dy, value;

  cm_return_if_fail (adjustment != NULL);
  cm_return_if_fail (GTK_IS_CMCLIST (data));

  clist = GTK_CMCLIST (data);

  if (adjustment != clist->vadjustment)
    return;

  value = -gtk_adjustment_get_value (adjustment);
  dy = value - clist->voffset;
  clist->voffset = value;

  if (gtk_widget_is_drawable (GTK_WIDGET(clist)))
    {
      gdk_window_scroll (clist->clist_window, 0, dy);
    }
  
  return;
}

typedef struct
{
  GdkWindow *window;
  gint dx;
} ScrollData;

/* The window to which widget->window is relative */
#define ALLOCATION_WINDOW(widget)		\
   (!gtk_widget_get_has_window (widget) ?		\
	gtk_widget_get_window (widget) :         \
	gdk_window_get_parent (gtk_widget_get_window(widget)))

static void
adjust_allocation_recurse (GtkWidget *widget,
			   gpointer   data)
{
  GtkAllocation allocation;
  ScrollData *scroll_data = data;

  gtk_widget_get_allocation (widget, &allocation);
  
  if (!gtk_widget_get_realized (widget))
    {
      if (gtk_widget_get_visible (widget))
	{
	  GdkRectangle tmp_rectangle = allocation;
	  tmp_rectangle.x += scroll_data->dx;
      
	  gtk_widget_size_allocate (widget, &tmp_rectangle);
	}
    }
  else
    {
      if (ALLOCATION_WINDOW (widget) == scroll_data->window)
	{
	  allocation.x += scroll_data->dx;
	  gtk_widget_set_allocation (widget, &allocation);

	  if (GTK_IS_CONTAINER (widget))
	    gtk_container_forall (GTK_CONTAINER (widget),
				  adjust_allocation_recurse,
				  data);
	}
    }
}

static void
adjust_allocation (GtkWidget *widget,
		   gint       dx)
{
  ScrollData scroll_data;

  if (gtk_widget_get_realized (widget))
    scroll_data.window = ALLOCATION_WINDOW (widget);
  else
    scroll_data.window = NULL;
    
  scroll_data.dx = dx;
  
  adjust_allocation_recurse (widget, &scroll_data);
}

static void
hadjustment_value_changed (GtkAdjustment *adjustment,
			   gpointer       data)
{
  GtkCMCList *clist;
  GtkContainer *container;
  gint i;
  gint y = 0;
  gint value;
  gint dx;
  cairo_t *cr;

  cm_return_if_fail (adjustment != NULL);
  cm_return_if_fail (GTK_IS_CMCLIST (data));

  clist = GTK_CMCLIST (data);
  container = GTK_CONTAINER (data);

  if (adjustment != clist->hadjustment)
    return;

  value = gtk_adjustment_get_value (adjustment);

  dx = -value - clist->hoffset;

  if (gtk_widget_get_realized (GTK_WIDGET(clist)))
    gdk_window_scroll (clist->title_window, dx, 0);

  /* adjust the column button's allocations */
  for (i = 0; i < clist->columns; i++)
    if (clist->column[i].button)
      adjust_allocation (clist->column[i].button, dx);

  clist->hoffset = -value;

  cr = gdk_cairo_create(clist->clist_window);
  cairo_dash_from_add_mode(clist, cr);
  cairo_set_line_width(cr, 1.0);
  cairo_set_antialias(cr, CAIRO_ANTIALIAS_NONE);
  if (gtk_widget_is_drawable (GTK_WIDGET(clist)))
    {
      GtkWidget *focus_child = gtk_container_get_focus_child (container);
 
      gdk_window_scroll (clist->clist_window, dx, 0);

      if (gtk_widget_get_can_focus(GTK_WIDGET(clist)) && 
          gtk_widget_has_focus(GTK_WIDGET(clist)) &&
          !focus_child && GTK_CMCLIST_ADD_MODE(clist))
        {
          y = ROW_TOP_YPIXEL (clist, clist->focus_row);
	  cairo_rectangle(cr, 0, y, clist->clist_window_width + 1,
                              clist->row_height);
	  cairo_stroke(cr);
        }

      if (gtk_widget_get_can_focus(GTK_WIDGET(clist)) && 
          gtk_widget_has_focus(GTK_WIDGET(clist)) &&
          !focus_child)
        {
          if (GTK_CMCLIST_ADD_MODE(clist))
            {
              gint focus_row;
	  
              focus_row = clist->focus_row;
              clist->focus_row = -1;
              draw_rows (clist, NULL);
              clist->focus_row = focus_row;
	  
	      cairo_rectangle(cr, 0, y, clist->clist_window_width + 1,
                              clist->row_height);
	      cairo_stroke(cr);
              return;
            }
        }
    }
    cairo_destroy(cr);
}

/* PRIVATE 
 * Memory Allocation/Distruction Routines for GtkCMCList stuctures
 *
 * functions:
 *   columns_new
 *   column_title_new
 *   columns_delete
 *   row_new
 *   row_delete
 */
static GtkCMCListColumn *
columns_new (GtkCMCList *clist)
{
  GtkCMCListColumn *column;
  gint i;

  column = g_new (GtkCMCListColumn, clist->columns);

  for (i = 0; i < clist->columns; i++)
    {
      column[i].area.x = 0;
      column[i].area.y = 0;
      column[i].area.width = 0;
      column[i].area.height = 0;
      column[i].title = NULL;
      column[i].button = NULL;
      column[i].window = NULL;
      column[i].width = 0;
      column[i].min_width = -1;
      column[i].max_width = -1;
      column[i].visible = TRUE;
      column[i].width_set = FALSE;
      column[i].resizeable = TRUE;
      column[i].auto_resize = FALSE;
      column[i].button_passive = FALSE;
      column[i].justification = GTK_JUSTIFY_LEFT;
    }

  return column;
}

static void
column_title_new (GtkCMCList    *clist,
		  gint         column,
		  const gchar *title)
{
  g_free (clist->column[column].title);

  clist->column[column].title = g_strdup (title);
}

static void
columns_delete (GtkCMCList *clist)
{
  gint i;

  for (i = 0; i < clist->columns; i++)
    g_free (clist->column[i].title);
      
  g_free (clist->column);
}

static GtkCMCListRow *
row_new (GtkCMCList *clist)
{
  int i;
  GtkCMCListRow *clist_row;

  clist_row = g_slice_new (GtkCMCListRow);
  clist_row->cell = g_slice_alloc (sizeof (GtkCMCell) * clist->columns);

  for (i = 0; i < clist->columns; i++)
    {
      clist_row->cell[i].type = GTK_CMCELL_EMPTY;
      clist_row->cell[i].vertical = 0;
      clist_row->cell[i].horizontal = 0;
      clist_row->cell[i].style = NULL;
    }

  clist_row->fg_set = FALSE;
  clist_row->bg_set = FALSE;
  clist_row->style = NULL;
  clist_row->selectable = TRUE;
  clist_row->state = GTK_STATE_NORMAL;
  clist_row->data = NULL;
  clist_row->destroy = NULL;

  return clist_row;
}

static void
row_delete (GtkCMCList    *clist,
	    GtkCMCListRow *clist_row)
{
  gint i;

  for (i = 0; i < clist->columns; i++)
    {
      GTK_CMCLIST_GET_CLASS (clist)->set_cell_contents
	(clist, clist_row, i, GTK_CMCELL_EMPTY, NULL, 0, NULL);
      if (clist_row->cell[i].style)
	{
	  if (gtk_widget_get_realized (GTK_WIDGET(clist)))
	    gtk_style_detach (clist_row->cell[i].style);
	  g_object_unref (clist_row->cell[i].style);
	}
    }

  if (clist_row->style)
    {
      if (gtk_widget_get_realized (GTK_WIDGET(clist)))
        gtk_style_detach (clist_row->style);
      g_object_unref (clist_row->style);
    }

  if (clist_row->destroy)
    clist_row->destroy (clist_row->data);

  g_slice_free1 (sizeof (GtkCMCell) * clist->columns, clist_row->cell);
  g_slice_free (GtkCMCListRow, clist_row);
}

/* FOCUS FUNCTIONS
 *   gtk_cmclist_focus_content_area
 *   gtk_cmclist_focus
 *   gtk_cmclist_draw_focus
 *   gtk_cmclist_focus_in
 *   gtk_cmclist_focus_out
 *   title_focus
 */
static void
gtk_cmclist_focus_content_area (GtkCMCList *clist)
{
  if (clist->focus_row < 0)
    {
      clist->focus_row = 0;
      
      if ((clist->selection_mode == GTK_SELECTION_BROWSE ||
	   clist->selection_mode == GTK_SELECTION_MULTIPLE) &&
	  !clist->selection)
	g_signal_emit (G_OBJECT (clist),
			 clist_signals[SELECT_ROW], 0,
			 clist->focus_row, -1, NULL);
    }
  gtk_widget_grab_focus (GTK_WIDGET (clist));
}

static gboolean
gtk_cmclist_focus (GtkWidget        *widget,
		 GtkDirectionType  direction)
{
  GtkCMCList *clist = GTK_CMCLIST (widget);
  GtkWidget *focus_child;
  gboolean is_current_focus;

  if (!gtk_widget_is_sensitive (widget))
    return FALSE;

  focus_child = gtk_container_get_focus_child (GTK_CONTAINER (widget));
  
  is_current_focus = gtk_widget_is_focus (GTK_WIDGET (clist));
			  
  if (focus_child &&
      gtk_widget_child_focus (focus_child, direction))
    return TRUE;
      
  switch (direction)
    {
    case GTK_DIR_LEFT:
    case GTK_DIR_RIGHT:
      if (focus_child)
	{
	  if (title_focus_move (clist, direction))
	    return TRUE;
	}
      else if (!is_current_focus)
	{
	  gtk_cmclist_focus_content_area (clist);
	  return TRUE;
	}
      break;
    case GTK_DIR_DOWN:
    case GTK_DIR_TAB_FORWARD:
      if (!focus_child && !is_current_focus)
	{
	  if (title_focus_in (clist, direction))
	    return TRUE;
	}
      
      if (!is_current_focus && clist->rows)
	{
	  gtk_cmclist_focus_content_area (clist);
	  return TRUE;
	}
      break;
    case GTK_DIR_UP:
    case GTK_DIR_TAB_BACKWARD:
      if (!focus_child && is_current_focus)
	{
	  if (title_focus_in (clist, direction))
	    return TRUE;
	}
      
      if (!is_current_focus && !focus_child && clist->rows)
	{
	  gtk_cmclist_focus_content_area (clist);
	  return TRUE;
	}
      break;
    default:
      break;
    }

  return FALSE;
}

static void
gtk_cmclist_set_focus_child (GtkContainer *container,
			   GtkWidget    *child)
{
  GtkCMCList *clist = GTK_CMCLIST (container);
  gint i;

  for (i = 0; i < clist->columns; i++)
    if (clist->column[i].button == child)
      clist->focus_header_column = i;
  
  if (GTK_CONTAINER_CLASS (gtk_cmclist_parent_class)->set_focus_child)
    (*GTK_CONTAINER_CLASS (gtk_cmclist_parent_class)->set_focus_child) (container, child);
}

static void
gtk_cmclist_draw_focus (GtkWidget *widget)
{
  GtkCMCList *clist;
  cairo_t *cr;

  cm_return_if_fail (GTK_IS_CMCLIST (widget));

  if (!gtk_widget_is_drawable (widget) || !gtk_widget_get_can_focus (widget))
    return;

  clist = GTK_CMCLIST (widget);
  if (clist->focus_row >= 0) {
    if (!clist->draw_now) {
      cr = gdk_cairo_create(clist->clist_window);
      cairo_dash_from_add_mode(clist, cr);
      cairo_set_line_width(cr, 1.0);
      cairo_set_antialias(cr, CAIRO_ANTIALIAS_NONE);
      cairo_rectangle(cr, 0, ROW_TOP_YPIXEL(clist, clist->focus_row) + 0.5,
              clist->clist_window_width + 1,
              clist->row_height - 0.5);
      cairo_stroke(cr);
      cairo_destroy(cr);
    } else {
      gtk_widget_queue_draw(GTK_WIDGET(clist));
    }
  }
}

static void
gtk_cmclist_undraw_focus (GtkWidget *widget)
{
  GtkCMCList *clist;
  int row;
  cm_return_if_fail (GTK_IS_CMCLIST (widget));

  clist = GTK_CMCLIST(widget);

  if (clist->focus_row < 0)
    return;

  if (!gtk_widget_is_drawable (widget) || !gtk_widget_get_can_focus (widget))
    return;

  clist = GTK_CMCLIST (widget);
  if (clist->focus_row >= 0) {
    if (!clist->draw_now) {
      cairo_t *cr = gdk_cairo_create(clist->clist_window);
      cairo_set_line_width(cr, 1.0);
      gdk_cairo_set_source_color(cr, &gtk_widget_get_style(widget)->base[GTK_STATE_NORMAL]);
      cairo_set_antialias(cr, CAIRO_ANTIALIAS_NONE);
      cairo_rectangle(cr, 0, ROW_TOP_YPIXEL(clist, clist->focus_row) + 0.5,
              clist->clist_window_width + 1,
              clist->row_height - 0.5);
      cairo_stroke(cr);
      cairo_destroy(cr);
    } else {
      gtk_widget_queue_draw(GTK_WIDGET(clist));
    }
  }

  row = clist->focus_row;
  GTK_CMCLIST_GET_CLASS(GTK_CMCLIST(widget))->draw_row(clist, NULL, row, ROW_ELEMENT (clist, row)->data);
}

static gint
gtk_cmclist_focus_in (GtkWidget     *widget,
		    GdkEventFocus *event)
{
  GtkCMCList *clist = GTK_CMCLIST (widget);

  if (clist->selection_mode == GTK_SELECTION_BROWSE &&
      clist->selection == NULL && clist->focus_row > -1)
    {
      GList *list;

      list = g_list_nth (clist->row_list, clist->focus_row);
      if (list && GTK_CMCLIST_ROW (list)->selectable)
	g_signal_emit (G_OBJECT (clist), clist_signals[SELECT_ROW], 0,
			 clist->focus_row, -1, event);
      else
	gtk_cmclist_draw_focus (widget);
    }
  else
    gtk_cmclist_undraw_focus (widget);

  return FALSE;
}

static gint
gtk_cmclist_focus_out (GtkWidget     *widget,
		     GdkEventFocus *event)
{
  GtkCMCList *clist = GTK_CMCLIST (widget);

  gtk_cmclist_undraw_focus (widget);
  
  GTK_CMCLIST_GET_CLASS (widget)->resync_selection (clist, (GdkEvent *) event);

  return FALSE;
}

static gboolean
focus_column (GtkCMCList *clist, gint column, gint dir)
{
  GtkWidget *child = clist->column[column].button;
  
  if (gtk_widget_child_focus (child, dir))
    {
      return TRUE;
    }
  else if (gtk_widget_get_can_focus (child))
    {
      gtk_widget_grab_focus (child);
      return TRUE;
    }

  return FALSE;
}

/* Focus moved onto the headers. Focus first focusable and visible child.
 * (FIXME: focus the last focused child if visible)
 */
static gboolean
title_focus_in (GtkCMCList *clist, gint dir)
{
  gint i;
  gint left, right;

  if (!GTK_CMCLIST_SHOW_TITLES (clist))
    return FALSE;

  /* Check last focused column */
  if (clist->focus_header_column != -1)
    {
      i = clist->focus_header_column;
      
      left = COLUMN_LEFT_XPIXEL (clist, i);
      right = left + clist->column[i].area.width;
      
      if (left >= 0 && right <= clist->clist_window_width)
	{
	  if (focus_column (clist, i, dir))
	    return TRUE;
	}
    }

  /* Check fully visible columns */
  for (i = 0 ; i < clist->columns ; i++)
    {
      left = COLUMN_LEFT_XPIXEL (clist, i);
      right = left + clist->column[i].area.width;
      
      if (left >= 0 && right <= clist->clist_window_width)
	{
	  if (focus_column (clist, i, dir))
	    return TRUE;
	}
    }

  /* Check partially visible columns */
  for (i = 0 ; i < clist->columns ; i++)
    {
      left = COLUMN_LEFT_XPIXEL (clist, i);
      right = left + clist->column[i].area.width;

      if ((left < 0 && right > 0) ||
	  (left < clist->clist_window_width && right > clist->clist_window_width))
	{
	  if (focus_column (clist, i, dir))
	    return TRUE;
	}
    }
      
  return FALSE;
}

/* Move the focus right or left within the title buttons, scrolling
 * as necessary to keep the focused child visible.
 */
static gboolean
title_focus_move (GtkCMCList *clist,
		  gint      dir)
{
  GtkWidget *focus_child;
  gboolean return_val = FALSE;
  gint d = 0;
  gint i = -1;
  gint j;

  if (!GTK_CMCLIST_SHOW_TITLES(clist))
    return FALSE;

  focus_child = gtk_container_get_focus_child (GTK_CONTAINER (clist));
  g_assert (focus_child);

  /* Movement direction within headers
   */
  switch (dir)
    {
    case GTK_DIR_RIGHT:
      d = 1;
      break;
    case GTK_DIR_LEFT:
      d = -1;
      break;
    }
  
  for (i = 0; i < clist->columns; i++)
    if (clist->column[i].button == focus_child)
      break;
  
  g_assert (i != -1);		/* Have a starting column */
  
  j = i + d;
  while (!return_val && j >= 0 && j < clist->columns)
    {
      if (clist->column[j].button &&
	  gtk_widget_get_visible (clist->column[j].button))
	{
	  if (focus_column (clist, j, dir))
	    {
	      return_val = TRUE;
	      break;
	    }
	}
      j += d;
    }

  /* If we didn't find it, wrap around and keep looking
   */
  if (!return_val)
    {
      j = d > 0 ? 0 : clist->columns - 1;

      while (!return_val && j != i)
	{
	  if (clist->column[j].button &&
	      gtk_widget_get_visible (clist->column[j].button))
	    {
	      if (focus_column (clist, j, dir))
		{
		  return_val = TRUE;
		  break;
		}
	    }
	  j += d;
	}
    }

  /* Scroll horizontally so focused column is visible
   */
  if (return_val)
    {
      if (COLUMN_LEFT_XPIXEL (clist, j) < CELL_SPACING + COLUMN_INSET)
	gtk_cmclist_moveto (clist, -1, j, 0, 0);
      else if (COLUMN_LEFT_XPIXEL(clist, j) + clist->column[j].area.width >
	       clist->clist_window_width)
	{
	  gint last_column;
	  
	  for (last_column = clist->columns - 1;
	       last_column >= 0 && !clist->column[last_column].visible; last_column--);

	  if (j == last_column)
	    gtk_cmclist_moveto (clist, -1, j, 0, 0);
	  else
	    gtk_cmclist_moveto (clist, -1, j, 0, 1);
	}
    }
  return TRUE;			/* Even if we didn't find a new one, we can keep the
				 * focus in the same place.
				 */
}

/* PRIVATE SCROLLING FUNCTIONS
 *   move_focus_row
 *   scroll_horizontal
 *   scroll_vertical
 *   move_horizontal
 *   move_vertical
 *   horizontal_timeout
 *   vertical_timeout
 *   remove_grab
 */
static void
move_focus_row (GtkCMCList      *clist,
		GtkScrollType  scroll_type,
		gfloat         position)
{
  GtkWidget *widget;

  cm_return_if_fail (clist != 0);
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  widget = GTK_WIDGET (clist);

  switch (scroll_type)
    {
    case GTK_SCROLL_STEP_UP:
    case GTK_SCROLL_STEP_BACKWARD:
      if (clist->focus_row <= 0)
	return;
      gtk_cmclist_undraw_focus (widget);
      clist->focus_row--;
      gtk_cmclist_draw_focus (widget);
      break;

    case GTK_SCROLL_STEP_DOWN:
    case GTK_SCROLL_STEP_FORWARD:
      if (clist->focus_row >= clist->rows - 1)
	return;
      gtk_cmclist_undraw_focus (widget);
      clist->focus_row++;
      gtk_cmclist_draw_focus (widget);
      break;
    case GTK_SCROLL_PAGE_UP:
    case GTK_SCROLL_PAGE_BACKWARD:
      if (clist->focus_row <= 0)
	return;
      gtk_cmclist_undraw_focus (widget);
      clist->focus_row = MAX (0, clist->focus_row -
			      (2 * clist->clist_window_height -
			       clist->row_height - CELL_SPACING) / 
			      (2 * (clist->row_height + CELL_SPACING)));
      gtk_cmclist_draw_focus (widget);
      break;
    case GTK_SCROLL_PAGE_DOWN:
    case GTK_SCROLL_PAGE_FORWARD:
      if (clist->focus_row >= clist->rows - 1)
	return;
      gtk_cmclist_undraw_focus (widget);
      clist->focus_row = MIN (clist->rows - 1, clist->focus_row + 
			      (2 * clist->clist_window_height -
			       clist->row_height - CELL_SPACING) / 
			      (2 * (clist->row_height + CELL_SPACING)));
      gtk_cmclist_draw_focus (widget);
      break;
    case GTK_SCROLL_JUMP:
      if (position >= 0 && position <= 1)
	{
	  gint row = position * (clist->rows - 1);

	  if (row == clist->focus_row)
	    return;

	  gtk_cmclist_undraw_focus (widget);
	  clist->focus_row = row;
	  gtk_cmclist_draw_focus (widget);
	}
      break;
    default:
      break;
    }
}

static void
scroll_horizontal (GtkCMCList      *clist,
		   GtkScrollType  scroll_type,
		   gfloat         position)
{
  gint column = 0;
  gint last_column;

  cm_return_if_fail (clist != 0);
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (clist_has_grab (clist))
    return;

  for (last_column = clist->columns - 1;
       last_column >= 0 && !clist->column[last_column].visible; last_column--)
    ;

  switch (scroll_type)
    {
    case GTK_SCROLL_STEP_BACKWARD:
      column = COLUMN_FROM_XPIXEL (clist, 0);
      if (COLUMN_LEFT_XPIXEL (clist, column) - CELL_SPACING - COLUMN_INSET >= 0
	  && column > 0)
	column--;
      break;
    case GTK_SCROLL_STEP_FORWARD:
      column = COLUMN_FROM_XPIXEL (clist, clist->clist_window_width);
      if (column < 0)
	return;
      if (COLUMN_LEFT_XPIXEL (clist, column) +
	  clist->column[column].area.width +
	  CELL_SPACING + COLUMN_INSET - 1 <= clist->clist_window_width &&
	  column < last_column)
	column++;
      break;
    case GTK_SCROLL_PAGE_BACKWARD:
    case GTK_SCROLL_PAGE_FORWARD:
      return;
    case GTK_SCROLL_JUMP:
      if (position >= 0 && position <= 1)
	{
	  gint vis_columns = 0;
	  gint i;

	  for (i = 0; i <= last_column; i++)
 	    if (clist->column[i].visible)
	      vis_columns++;

	  column = position * vis_columns;

	  for (i = 0; i <= last_column && column > 0; i++)
	    if (clist->column[i].visible)
	      column--;

	  column = i;
	}
      else
	return;
      break;
    default:
      break;
    }

  if (COLUMN_LEFT_XPIXEL (clist, column) < CELL_SPACING + COLUMN_INSET)
    gtk_cmclist_moveto (clist, -1, column, 0, 0);
  else if (COLUMN_LEFT_XPIXEL (clist, column) + CELL_SPACING + COLUMN_INSET - 1
	   + clist->column[column].area.width > clist->clist_window_width)
    {
      if (column == last_column)
	gtk_cmclist_moveto (clist, -1, column, 0, 0);
      else
	gtk_cmclist_moveto (clist, -1, column, 0, 1);
    }
}

static void
scroll_vertical (GtkCMCList      *clist,
		 GtkScrollType  scroll_type,
		 gfloat         position)
{
  gint old_focus_row;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (clist_has_grab (clist))
    return;

  switch (clist->selection_mode)
    {
    case GTK_SELECTION_MULTIPLE:
      if (clist->anchor >= 0)
	return;
    case GTK_SELECTION_BROWSE:

      old_focus_row = clist->focus_row;
      move_focus_row (clist, scroll_type, position);

      if (old_focus_row != clist->focus_row)
	{
	  if (clist->selection_mode == GTK_SELECTION_BROWSE)
	    g_signal_emit (G_OBJECT (clist), clist_signals[UNSELECT_ROW], 0,
			     old_focus_row, -1, NULL);
	  else if (!GTK_CMCLIST_ADD_MODE(clist))
	    {
	      gtk_cmclist_unselect_all (clist);
	      clist->undo_anchor = old_focus_row;
	    }
	}

      switch (gtk_cmclist_row_is_visible (clist, clist->focus_row))
	{
	case GTK_VISIBILITY_NONE:
	  if (old_focus_row != clist->focus_row &&
	      !(clist->selection_mode == GTK_SELECTION_MULTIPLE &&
		GTK_CMCLIST_ADD_MODE(clist)))
	    g_signal_emit (G_OBJECT (clist), clist_signals[SELECT_ROW], 0,
			     clist->focus_row, -1, NULL);
	  switch (scroll_type)
	    {
            case GTK_SCROLL_PAGE_UP:
            case GTK_SCROLL_STEP_UP:
	    case GTK_SCROLL_STEP_BACKWARD:
	    case GTK_SCROLL_PAGE_BACKWARD:
	      gtk_cmclist_moveto (clist, clist->focus_row, -1, 0, 0);
	      break;
            case GTK_SCROLL_PAGE_DOWN:
            case GTK_SCROLL_STEP_DOWN:
	    case GTK_SCROLL_STEP_FORWARD:
	    case GTK_SCROLL_PAGE_FORWARD:
	      gtk_cmclist_moveto (clist, clist->focus_row, -1, 1, 0);
	      break;
	    case GTK_SCROLL_JUMP:
	      gtk_cmclist_moveto (clist, clist->focus_row, -1, 0.5, 0);
	      break;
	    default:
	      break;
	    }
	  break;
	case GTK_VISIBILITY_PARTIAL:
	  switch (scroll_type)
	    {
	    case GTK_SCROLL_STEP_BACKWARD:
	    case GTK_SCROLL_PAGE_BACKWARD:
	      gtk_cmclist_moveto (clist, clist->focus_row, -1, 0, 0);
	      break;
	    case GTK_SCROLL_STEP_FORWARD:
	    case GTK_SCROLL_PAGE_FORWARD:
	      gtk_cmclist_moveto (clist, clist->focus_row, -1, 1, 0);
	      break;
	    case GTK_SCROLL_JUMP:
	      gtk_cmclist_moveto (clist, clist->focus_row, -1, 0.5, 0);
	      break;
	    default:
	      break;
	    }
	  /* fallback is intentional */	
	default:
	  if (old_focus_row != clist->focus_row &&
	      !(clist->selection_mode == GTK_SELECTION_MULTIPLE &&
		GTK_CMCLIST_ADD_MODE(clist)))
	    g_signal_emit (G_OBJECT (clist), clist_signals[SELECT_ROW], 0,
			     clist->focus_row, -1, NULL);
	  break;
	}
      break;
    default:
      move_focus_row (clist, scroll_type, position);

      if (ROW_TOP_YPIXEL (clist, clist->focus_row) + clist->row_height >
	  clist->clist_window_height)
	gtk_cmclist_moveto (clist, clist->focus_row, -1, 1, 0);
      else if (ROW_TOP_YPIXEL (clist, clist->focus_row) < 0)
	gtk_cmclist_moveto (clist, clist->focus_row, -1, 0, 0);
      break;
    }
}

static void
move_horizontal (GtkCMCList *clist,
		 gint      diff)
{
  gdouble value;

  if (!clist->hadjustment)
    return;

  value = CLAMP (gtk_adjustment_get_value (clist->hadjustment) + diff, 0.0,
		 gtk_adjustment_get_upper (clist->hadjustment) -
		 gtk_adjustment_get_page_size (clist->hadjustment));
  gtk_adjustment_set_value (clist->hadjustment, value);
}

static void
move_vertical (GtkCMCList *clist,
	       gint      row,
	       gfloat    align)
{
  gdouble value;
  gdouble upper;
  gdouble page_size;

  if (!clist->vadjustment)
    return;

  value = (ROW_TOP_YPIXEL (clist, row) - clist->voffset -
	   align * (clist->clist_window_height - clist->row_height) +
	   (2 * align - 1) * CELL_SPACING);

  upper = gtk_adjustment_get_upper (clist->vadjustment);
  page_size = gtk_adjustment_get_page_size (clist->vadjustment);
  if ((value + page_size) > upper)
	value = upper - page_size;

  gtk_adjustment_set_value (clist->vadjustment, value);
}

static void
do_fake_motion (GtkWidget *widget)
{
  GdkEvent *event = gdk_event_new (GDK_MOTION_NOTIFY);

  event->motion.send_event = TRUE;

  gtk_cmclist_motion (widget, (GdkEventMotion *)event);
  gdk_event_free (event);
}

static gint
horizontal_timeout (GtkCMCList *clist)
{
  clist->htimer = 0;
  do_fake_motion (GTK_WIDGET (clist));

  return FALSE;
}

static gint
vertical_timeout (GtkCMCList *clist)
{
  clist->vtimer = 0;
  do_fake_motion (GTK_WIDGET (clist));

  return FALSE;
}

static void
remove_grab (GtkCMCList *clist)
{
  GtkWidget *widget = GTK_WIDGET (clist);
  
  if (gtk_widget_has_grab (widget))
    {
      GdkDisplay *display = gtk_widget_get_display (widget);
      
      gtk_grab_remove (widget);
      if (gtkut_pointer_is_grabbed (widget))
	gdk_display_pointer_ungrab (display, GDK_CURRENT_TIME);
    }

  if (clist->htimer)
    {
      g_source_remove (clist->htimer);
      clist->htimer = 0;
    }

  if (clist->vtimer)
    {
      g_source_remove (clist->vtimer);
      clist->vtimer = 0;
    }
}

/* PUBLIC SORTING FUNCTIONS
 * gtk_cmclist_sort
 * gtk_cmclist_set_compare_func
 * gtk_cmclist_set_auto_sort
 * gtk_cmclist_set_sort_type
 * gtk_cmclist_set_sort_column
 */
void
gtk_cmclist_sort (GtkCMCList *clist)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  GTK_CMCLIST_GET_CLASS (clist)->sort_list (clist);
}

void
gtk_cmclist_set_compare_func (GtkCMCList            *clist,
			    GtkCMCListCompareFunc  cmp_func)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  clist->compare = (cmp_func) ? cmp_func : default_compare;
}

void       
gtk_cmclist_set_auto_sort (GtkCMCList *clist,
			 gboolean  auto_sort)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));
  
  if (GTK_CMCLIST_AUTO_SORT(clist) && !auto_sort)
    GTK_CMCLIST_UNSET_FLAG (clist, CMCLIST_AUTO_SORT);
  else if (!GTK_CMCLIST_AUTO_SORT(clist) && auto_sort)
    {
      GTK_CMCLIST_SET_FLAG (clist, CMCLIST_AUTO_SORT);
      gtk_cmclist_sort (clist);
    }
}

void       
gtk_cmclist_set_sort_type (GtkCMCList    *clist,
			 GtkSortType  sort_type)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));
  
  clist->sort_type = sort_type;
}

void
gtk_cmclist_set_sort_column (GtkCMCList *clist,
			   gint      column)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (column < 0 || column >= clist->columns)
    return;

  clist->sort_column = column;
}

/* PRIVATE SORTING FUNCTIONS
 *   default_compare
 *   real_sort_list
 *   gtk_cmclist_merge
 *   gtk_cmclist_mergesort
 */
static gint
default_compare (GtkCMCList      *clist,
		 gconstpointer  ptr1,
		 gconstpointer  ptr2)
{
  char *text1 = NULL;
  char *text2 = NULL;

  GtkCMCListRow *row1 = (GtkCMCListRow *) ptr1;
  GtkCMCListRow *row2 = (GtkCMCListRow *) ptr2;

  switch (row1->cell[clist->sort_column].type)
    {
    case GTK_CMCELL_TEXT:
      text1 = GTK_CMCELL_TEXT (row1->cell[clist->sort_column])->text;
      break;
    case GTK_CMCELL_PIXTEXT:
      text1 = GTK_CMCELL_PIXTEXT (row1->cell[clist->sort_column])->text;
      break;
    default:
      break;
    }
 
  switch (row2->cell[clist->sort_column].type)
    {
    case GTK_CMCELL_TEXT:
      text2 = GTK_CMCELL_TEXT (row2->cell[clist->sort_column])->text;
      break;
    case GTK_CMCELL_PIXTEXT:
      text2 = GTK_CMCELL_PIXTEXT (row2->cell[clist->sort_column])->text;
      break;
    default:
      break;
    }

  if (!text2)
    return (text1 != NULL);

  if (!text1)
    return -1;

  return strcmp (text1, text2);
}

static void
real_sort_list (GtkCMCList *clist)
{
  GList *list;
  GList *work;
  gint i;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (clist->rows <= 1)
    return;

  if (clist_has_grab (clist))
    return;

  gtk_cmclist_freeze (clist);

  if (clist->anchor != -1 && clist->selection_mode == GTK_SELECTION_MULTIPLE)
    {
      GTK_CMCLIST_GET_CLASS (clist)->resync_selection (clist, NULL);
      g_list_free (clist->undo_selection);
      g_list_free (clist->undo_unselection);
      clist->undo_selection = NULL;
      clist->undo_unselection = NULL;
    }
   
  clist->row_list = gtk_cmclist_mergesort (clist, clist->row_list, clist->rows);

  work = clist->selection;

  for (i = 0, list = clist->row_list; i < clist->rows; i++, list = list->next)
    {
      if (GTK_CMCLIST_ROW (list)->state == GTK_STATE_SELECTED)
	{
	  work->data = GINT_TO_POINTER (i);
	  work = work->next;
	}
      
      if (i == clist->rows - 1)
	clist->row_list_end = list;
    }

  gtk_cmclist_thaw (clist);
}

static GList *
gtk_cmclist_merge (GtkCMCList *clist,
		 GList    *a,         /* first list to merge */
		 GList    *b)         /* second list to merge */
{
  GList z = { 0 };                    /* auxiliary node */
  GList *c;
  gint cmp;

  c = &z;

  if (!a && !b)
	return NULL;

  while (a || b)
    {
      if (a && !b)
	{
	  c->next = a;
	  a->prev = c;
	  c = a;
	  a = a->next;
	  break;
	}
      else if (!a && b)
	{
	  c->next = b;
	  b->prev = c;
	  c = b;
	  b = b->next;
	  break;
	}
      else /* a && b */
	{
	  cmp = clist->compare (clist, GTK_CMCLIST_ROW (a), GTK_CMCLIST_ROW (b));
	  if ((cmp >= 0 && clist->sort_type == GTK_SORT_DESCENDING) ||
	      (cmp <= 0 && clist->sort_type == GTK_SORT_ASCENDING))
	    {
	      c->next = a;
	      a->prev = c;
	      c = a;
	      a = a->next;
	    }
	  else
	    {
	      c->next = b;
	      b->prev = c;
	      c = b;
	      b = b->next;
	    }
	}
    }

  if (z.next)
	z.next->prev = NULL;

  return z.next;
}

static GList *
gtk_cmclist_mergesort (GtkCMCList *clist,
		     GList    *list,         /* the list to sort */
		     gint      num)          /* the list's length */
{
  GList *half;
  gint i;

  if (num <= 1)
    {
      return list;
    }
  else
    {
      /* move "half" to the middle */
      half = list;
      for (i = 0; i < num / 2; i++)
	half = half->next;

      /* cut the list in two */
      half->prev->next = NULL;
      half->prev = NULL;

      /* recursively sort both lists */
      return gtk_cmclist_merge (clist,
		       gtk_cmclist_mergesort (clist, list, num / 2),
		       gtk_cmclist_mergesort (clist, half, num - num / 2));
    }
}

/************************/

static void
drag_source_info_destroy (gpointer data)
{
  GtkCMCListCellInfo *info = data;

  g_free (info);
}

static void
drag_dest_info_destroy (gpointer data)
{
  GtkCMCListDestInfo *info = data;

  g_free (info);
}

static void
drag_dest_cell (GtkCMCList         *clist,
		gint              x,
		gint              y,
		GtkCMCListDestInfo *dest_info)
{
  GtkWidget *widget;
  GtkStyle *style;
  guint border_width;

  widget = GTK_WIDGET (clist);
  style = gtk_widget_get_style (widget);

  dest_info->insert_pos = GTK_CMCLIST_DRAG_NONE;

  border_width = gtk_container_get_border_width (GTK_CONTAINER (widget));
  y -= (border_width +
	style->ythickness +
	clist->column_title_area.height);

  dest_info->cell.row = ROW_FROM_YPIXEL (clist, y);
  if (dest_info->cell.row >= clist->rows)
    {
      dest_info->cell.row = clist->rows - 1;
      y = ROW_TOP_YPIXEL (clist, dest_info->cell.row) + clist->row_height;
    }
  if (dest_info->cell.row < -1)
    dest_info->cell.row = -1;
  
  x -= border_width + style->xthickness;

  dest_info->cell.column = COLUMN_FROM_XPIXEL (clist, x);

  if (dest_info->cell.row >= 0)
    {
      gint y_delta;
      gint h = 0;

      y_delta = y - ROW_TOP_YPIXEL (clist, dest_info->cell.row);
      
      if (GTK_CMCLIST_DRAW_DRAG_RECT(clist))
	{
	  dest_info->insert_pos = GTK_CMCLIST_DRAG_INTO;
	  h = clist->row_height / 4;
	}
      else if (GTK_CMCLIST_DRAW_DRAG_LINE(clist))
	{
	  dest_info->insert_pos = GTK_CMCLIST_DRAG_BEFORE;
	  h = clist->row_height / 2;
	}

      if (GTK_CMCLIST_DRAW_DRAG_LINE(clist))
	{
	  if (y_delta < h)
	    dest_info->insert_pos = GTK_CMCLIST_DRAG_BEFORE;
	  else if (clist->row_height - y_delta < h)
	    dest_info->insert_pos = GTK_CMCLIST_DRAG_AFTER;
	}
    }
}

static void
gtk_cmclist_drag_begin (GtkWidget	     *widget,
		      GdkDragContext *context)
{
  GtkCMCList *clist;
  GtkCMCListCellInfo *info;

  cm_return_if_fail (GTK_IS_CMCLIST (widget));
  cm_return_if_fail (context != NULL);

  clist = GTK_CMCLIST (widget);

  clist->drag_button = 0;
  remove_grab (clist);

  switch (clist->selection_mode)
    {
    case GTK_SELECTION_MULTIPLE:
      update_extended_selection (clist, clist->focus_row);
      GTK_CMCLIST_GET_CLASS (clist)->resync_selection (clist, NULL);
      break;
    case GTK_SELECTION_SINGLE:
      clist->anchor = -1;
    case GTK_SELECTION_BROWSE:
      break;
    default:
      g_assert_not_reached ();
    }

  info = g_dataset_get_data (context, "gtk-clist-drag-source");

  if (!info)
    {
      info = g_new (GtkCMCListCellInfo, 1);

      if (clist->click_cell.row < 0)
	clist->click_cell.row = 0;
      else if (clist->click_cell.row >= clist->rows)
	clist->click_cell.row = clist->rows - 1;
      info->row = clist->click_cell.row;
      info->column = clist->click_cell.column;

      g_dataset_set_data_full (context, "gtk-clist-drag-source", info,
			       drag_source_info_destroy);
    }

  if (GTK_CMCLIST_USE_DRAG_ICONS (clist))
    gtk_drag_set_icon_default (context);
}

static void
gtk_cmclist_drag_end (GtkWidget	   *widget,
		    GdkDragContext *context)
{
  GtkCMCList *clist;

  cm_return_if_fail (GTK_IS_CMCLIST (widget));
  cm_return_if_fail (context != NULL);

  clist = GTK_CMCLIST (widget);

  clist->click_cell.row = -1;
  clist->click_cell.column = -1;
}

static void
gtk_cmclist_drag_leave (GtkWidget      *widget,
		      GdkDragContext *context,
		      guint           time)
{
  GtkCMCList *clist;
  GtkCMCListDestInfo *dest_info;

  cm_return_if_fail (GTK_IS_CMCLIST (widget));
  cm_return_if_fail (context != NULL);

  clist = GTK_CMCLIST (widget);

  dest_info = g_dataset_get_data (context, "gtk-clist-drag-dest");
  
  if (dest_info)
    {
      if (dest_info->cell.row >= 0 &&
	  GTK_CMCLIST_REORDERABLE(clist) &&
	  gtk_drag_get_source_widget (context) == widget)
	{
	  GdkAtom atom = gdk_atom_intern_static_string ("gtk-clist-drag-reorder");
	  GdkAtom found = gtk_drag_dest_find_target(widget, context, NULL);

	      if (atom == found)
		{
		  clist->drag_highlight_row = -1;
		}
	}
      g_dataset_remove_data (context, "gtk-clist-drag-dest");
    }
}

static gint
gtk_cmclist_drag_motion (GtkWidget      *widget,
		       GdkDragContext *context,
		       gint            x,
		       gint            y,
		       guint           time)
{
  GtkCMCList *clist;
  GtkCMCListDestInfo new_info;
  GtkCMCListDestInfo *dest_info;

  cm_return_val_if_fail (GTK_IS_CMCLIST (widget), FALSE);

  clist = GTK_CMCLIST (widget);

  dest_info = g_dataset_get_data (context, "gtk-clist-drag-dest");

  if (!dest_info)
    {
      dest_info = g_new (GtkCMCListDestInfo, 1);

      dest_info->insert_pos  = GTK_CMCLIST_DRAG_NONE;
      dest_info->cell.row    = -1;
      dest_info->cell.column = -1;

      g_dataset_set_data_full (context, "gtk-clist-drag-dest", dest_info,
			       drag_dest_info_destroy);
    }

  drag_dest_cell (clist, x, y, &new_info);

  if (GTK_CMCLIST_REORDERABLE (clist))
    {
      GdkAtom atom = gdk_atom_intern_static_string ("gtk-clist-drag-reorder");
      GdkAtom found = gtk_drag_dest_find_target(widget, context, NULL);

      if (atom == found)
	{
	  if (gtk_drag_get_source_widget (context) != widget ||
	      new_info.insert_pos == GTK_CMCLIST_DRAG_NONE ||
	      new_info.cell.row == clist->click_cell.row ||
	      (new_info.cell.row == clist->click_cell.row - 1 &&
	       new_info.insert_pos == GTK_CMCLIST_DRAG_AFTER) ||
	      (new_info.cell.row == clist->click_cell.row + 1 &&
	       new_info.insert_pos == GTK_CMCLIST_DRAG_BEFORE))
	    {
	      if (dest_info->cell.row < 0)
		{
		  gdk_drag_status (context, GDK_ACTION_DEFAULT, time);
		  return FALSE;
		}
	      return TRUE;
	    }
		
	  if (new_info.cell.row != dest_info->cell.row ||
	      (new_info.cell.row == dest_info->cell.row &&
	       dest_info->insert_pos != new_info.insert_pos))
	    {

	      dest_info->insert_pos  = new_info.insert_pos;
	      dest_info->cell.row    = new_info.cell.row;
	      dest_info->cell.column = new_info.cell.column;
	      
	      clist->drag_highlight_row = dest_info->cell.row;
	      clist->drag_highlight_pos = dest_info->insert_pos;

	      gdk_drag_status (context,
		gdk_drag_context_get_suggested_action(context), time);
	    }
	  return TRUE;
	}
    }

  dest_info->insert_pos  = new_info.insert_pos;
  dest_info->cell.row    = new_info.cell.row;
  dest_info->cell.column = new_info.cell.column;
  return TRUE;
}

static gboolean
gtk_cmclist_drag_drop (GtkWidget      *widget,
		     GdkDragContext *context,
		     gint            x,
		     gint            y,
		     guint           time)
{
  cm_return_val_if_fail (GTK_IS_CMCLIST (widget), FALSE);
  cm_return_val_if_fail (context != NULL, FALSE);

  if (GTK_CMCLIST_REORDERABLE (widget) &&
      gtk_drag_get_source_widget (context) == widget)
    {
      GdkAtom atom = gdk_atom_intern_static_string ("gtk-clist-drag-reorder");
      GdkAtom found = gtk_drag_dest_find_target(widget, context, NULL);

	  if (atom == found)
	    return TRUE;
    }
  return FALSE;
}

static void
gtk_cmclist_drag_data_received (GtkWidget        *widget,
			      GdkDragContext   *context,
			      gint              x,
			      gint              y,
			      GtkSelectionData *selection_data,
			      guint             info,
			      guint             time)
{
  GtkCMCList *clist;

  cm_return_if_fail (GTK_IS_CMCLIST (widget));
  cm_return_if_fail (context != NULL);
  cm_return_if_fail (selection_data != NULL);

  clist = GTK_CMCLIST (widget);

  if (GTK_CMCLIST_REORDERABLE (clist) &&
      gtk_drag_get_source_widget (context) == widget &&
      gtk_selection_data_get_target (selection_data) ==
      gdk_atom_intern_static_string ("gtk-clist-drag-reorder") &&
      gtk_selection_data_get_format (selection_data) == 8 &&
      gtk_selection_data_get_length (selection_data) == sizeof (GtkCMCListCellInfo))
    {
      GtkCMCListCellInfo *source_info;

      source_info = (GtkCMCListCellInfo *)(gtk_selection_data_get_data (selection_data));
      if (source_info)
	{
	  GtkCMCListDestInfo dest_info;

	  drag_dest_cell (clist, x, y, &dest_info);

	  if (dest_info.insert_pos == GTK_CMCLIST_DRAG_AFTER)
	    dest_info.cell.row++;
	  if (source_info->row < dest_info.cell.row)
	    dest_info.cell.row--;
	  if (dest_info.cell.row != source_info->row)
	    gtk_cmclist_row_move (clist, source_info->row, dest_info.cell.row);

	  g_dataset_remove_data (context, "gtk-clist-drag-dest");
	}
    }
}

static void  
gtk_cmclist_drag_data_get (GtkWidget        *widget,
			 GdkDragContext   *context,
			 GtkSelectionData *selection_data,
			 guint             info,
			 guint             time)
{
  GdkAtom target;
  cm_return_if_fail (GTK_IS_CMCLIST (widget));
  cm_return_if_fail (context != NULL);
  cm_return_if_fail (selection_data != NULL);

  target = gtk_selection_data_get_target (selection_data);
  if (target == gdk_atom_intern_static_string ("gtk-clist-drag-reorder"))
    {
      GtkCMCListCellInfo *info;

      info = g_dataset_get_data (context, "gtk-clist-drag-source");

      if (info)
	{
	  GtkCMCListCellInfo ret_info;

	  ret_info.row = info->row;
	  ret_info.column = info->column;

	  gtk_selection_data_set (selection_data, target,
				  8, (guchar *) &ret_info,
				  sizeof (GtkCMCListCellInfo));
	}
    }
}

void
gtk_cmclist_set_reorderable (GtkCMCList *clist, 
			   gboolean  reorderable)
{
  GtkWidget *widget;

  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if ((GTK_CMCLIST_REORDERABLE(clist) != 0) == reorderable)
    return;

  widget = GTK_WIDGET (clist);

  if (reorderable)
    {
      GTK_CMCLIST_SET_FLAG (clist, CMCLIST_REORDERABLE);
      gtk_drag_dest_set (widget,
			 GTK_DEST_DEFAULT_MOTION | GTK_DEST_DEFAULT_DROP,
			 &clist_target_table, 1, GDK_ACTION_MOVE);
    }
  else
    {
      GTK_CMCLIST_UNSET_FLAG (clist, CMCLIST_REORDERABLE);
      gtk_drag_dest_unset (GTK_WIDGET (clist));
    }
}

void
gtk_cmclist_set_use_drag_icons (GtkCMCList *clist,
			      gboolean  use_icons)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));

  if (use_icons != 0)
    GTK_CMCLIST_SET_FLAG (clist, CMCLIST_USE_DRAG_ICONS);
  else
    GTK_CMCLIST_UNSET_FLAG (clist, CMCLIST_USE_DRAG_ICONS);
}

void
gtk_cmclist_set_button_actions (GtkCMCList *clist,
			      guint     button,
			      guint8    button_actions)
{
  cm_return_if_fail (GTK_IS_CMCLIST (clist));
  
  if (button < MAX_BUTTON)
    {
      if (gtkut_pointer_is_grabbed (GTK_WIDGET(clist)) || 
	  gtk_widget_has_grab (GTK_WIDGET(clist)))
	{
	  remove_grab (clist);
	  clist->drag_button = 0;
	}

      GTK_CMCLIST_GET_CLASS (clist)->resync_selection (clist, NULL);

      clist->button_actions[button] = button_actions;
    }
}

static gboolean
gtk_cmclist_get_border (GtkScrollable *scrollable,
		GtkBorder *border)
{
	GtkCMCList *cmclist = GTK_CMCLIST(scrollable);

	border->top = cmclist->column_title_area.height;
	return TRUE;
}

static void
gtk_cmclist_scrollable_init (GtkScrollableInterface *iface)
{
	iface->get_border = gtk_cmclist_get_border;
}
