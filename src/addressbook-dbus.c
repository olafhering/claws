/*
 * $Id$
 */
/* vim:et:ts=4:sw=4:et:sts=4:ai:set list listchars=tab\:��,trail\:�: */

/*
 * Claws-contacts is a proposed new design for the address book feature
 * in Claws Mail. The goal for this new design was to create a
 * solution more suitable for the term lightweight and to be more
 * maintainable than the present implementation.
 *
 * More lightweight is achieved by design, in that sence that the whole
 * structure is based on a plugable design.
 *
 * Claws Mail is Copyright (C) 1999-2018 by the Claws Mail Team and
 * Claws-contacts is Copyright (C) 2018 by Michael Rasmussen.
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
#       include <config.h>
#endif

#include <glib.h>
#include <glib/gi18n.h>
#include <gio/gio.h>
#include "dbus-contact.h"
#include "addrgather.h"
#include "folder.h"
#include "compose.h"
#include "hooks.h"

#include "addressbook-dbus.h"

static GDBusProxy* proxy = NULL;
static GDBusConnection* connection = NULL;
static Compose* compose_instance = NULL;
static guint signal_subscription_id = 0;

#define CLIENT_ERROR_QUARK (g_quark_from_static_string("client-object-error"))

static gboolean init(GError** error) {
    if (connection != NULL && proxy != NULL)
        return TRUE;

    connection = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, error);
    if (connection == NULL || *error) {
        if (! *error)
            g_set_error(error, CLIENT_ERROR_QUARK, 1, "Unable to connect to dbus");
        g_warning("unable to connect to dbus: %s", (*error)->message);
        return FALSE;
    }

    proxy = g_dbus_proxy_new_sync(connection,
            G_DBUS_PROXY_FLAGS_NONE,
            NULL,
            "org.clawsmail.Contacts",
            "/org/clawsmail/contacts",
            "org.clawsmail.Contacts",
            NULL,
            error);
    if (proxy == NULL) {
        g_warning("could not get a proxy object");
        if (! *error)
            g_set_error(error, CLIENT_ERROR_QUARK, 1, "Could not get a proxy object");
        return FALSE;
    }

    return TRUE;
}

static void dbus_contact_free(const DBusContact* contact) {
    g_hash_table_destroy(contact->data);
    g_ptr_array_free(contact->emails, TRUE);
}

static GHashTable* hash_table_new(void) {
    return g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
}

static void g_value_email_free(gpointer data) {
    GArray* email = (GArray *) data;
    GValue* email_member;
    guint i;

    for (i = 0; i < email->len; i++) {
        email_member = g_array_index(email, GValue*, i);
        g_value_unset(email_member);
    }
}

static GPtrArray* g_value_email_new() {
    return g_ptr_array_new_with_free_func(g_value_email_free);
}

static gchar* convert_2_utf8(gchar* locale) {
    gsize read, write;
    GError* error = NULL;
    gchar *current, *utf8;
    const gchar* charset;

    if (g_get_charset(&charset) || g_utf8_validate(locale, -1, 0))
        return g_strdup(locale);

    if (strcmp("ANSI_X3.4-1968", charset) == 0)
        current = g_strdup("ISO-8859-1");
    else
        current = g_strdup(charset);

    utf8 = g_convert(locale, -1, "UTF-8", current, &read, &write, &error);
    if (error) {
        g_warning("failed to convert [%s]: %s", charset, error->message);
        g_free(current);
        return NULL;
    }
    g_free(current);

    return utf8;
}

static GVariant* format_contact_data(ContactData* c) {
    GVariantBuilder builder;
    gchar* firstname = NULL;
    gchar* lastname = NULL;
    gchar* image = NULL;
    gsize size;

    g_variant_builder_init(&builder, G_VARIANT_TYPE("a{ss}"));

    if (c->name) {
        gchar* pos = strchr(c->name, ' ');
        if (pos) {
            firstname = g_strndup(c->name, pos - c->name);
            lastname = g_strdup(++pos);
            g_variant_builder_add(&builder, "{ss}", "first-name", convert_2_utf8(firstname));
            g_variant_builder_add(&builder, "{ss}", "last-name", convert_2_utf8(lastname));
        }
        else {
            lastname = g_strdup(c->name);
            g_variant_builder_add(&builder, "{ss}", "last-name", convert_2_utf8(lastname));
        }
        g_free(firstname);
        g_free(lastname);
    }
    if (c->cn) {
        g_variant_builder_add(&builder, "{ss}", "cn", convert_2_utf8(c->cn));
    }

    if (c->picture) {
        gdk_pixbuf_save_to_buffer(c->picture, &image, &size, "png", NULL, NULL);
        gchar* encoded = g_base64_encode((const guchar *) image, size);
        g_variant_builder_add(&builder, "{ss}", "image", encoded);
        g_free(encoded);
    }

    return g_variant_builder_end(&builder);
}

static GVariant* format_contact_emails(ContactData* c) {
    GVariantBuilder builder;
    GVariantBuilder email_builder;
    gchar* str;

    g_variant_builder_init(&builder, G_VARIANT_TYPE("aas"));
    g_variant_builder_init(&email_builder, G_VARIANT_TYPE("as"));

    /* Alias is not available but needed so make an empty string */
    g_variant_builder_add(&email_builder, "s", "");

    if (c->email)
        str = convert_2_utf8(c->email);
    else
        str = g_strdup("");
    g_variant_builder_add(&email_builder, "s", str);
    g_free(str);

    if (c->remarks)
        str = convert_2_utf8(c->remarks);
    else
        str = g_strdup("");
    g_variant_builder_add(&email_builder, "s", str);
    g_free(str);

    g_variant_builder_add(&builder, "as", &email_builder);

    return g_variant_builder_end(&builder);
}

static void contact_signal_cb(GDBusConnection *conn,
                               const gchar *sender_name,
                               const gchar *object_path,
                               const gchar *interface_name,
                               const gchar *signal_name,
                               GVariant *parameters,
                               gpointer user_data) {
    const gchar *address = NULL;

    if (! compose_instance) {
        g_message("Missing compose instance\n");
        return;
    }

    if (g_strcmp0(signal_name, "ContactMailTo") == 0) {
        g_variant_get(parameters, "(&s)", &address);
        debug_print("ContactMailTo address received: %s\n", address);
        compose_entry_append(compose_instance, address, COMPOSE_TO, PREF_NONE);
    }
    else if (g_strcmp0(signal_name, "ContactMailCc") == 0) {
        g_variant_get(parameters, "(&s)", &address);
        debug_print("ContactMailCc address received: %s\n", address);
        compose_entry_append(compose_instance, address, COMPOSE_CC, PREF_NONE);
    }
    else if (g_strcmp0(signal_name, "ContactMailBcc") == 0) {
        g_variant_get(parameters, "(&s)", &address);
        debug_print("ContactMailBcc address received: %s\n", address);
        compose_entry_append(compose_instance, address, COMPOSE_BCC, PREF_NONE);
    }
    else {
        debug_print("Unhandled signal received: %s\n", signal_name);
    }
}

gboolean addressbook_start_service(GError** error) {
    GVariant* result = NULL;
    gchar* reply = NULL;
    gboolean ret = FALSE;

    if (! init(error))
        return FALSE;

    result = g_dbus_proxy_call_sync(proxy,
            "Ping",
            NULL,
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            NULL,
            error);

    if (!result) {
        if (! *error)
            g_set_error(error, CLIENT_ERROR_QUARK, 1, "Woops remote method failed");
        g_warning("woops remote method failed: %s", (*error)->message);
        return FALSE;
    }

    g_variant_get(result, "(s)", &reply);
    if (reply && strcmp("PONG", reply) == 0)
        ret = TRUE;

    g_free(reply);
    g_variant_unref(result);
    return ret;
}

int addressbook_dbus_add_contact(ContactData* contact, GError** error) {
    GVariant* data_variant;
    GVariant* emails_variant;
    GVariant* result;

    if (! init(error))
        return -1;

    data_variant = format_contact_data(contact);
    emails_variant = format_contact_emails(contact);

    result = g_dbus_proxy_call_sync(proxy,
            "AddContact",
            g_variant_new("(s@a{ss}@aas)", contact->book, data_variant, emails_variant),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            NULL,
            error);

    if (!result) {
        if (! *error)
            g_set_error(error, CLIENT_ERROR_QUARK, 1, "Woops remote method failed");
        g_warning("woops remote method failed: %s", (*error)->message);
        return -1;
    }

    g_variant_unref(result);
    return 0;
}

gboolean addrindex_dbus_load_completion(gint (*callBackFunc)
                                        (const gchar* name,
                                         const gchar* address,
                                         const gchar* nick,
                                         const gchar* alias,
                                         GList* grp_emails),
                                         GError** error) {
    GVariant* result;
    gchar **list = NULL;
    gchar **contacts;
    gchar *name, *email;

    if (! init(error))
        return FALSE;

    result = g_dbus_proxy_call_sync(proxy,
            "SearchAddressbook",
            g_variant_new("(ss)", "*", ""),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            NULL,
            error);

    if (!result) {
        if (! *error)
            g_set_error(error, CLIENT_ERROR_QUARK, 1, "Woops remote method failed");
        g_warning("woops remote method failed: %s", (*error)->message);
        return FALSE;
    }

    g_variant_get(result, "(^as)", &list);

    for (contacts = list; *contacts != NULL; contacts += 1) {
        gchar* tmp = g_strdup(*contacts);
        gchar* pos = g_strrstr(tmp, "\"");
        if (pos) {
            /* Contact has a name as part of email address */
            *pos = '\0';
            name = tmp;
            name += 1;
            pos += 3;
            email = pos;
            pos = g_strrstr(email, ">");
            if (pos)
                *pos = '\0';
        }
        else {
            name = "";
            email = tmp;
        }
        debug_print("Adding: %s <%s> to completition\n", name, email);
        callBackFunc(name, email, NULL, NULL, NULL);
        g_free(tmp);
    }

    g_strfreev(list);
    g_variant_unref(result);
    return TRUE;
}

void addressbook_dbus_open(gboolean compose, GError** error) {
    GVariant* result;

    if (! init(error))
        return;

    result = g_dbus_proxy_call_sync(proxy,
            "ShowAddressbook",
            g_variant_new("(b)", compose),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            NULL,
            error);

    if (!result) {
        if (! *error)
            g_set_error(error, CLIENT_ERROR_QUARK, 1, "Woops remote method failed");
        g_warning("woops remote method failed: %s", (*error)->message);
        return;
    }

    g_variant_unref(result);
}

GSList* addressbook_dbus_get_books(GError** error) {
    GVariant* result;
    gchar **book_names = NULL, **cur;
    GSList* books = NULL;

    if (! init(error)) {
        return books;
    }

    result = g_dbus_proxy_call_sync(proxy,
            "BookList",
            NULL,
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            NULL,
            error);

    if (!result) {
        if (! *error)
            g_set_error(error, CLIENT_ERROR_QUARK, 1, "Woops remote method failed");
        g_warning("woops remote method failed: %s", (*error)->message);
        return books;
    }

    g_variant_get(result, "(^as)", &book_names);

    for (cur = book_names; *cur; cur += 1)
        books = g_slist_prepend(books, g_strdup(*cur));

    g_strfreev(book_names);
    g_variant_unref(result);

    return books;
}

void contact_data_free(ContactData** data) {
    ContactData* contact;

    if (! data && ! *data)
        return;

    contact = *data;
    g_free(contact->cn);
    g_free(contact->email);
    g_free(contact->remarks);
    g_free(contact->name);
    g_free(contact->book);
    g_free(contact);
    *data = NULL;
}

void addressbook_harvest(FolderItem *folderItem,
                         gboolean sourceInd,
                         GList *msgList ) {
    addrgather_dlg_execute(folderItem, sourceInd, msgList);
}

void addressbook_connect_signals(Compose* compose) {
    g_return_if_fail(compose != NULL);

    if (!connection) {
        GError* error = NULL;
        connection = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
        if (!connection) {
            g_warning("failed to connect to the D-BUS daemon: %s", error->message);
            g_error_free(error);
            return;
        }
    }

    debug_print("Compose: %p\n", compose);
    compose_instance = compose;

    signal_subscription_id = g_dbus_connection_signal_subscribe(
            connection,
            "org.clawsmail.Contacts",
            "org.clawsmail.Contacts",
            NULL,
            "/org/clawsmail/contacts",
            NULL,
            G_DBUS_SIGNAL_FLAGS_NONE,
            contact_signal_cb,
            NULL,
            NULL);

    if (signal_subscription_id == 0) {
        debug_print("Failed to subscribe to D-BUS signals\n");
    }
}

gchar* addressbook_get_vcard(const gchar* account, GError** error) {
    GVariant* result;
    gchar* vcard = NULL;

    g_return_val_if_fail(account != NULL, vcard);

    if (! init(error)) {
        return vcard;
    }

    result = g_dbus_proxy_call_sync(proxy,
            "GetVCard",
            g_variant_new("(s)", account),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            NULL,
            error);

    if (!result) {
        if (! *error)
            g_set_error(error, CLIENT_ERROR_QUARK, 1, "Woops remote method failed");
        g_warning("woops remote method failed: %s", (*error)->message);
        return NULL;
    }

    g_variant_get(result, "(s)", &vcard);
    g_variant_unref(result);

    return vcard;
}

gboolean addressbook_add_vcard(const gchar* abook, const gchar* vcard, GError** error) {
    gboolean result = FALSE;
    return result;
}

static gboolean my_compose_create_hook(gpointer source, gpointer user_data) {
    GError* error = NULL;

    gchar* vcard = addressbook_get_vcard("test", &error);
    if (error) {
        g_warning("%s", error->message);
        g_clear_error(&error);
    }
    else {
        debug_print("test.vcf:\n%s\n", vcard);
        g_free(vcard);
    }

    return FALSE;
}

void addressbook_install_hooks(GError** error) {
    if ((guint)-1 == hooks_register_hook(COMPOSE_CREATED_HOOKLIST, my_compose_create_hook, NULL)) {
        g_warning("could not register hook for adding vCards");
        if (error) {
            g_set_error(error, CLIENT_ERROR_QUARK, 1,
                "Could not register hook for adding vCards");
        }
    }
}
