/*
 * Claws Mail -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 1999-2021 the Claws Mail team and Hiroyuki Yamamoto
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include "session.h"
#include "utils.h"
#include "log.h"

static gint session_connect_cb(SockInfo *sock, gpointer data);
static gint session_close(Session *session);

static gboolean session_timeout_cb(gpointer data);

static gboolean session_recv_msg_idle_cb(gpointer data);
static gboolean session_recv_data_idle_cb(gpointer data);

static gboolean session_read_msg_cb(SockInfo *source, GIOCondition condition, gpointer data);
static gboolean session_read_data_cb(SockInfo *source, GIOCondition condition, gpointer data);
static gboolean session_write_msg_cb(SockInfo *source, GIOCondition condition, gpointer data);
static gboolean session_write_data_cb(SockInfo *source, GIOCondition condition, gpointer data);

void session_init(Session *session, const void *prefs_account)
{
	session->sock = NULL;
	session->server = NULL;
	session->port = 0;
#ifdef USE_GNUTLS
	session->ssl_type = SSL_NONE;
	session->use_tls_sni = TRUE;
#endif
	session->nonblocking = TRUE;
	session->state = SESSION_READY;
	session->last_access_time = time(NULL);

	session->tv_prev = g_date_time_new_now_local();

	session->conn_id = 0;

	session->io_tag = 0;

	session->read_buf_p = session->read_buf;
	session->read_buf_len = 0;

	session->read_msg_buf = g_string_sized_new(1024);
	session->read_data_buf = g_byte_array_new();

	session->write_buf = NULL;
	session->write_buf_p = NULL;
	session->write_buf_len = 0;

	session->write_data = NULL;
	session->write_data_p = NULL;
	session->write_data_len = 0;

	session->timeout_tag = 0;
	session->timeout_interval = 0;

	session->data = NULL;
	session->account = prefs_account;

	session->ping_tag = -1;

	session->proxy_info = NULL;
}

/*!
 *\brief	Set up parent and child process
 *		Childloop: Read commands from parent,
 *		send to server, get answer, pass to parent
 *
 *\param	session Contains session information
 *		server to connect to
 *		port to connect to
 *
 *\return	 0 : success
 *		-1 : pipe / fork errors (parent)
 *		 1 : connection error (child)
 */
gint session_connect(Session *session, const gchar *server, gushort port)
{
	session->server = g_strdup(server);
	session->port = port;

	if (session->proxy_info) {
		server = session->proxy_info->proxy_host;
		port = session->proxy_info->proxy_port;
	}
#ifdef G_OS_UNIX
	session->conn_id = sock_connect_async(server, port, session_connect_cb, session);
	if (session->conn_id < 0) {
		g_warning("can't connect to server");
		session_close(session);
		if (session->connect_finished)
			session->connect_finished(session, FALSE);
		return -1;
	}

	return 0;
#else
	SockInfo *sock;

	sock = sock_connect(server, port);
	if (sock == NULL) {
		g_warning("can't connect to server");
		session_close(session);
		if (session->connect_finished)
			session->connect_finished(session, FALSE);
		return -1;
	}
	sock->is_smtp = session->is_smtp;

	return session_connect_cb(sock, session);
#endif
}

static gint session_connect_cb(SockInfo *sock, gpointer data)
{
	Session *session = SESSION(data);

	session->conn_id = 0;

	if (!sock) {
		g_warning("can't connect to server");
		session->state = SESSION_ERROR;
		if (session->connect_finished)
			session->connect_finished(session, FALSE);
		return -1;
	}

	session->sock = sock;
	sock->account = session->account;
	sock->is_smtp = session->is_smtp;
	sock->ssl_cert_auto_accept = session->ssl_cert_auto_accept;

	if (session->proxy_info) {
		debug_print("connecting through socks\n");
		sock_set_nonblocking_mode(sock, FALSE);
		if (proxy_connect(sock, session->server, session->port, session->proxy_info) < 0) {
			g_warning("can't establish SOCKS connection");
			session->state = SESSION_ERROR;
			return -1;
		}
	}

#ifdef USE_GNUTLS
	sock->gnutls_priority = session->gnutls_priority;
	sock->use_tls_sni = session->use_tls_sni;

	if (session->ssl_type == SSL_TUNNEL) {
		sock_set_nonblocking_mode(sock, FALSE);
		if (!ssl_init_socket(sock)) {
			g_warning("can't initialize TLS");
			log_error(LOG_PROTOCOL, _("TLS handshake failed\n"));
			session->state = SESSION_ERROR;
			if (session->connect_finished)
				session->connect_finished(session, FALSE);
			return -1;
		}
	}
#endif

	/* we could have gotten a timeout while waiting for user input in 
	 * an SSL certificate dialog */
	if (session->state == SESSION_TIMEOUT) {
		if (session->connect_finished)
			session->connect_finished(session, FALSE);
		return -1;
	}

	sock_set_nonblocking_mode(sock, session->nonblocking);

	debug_print("session (%p): connected\n", session);

	session->state = SESSION_RECV;
	session->io_tag = sock_add_watch(session->sock, G_IO_IN, session_read_msg_cb, session);

	if (session->connect_finished)
		session->connect_finished(session, TRUE);
	return 0;
}

/*!
 *\brief	child and parent: send DISCONNECT message to other process
 *
 *\param	session Contains session information
 *
 *\return	 0 : success
 */
gint session_disconnect(Session *session)
{
	session_close(session);
	return 0;
}

/*!
 *\brief	parent ?
 *
 *\param	session Contains session information
 */
void session_destroy(Session *session)
{
	cm_return_if_fail(session != NULL);
	cm_return_if_fail(session->destroy != NULL);

	session_register_ping(session, NULL);

	session_close(session);
	session->destroy(session);
	g_free(session->server);
	g_string_free(session->read_msg_buf, TRUE);
	g_byte_array_free(session->read_data_buf, TRUE);
	g_free(session->read_data_terminator);
	g_free(session->write_buf);
#ifdef USE_GNUTLS
	g_free(session->gnutls_priority);
#endif
	g_date_time_unref(session->tv_prev);
	debug_print("session (%p): destroyed\n", session);

	g_free(session);
}

gboolean session_is_running(Session *session)
{
	return (session->state == SESSION_READY || session->state == SESSION_SEND || session->state == SESSION_RECV);
}

gboolean session_is_connected(Session *session)
{
	return (session->state == SESSION_SEND || session->state == SESSION_RECV);
}

void session_set_access_time(Session *session)
{
	session->last_access_time = time(NULL);
}

void session_set_timeout(Session *session, guint interval)
{
	if (session->timeout_tag > 0)
		g_source_remove(session->timeout_tag);

	session->timeout_interval = interval;
	if (interval > 0) {
		if (interval % 1000 == 0)
			session->timeout_tag = g_timeout_add_seconds(interval / 1000, session_timeout_cb, session);
		else
			session->timeout_tag = g_timeout_add(interval, session_timeout_cb, session);
	} else
		session->timeout_tag = 0;
}

static gboolean session_timeout_cb(gpointer data)
{
	Session *session = SESSION(data);

	g_warning("session timeout");

	if (session->io_tag > 0) {
		g_source_remove(session->io_tag);
		session->io_tag = 0;
	}

	session->timeout_tag = 0;
	session->state = SESSION_TIMEOUT;

	return FALSE;
}

void session_set_recv_message_notify(Session *session, RecvMsgNotify notify_func, gpointer data)
{
	session->recv_msg_notify = notify_func;
	session->recv_msg_notify_data = data;
}

void session_set_recv_data_progressive_notify(Session *session, RecvDataProgressiveNotify notify_func, gpointer data) {
	session->recv_data_progressive_notify = notify_func, session->recv_data_progressive_notify_data = data;
}

void session_set_recv_data_notify(Session *session, RecvDataNotify notify_func, gpointer data)
{
	session->recv_data_notify = notify_func;
	session->recv_data_notify_data = data;
}

void session_set_send_data_progressive_notify(Session *session, SendDataProgressiveNotify notify_func, gpointer data) {
	session->send_data_progressive_notify = notify_func;
	session->send_data_progressive_notify_data = data;
}

void session_set_send_data_notify(Session *session, SendDataNotify notify_func, gpointer data)
{
	session->send_data_notify = notify_func;
	session->send_data_notify_data = data;
}

/*!
 *\brief	child and parent cleanup (child closes first)
 *
 *\param	session Contains session information
 *
 *\return	 0 : success
 */
static gint session_close(Session *session)
{
	cm_return_val_if_fail(session != NULL, -1);

#ifdef G_OS_UNIX
	if (session->conn_id > 0) {
		sock_connect_async_cancel(session->conn_id);
		session->conn_id = 0;
		debug_print("session (%p): connection cancelled\n", session);
	}
#endif

	session_set_timeout(session, 0);

	if (session->io_tag > 0) {
		g_source_remove(session->io_tag);
		session->io_tag = 0;
	}

	if (session->sock) {
		sock_close(session->sock, TRUE);
		session->sock = NULL;
		session->state = SESSION_DISCONNECTED;
		debug_print("session (%p): closed\n", session);
	}

	return 0;
}

#ifdef USE_GNUTLS
gint session_start_tls(Session *session)
{
	gboolean nb_mode;

	nb_mode = sock_is_nonblocking_mode(session->sock);

	session->sock->ssl_cert_auto_accept = session->ssl_cert_auto_accept;
	session->sock->gnutls_priority = session->gnutls_priority;
	session->sock->use_tls_sni = session->use_tls_sni;

	if (nb_mode)
		sock_set_nonblocking_mode(session->sock, FALSE);

	if (!ssl_init_socket(session->sock)) {
		g_warning("couldn't start STARTTLS session");
		if (nb_mode)
			sock_set_nonblocking_mode(session->sock, session->nonblocking);
		return -1;
	}

	if (0 < session->read_buf_len) {
		g_warning("protocol violation: suffix data after STARTTLS detected");
		if (nb_mode)
			sock_set_nonblocking_mode(session->sock, session->nonblocking);
		return -1;
	}

	if (nb_mode)
		sock_set_nonblocking_mode(session->sock, session->nonblocking);

	return 0;
}
#endif

gint session_send_msg(Session *session, const gchar *msg)
{
	gboolean ret;

	cm_return_val_if_fail(session->write_buf == NULL, -1);
	cm_return_val_if_fail(msg != NULL, -1);

	session->state = SESSION_SEND;
	session->write_buf = g_strconcat((strlen(msg) > 0 ? msg : ""), "\r\n", NULL);
	session->write_buf_p = session->write_buf;
	session->write_buf_len = strlen(msg) + 2;

	ret = session_write_msg_cb(session->sock, G_IO_OUT, session);

	if (ret == TRUE)
		session->io_tag = sock_add_watch(session->sock, G_IO_OUT, session_write_msg_cb, session);
	else if (session->state == SESSION_ERROR)
		return -1;

	return 0;
}

gint session_recv_msg(Session *session)
{
	cm_return_val_if_fail(session->read_msg_buf->len == 0, -1);

	session->state = SESSION_RECV;

	if (session->read_buf_len > 0)
		g_idle_add(session_recv_msg_idle_cb, session);
	else
		session->io_tag = sock_add_watch(session->sock, G_IO_IN, session_read_msg_cb, session);

	return 0;
}

static gboolean session_recv_msg_idle_cb(gpointer data)
{
	Session *session = SESSION(data);
	gboolean ret;

	ret = session_read_msg_cb(session->sock, G_IO_IN, session);

	if (ret == TRUE)
		session->io_tag = sock_add_watch(session->sock, G_IO_IN, session_read_msg_cb, session);

	return FALSE;
}

/*!
 *\brief	parent (child?): send data to other process
 *
 *\param	session Contains session information
 *		data Data to send
 *		size Bytes to send
 *
 *\return	 0 : success
 *		-1 : error
 */
gint session_send_data(Session *session, const guchar *data, guint size)
{
	gboolean ret;

	cm_return_val_if_fail(session->write_data == NULL, -1);
	cm_return_val_if_fail(data != NULL, -1);
	cm_return_val_if_fail(size != 0, -1);

	session->state = SESSION_SEND;

	session->write_data = data;
	session->write_data_p = session->write_data;
	session->write_data_len = size;
	g_date_time_unref(session->tv_prev);
	session->tv_prev = g_date_time_new_now_local();

	ret = session_write_data_cb(session->sock, G_IO_OUT, session);

	if (ret == TRUE)
		session->io_tag = sock_add_watch(session->sock, G_IO_OUT, session_write_data_cb, session);
	else if (session->state == SESSION_ERROR)
		return -1;

	return 0;
}

gint session_recv_data(Session *session, guint size, const gchar *terminator)
{
	cm_return_val_if_fail(session->read_data_buf->len == 0, -1);

	session->state = SESSION_RECV;

	g_free(session->read_data_terminator);
	session->read_data_terminator = g_strdup(terminator);
	g_date_time_unref(session->tv_prev);
	session->tv_prev = g_date_time_new_now_local();

	if (session->read_buf_len > 0)
		g_idle_add(session_recv_data_idle_cb, session);
	else
		session->io_tag = sock_add_watch(session->sock, G_IO_IN, session_read_data_cb, session);

	return 0;
}

static gboolean session_recv_data_idle_cb(gpointer data)
{
	Session *session = SESSION(data);
	gboolean ret;

	ret = session_read_data_cb(session->sock, G_IO_IN, session);

	if (ret == TRUE)
		session->io_tag = sock_add_watch(session->sock, G_IO_IN, session_read_data_cb, session);

	return FALSE;
}

static gboolean session_read_msg_cb(SockInfo *source, GIOCondition condition, gpointer data)
{
	Session *session = SESSION(data);
	gchar buf[SESSION_BUFFSIZE];
	gint line_len;
	gchar *newline;
	gchar *msg;
	gint ret;

	cm_return_val_if_fail(condition == G_IO_IN, FALSE);

	session_set_timeout(session, session->timeout_interval);

	if (session->read_buf_len == 0) {
		gint read_len = -1;

		if (session->sock)
			read_len = sock_read(session->sock, session->read_buf, SESSION_BUFFSIZE - 1);

		if (read_len == -1 && session->state == SESSION_DISCONNECTED) {
			g_warning("sock_read: session disconnected");
			if (session->io_tag > 0) {
				g_source_remove(session->io_tag);
				session->io_tag = 0;
			}
			return FALSE;
		}

		if (read_len == 0) {
			g_warning("sock_read: received EOF");
			session->state = SESSION_EOF;
			return FALSE;
		}

		if (read_len < 0) {
			switch (errno) {
			case EAGAIN:
				return TRUE;
			default:
				g_warning("sock_read: %s", g_strerror(errno));
				session->state = SESSION_ERROR;
				return FALSE;
			}
		}

		session->read_buf_len = read_len;
	}

	if ((newline = memchr(session->read_buf_p, '\n', session->read_buf_len))
	    != NULL)
		line_len = newline - session->read_buf_p + 1;
	else
		line_len = session->read_buf_len;

	if (line_len == 0)
		return TRUE;

	memcpy(buf, session->read_buf_p, line_len);
	buf[line_len] = '\0';

	g_string_append(session->read_msg_buf, buf);

	session->read_buf_len -= line_len;
	if (session->read_buf_len == 0)
		session->read_buf_p = session->read_buf;
	else
		session->read_buf_p += line_len;

	/* incomplete read */
	if (buf[line_len - 1] != '\n')
		return TRUE;

	/* complete */
	if (session->io_tag > 0) {
		g_source_remove(session->io_tag);
		session->io_tag = 0;
	}

	/* callback */
	msg = g_strdup(session->read_msg_buf->str);
	strretchomp(msg);
	g_string_truncate(session->read_msg_buf, 0);

	ret = session->recv_msg(session, msg);
	session->recv_msg_notify(session, msg, session->recv_msg_notify_data);

	g_free(msg);

	if (ret < 0)
		session->state = SESSION_ERROR;

	return FALSE;
}

static gboolean session_read_data_cb(SockInfo *source, GIOCondition condition, gpointer data)
{
	Session *session = SESSION(data);
	GByteArray *data_buf;
	gint terminator_len;
	gboolean complete = FALSE;
	guint data_len;
	gint ret;

	cm_return_val_if_fail(condition == G_IO_IN, FALSE);

	session_set_timeout(session, session->timeout_interval);

	if (session->read_buf_len == 0) {
		gint read_len;

		read_len = sock_read(session->sock, session->read_buf, SESSION_BUFFSIZE);

		if (read_len == 0) {
			g_warning("sock_read: received EOF");
			session->state = SESSION_EOF;
			return FALSE;
		}

		if (read_len < 0) {
			switch (errno) {
			case EAGAIN:
				return TRUE;
			default:
				g_warning("sock_read: %s", g_strerror(errno));
				session->state = SESSION_ERROR;
				return FALSE;
			}
		}

		session->read_buf_len = read_len;
	}

	data_buf = session->read_data_buf;
	terminator_len = strlen(session->read_data_terminator);

	if (session->read_buf_len == 0)
		return TRUE;

	g_byte_array_append(data_buf, session->read_buf_p, session->read_buf_len);

	session->read_buf_len = 0;
	session->read_buf_p = session->read_buf;

	/* check if data is terminated */
	if (data_buf->len >= terminator_len) {
		if (memcmp(data_buf->data, session->read_data_terminator, terminator_len) == 0)
			complete = TRUE;
		else if (data_buf->len >= terminator_len + 2 && memcmp(data_buf->data + data_buf->len - (terminator_len + 2), "\r\n", 2) == 0 && memcmp(data_buf->data + data_buf->len - terminator_len, session->read_data_terminator, terminator_len) == 0)
			complete = TRUE;
	}

	/* incomplete read */
	if (!complete) {
		GDateTime *tv_cur = g_date_time_new_now_local();

		GTimeSpan ts = g_date_time_difference(tv_cur, session->tv_prev);
		if (1000 - ts < 0 || ts > UI_REFRESH_INTERVAL) {
			session->recv_data_progressive_notify(session, data_buf->len, 0, session->recv_data_progressive_notify_data);
			g_date_time_unref(session->tv_prev);
			session->tv_prev = g_date_time_new_now_local();
		}
		g_date_time_unref(tv_cur);
		return TRUE;
	}

	/* complete */
	if (session->io_tag > 0) {
		g_source_remove(session->io_tag);
		session->io_tag = 0;
	}

	data_len = data_buf->len - terminator_len;

	/* callback */
	ret = session->recv_data_finished(session, (gchar *)data_buf->data, data_len);

	g_byte_array_set_size(data_buf, 0);

	session->recv_data_notify(session, data_len, session->recv_data_notify_data);

	if (ret < 0)
		session->state = SESSION_ERROR;

	return FALSE;
}

static gint session_write_buf(Session *session)
{
	gint write_len;
	gint to_write_len;

	cm_return_val_if_fail(session->write_buf != NULL, -1);
	cm_return_val_if_fail(session->write_buf_p != NULL, -1);
	cm_return_val_if_fail(session->write_buf_len > 0, -1);

	to_write_len = session->write_buf_len - (session->write_buf_p - session->write_buf);
	to_write_len = MIN(to_write_len, SESSION_BUFFSIZE);

	write_len = sock_write(session->sock, session->write_buf_p, to_write_len);

	if (write_len < 0) {
		switch (errno) {
		case EAGAIN:
			write_len = 0;
			break;
		default:
			g_warning("sock_write: %s", g_strerror(errno));
			session->state = SESSION_ERROR;
			return -1;
		}
	}

	/* incomplete write */
	if (session->write_buf_p - session->write_buf + write_len < session->write_buf_len) {
		session->write_buf_p += write_len;
		return 1;
	}

	g_free(session->write_buf);
	session->write_buf = NULL;
	session->write_buf_p = NULL;
	session->write_buf_len = 0;

	return 0;
}

static gint session_write_data(Session *session)
{
	gint write_len;
	gint to_write_len;

	cm_return_val_if_fail(session->write_data != NULL, -1);
	cm_return_val_if_fail(session->write_data_p != NULL, -1);
	cm_return_val_if_fail(session->write_data_len > 0, -1);

	to_write_len = session->write_data_len - (session->write_data_p - session->write_data);
	to_write_len = MIN(to_write_len, SESSION_BUFFSIZE);

	write_len = sock_write(session->sock, session->write_data_p, to_write_len);

	if (write_len < 0) {
		switch (errno) {
		case EAGAIN:
			write_len = 0;
			break;
		default:
			g_warning("sock_write: %s", g_strerror(errno));
			session->state = SESSION_ERROR;
			return -1;
		}
	}

	/* incomplete write */
	if (session->write_data_p - session->write_data + write_len < session->write_data_len) {
		session->write_data_p += write_len;
		return 1;
	}

	session->write_data = NULL;
	session->write_data_p = NULL;
	session->write_data_len = 0;

	return 0;
}

static gboolean session_write_msg_cb(SockInfo *source, GIOCondition condition, gpointer data)
{
	Session *session = SESSION(data);
	gint ret;

	cm_return_val_if_fail(condition == G_IO_OUT, FALSE);
	cm_return_val_if_fail(session->write_buf != NULL, FALSE);
	cm_return_val_if_fail(session->write_buf_p != NULL, FALSE);
	cm_return_val_if_fail(session->write_buf_len > 0, FALSE);

	ret = session_write_buf(session);

	if (ret < 0) {
		session->state = SESSION_ERROR;
		return FALSE;
	} else if (ret > 0)
		return TRUE;

	if (session->io_tag > 0) {
		g_source_remove(session->io_tag);
		session->io_tag = 0;
	}

	session_recv_msg(session);

	return FALSE;
}

static gboolean session_write_data_cb(SockInfo *source, GIOCondition condition, gpointer data)
{
	Session *session = SESSION(data);
	guint write_data_len;
	gint ret;

	cm_return_val_if_fail(condition == G_IO_OUT, FALSE);
	cm_return_val_if_fail(session->write_data != NULL, FALSE);
	cm_return_val_if_fail(session->write_data_p != NULL, FALSE);
	cm_return_val_if_fail(session->write_data_len > 0, FALSE);

	write_data_len = session->write_data_len;

	ret = session_write_data(session);

	if (ret < 0) {
		session->state = SESSION_ERROR;
		return FALSE;
	} else if (ret > 0) {
		GDateTime *tv_cur = g_date_time_new_now_local();

		GTimeSpan ts = g_date_time_difference(tv_cur, session->tv_prev);
		if (1000 - ts < 0 || ts > UI_REFRESH_INTERVAL) {
			session_set_timeout(session, session->timeout_interval);
			session->send_data_progressive_notify(session, session->write_data_p - session->write_data, write_data_len, session->send_data_progressive_notify_data);
			g_date_time_unref(session->tv_prev);
			session->tv_prev = g_date_time_new_now_local();
		}
		g_date_time_unref(tv_cur);
		return TRUE;
	}

	if (session->io_tag > 0) {
		g_source_remove(session->io_tag);
		session->io_tag = 0;
	}

	/* callback */
	ret = session->send_data_finished(session, write_data_len);
	session->send_data_notify(session, write_data_len, session->send_data_notify_data);

	return FALSE;
}

void session_register_ping(Session *session, gboolean (*ping_cb)(gpointer data))
{
	if(!session)
		return;
	if (session->ping_tag > -1)
		g_source_remove(session->ping_tag);

	session->ping_tag = -1;

	if (ping_cb != NULL)
		session->ping_tag = g_timeout_add_seconds(60, ping_cb, session);
}
/*
 * vim: noet ts=4 shiftwidth=4
 */
