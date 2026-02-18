/*
 * Claws Mail -- a GTK based, lightweight, and fast e-mail client
 * Copyright (C) 1999-2026 the Claws Mail team
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#include "claws-features.h"
#endif

#ifdef USE_GPGME

#include <time.h>
#include <gtk/gtk.h>
#include <gpgme.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#ifndef G_OS_WIN32
#  include <sys/wait.h>
#else
#  include <pthread.h>
#  include <windows.h>
#endif
#if (defined(__DragonFly__) || defined(SOLARIS) || defined (__NetBSD__) || defined (__FreeBSD__) || defined (__OpenBSD__))
#  include <sys/signal.h>
#endif
#ifndef G_OS_WIN32
#include <sys/mman.h>
#endif
#if HAVE_LOCALE_H
#  include <locale.h>
#endif

#include "sgpgme.h"
#include "privacy.h"
#include "prefs_common.h"
#include "utils.h"
#include "alertpanel.h"
#include "passphrase.h"
#include "prefs_gpg.h"
#include "account.h"
#include "select-keys.h"
#include "claws.h"
#include "file-utils.h"

#define PGP_FINGERPRINT_MAX_LENGTH 128

static void sgpgme_disable_all(void)
{
    /* FIXME: set a flag, so that we don't bother the user with failed
     * gpgme messages */
}

void cm_free_detached_sig_task_data(gpointer data)
{
	DetachedSigTaskData *task_data = (DetachedSigTaskData *)data;

	g_free(task_data->boundary);
	g_free(task_data->text_filename);
	g_free(task_data->sig_filename);
	g_free(task_data);
}

void cm_check_detached_sig(GTask *task,
	gpointer source_object,
	gpointer _task_data,
	GCancellable *cancellable)
{
	DetachedSigTaskData *task_data = (DetachedSigTaskData *)_task_data;
	GQuark domain;
	FILE *fp;
	gpgme_ctx_t ctx;
	gpgme_error_t err;
	gpgme_data_t textdata = NULL;
	gpgme_data_t sigdata = NULL;
	gpgme_verify_result_t gpgme_res;
	gchar *textstr;
	gboolean return_err = TRUE;
	gboolean cancelled = FALSE;
	SigCheckTaskResult *task_result = NULL;
	char err_str[GPGERR_BUFSIZE] = "";

	domain = g_quark_from_static_string("claws_pgpcore");

	err = gpgme_new(&ctx);
	if (err != GPG_ERR_NO_ERROR) {
		gpgme_strerror_r(err, err_str, GPGERR_BUFSIZE);
		g_warning("couldn't initialize GPG context: %s", err_str);
		goto out;
	}

	err = gpgme_set_protocol(ctx, task_data->protocol);
	if (err != GPG_ERR_NO_ERROR) {
		gpgme_strerror_r(err, err_str, GPGERR_BUFSIZE);
		g_warning("couldn't set GPG protocol: %s", err_str);
		goto out_ctx;
	}

	fp = claws_fopen(task_data->text_filename, "rb");
	if (fp == NULL) {
		err = GPG_ERR_GENERAL;
		g_snprintf(err_str, GPGERR_BUFSIZE, "claws_fopen failed");
		goto out_ctx;
	}

	textstr = task_data->get_canonical_content(fp, task_data->boundary);
	claws_fclose(fp);

	err = gpgme_data_new_from_mem(&textdata, textstr, textstr?strlen(textstr):0, 0);
	if (err != GPG_ERR_NO_ERROR) {
		gpgme_strerror_r(err, err_str, GPGERR_BUFSIZE);
		g_warning("gpgme_data_new_from_mem failed: %s", err_str);
		goto out_textstr;
	}

	fp = claws_fopen(task_data->sig_filename, "rb");
	if (fp == NULL) {
		err = GPG_ERR_GENERAL;
		g_snprintf(err_str, GPGERR_BUFSIZE, "claws_fopen failed");
		goto out_textdata;
	}

	err = gpgme_data_new_from_filepart(&sigdata, NULL, fp, task_data->sig_offset, task_data->sig_length);
	claws_fclose(fp);
	if (err != GPG_ERR_NO_ERROR) {
		gpgme_strerror_r(err, err_str, GPGERR_BUFSIZE);
		g_warning("gpgme_data_new_from_filepart failed: %s", err_str);
		goto out_textdata;
	}

	if (task_data->sig_encoding == ENC_BASE64) {
		err = gpgme_data_set_encoding(sigdata, GPGME_DATA_ENCODING_BASE64);
		if (err != GPG_ERR_NO_ERROR) {
			gpgme_strerror_r(err, err_str, GPGERR_BUFSIZE);
			g_warning("gpgme_data_set_encoding failed: %s\n", err_str);
			goto out_sigdata;
		}
	}

	if (g_task_return_error_if_cancelled(task)) {
		debug_print("task was cancelled, aborting task:%p\n", task);
		cancelled = TRUE;
		goto out_sigdata;
	}

	err = gpgme_op_verify(ctx, sigdata, textdata, NULL);
	if (err != GPG_ERR_NO_ERROR) {
		gpgme_strerror_r(err, err_str, GPGERR_BUFSIZE);
		g_warning("gpgme_op_verify failed: %s\n", err_str);
		goto out_sigdata;
	}

	if (g_task_return_error_if_cancelled(task)) {
		debug_print("task was cancelled, aborting task:%p\n", task);
		cancelled = TRUE;
		goto out_sigdata;
	}

	gpgme_res = gpgme_op_verify_result(ctx);
	if (gpgme_res && gpgme_res->signatures == NULL) {
		err = GPG_ERR_SYSTEM_ERROR;
		g_warning("no signature found");
		g_snprintf(err_str, GPGERR_BUFSIZE, "No signature found");
		goto out_sigdata;
	}

	task_result = g_new0(SigCheckTaskResult, 1);
	task_result->sig_data = g_new0(SignatureData, 1);

	task_result->sig_data->status = sgpgme_sigstat_gpgme_to_privacy(ctx, gpgme_res);
	task_result->sig_data->info_short = sgpgme_sigstat_info_short(ctx, gpgme_res);
	task_result->sig_data->info_full = sgpgme_sigstat_info_full(ctx, gpgme_res);

	return_err = FALSE;

out_sigdata:
	gpgme_data_release(sigdata);
out_textdata:
	gpgme_data_release(textdata);
out_textstr:
	g_free(textstr);
out_ctx:
	gpgme_release(ctx);
out:
	if (cancelled)
		return;

	if (return_err)
		g_task_return_new_error(task, domain, err, "%s", err_str);
	else
		g_task_return_pointer(task, task_result, privacy_free_sig_check_task_result);
}

gint cm_check_detached_sig_async(MimeInfo *mimeinfo,
	GCancellable *cancellable,
	GAsyncReadyCallback callback,
	gpointer user_data,
	gpgme_protocol_t protocol,
	gchar *(*get_canonical_content)(FILE *, const gchar *))
{
	GTask *task;
	DetachedSigTaskData *task_data;
	MimeInfo *parent;
	MimeInfo *signature;
	gchar *boundary;

	parent = procmime_mimeinfo_parent(mimeinfo);

	boundary = g_hash_table_lookup(parent->typeparameters, "boundary");
	if (boundary == NULL) {
		debug_print("failed to lookup boundary string\n");
		return -1;
	}

	signature = (MimeInfo *) mimeinfo->node->next->data;

	task_data = g_new0(DetachedSigTaskData, 1);

	task_data->protocol = protocol;
	task_data->boundary = g_strdup(boundary);
	task_data->text_filename = g_strdup(parent->data.filename);
	task_data->sig_filename = g_strdup(signature->data.filename);
	task_data->sig_offset = signature->offset;
	task_data->sig_length = signature->length;
	task_data->sig_encoding = signature->encoding_type;
	task_data->get_canonical_content = get_canonical_content;

	task = g_task_new(NULL, cancellable, callback, user_data);
	mimeinfo->last_sig_check_task = task;

	g_task_set_task_data(task, task_data, cm_free_detached_sig_task_data);
	debug_print("creating check sig async task:%p task_data:%p\n", task, task_data);
	g_task_set_return_on_cancel(task, TRUE);
	g_task_run_in_thread(task, cm_check_detached_sig);
	g_object_unref(task);

	return 0;
}

gpgme_verify_result_t sgpgme_verify_signature(gpgme_ctx_t ctx, gpgme_data_t sig, 
					gpgme_data_t plain, gpgme_data_t dummy)
{
	gpgme_verify_result_t status = NULL;
	gpgme_error_t err;

	if ((err = gpgme_op_verify(ctx, sig, plain, dummy)) != GPG_ERR_NO_ERROR) {
		debug_print("op_verify err %s\n", gpgme_strerror(err));
		privacy_set_error("%s", gpgme_strerror(err));
		return GINT_TO_POINTER(-GPG_ERR_SYSTEM_ERROR);
	}
	status = gpgme_op_verify_result(ctx);
	if (status && status->signatures == NULL) {
		debug_print("no signature found\n");
		privacy_set_error(_("No signature found"));
		return GINT_TO_POINTER(-GPG_ERR_SYSTEM_ERROR);
	}
	return status;
}

SignatureStatus sgpgme_sigstat_gpgme_to_privacy(gpgme_ctx_t ctx, gpgme_verify_result_t status)
{
	gpgme_signature_t sig = NULL;
	
	if (GPOINTER_TO_INT(status) == -GPG_ERR_SYSTEM_ERROR) {
		debug_print("system error\n");
		return SIGNATURE_CHECK_FAILED;
	}

	if (status == NULL) {
		debug_print("status == NULL\n");
		return SIGNATURE_UNCHECKED;
	}
	sig = status->signatures;

	if (sig == NULL) {
		debug_print("sig == NULL\n");
		return SIGNATURE_UNCHECKED;
	}

	debug_print("err code %d\n", gpg_err_code(sig->status));
	switch (gpg_err_code(sig->status)) {
	case GPG_ERR_NO_ERROR:
		switch (sig->validity) {
		case GPGME_VALIDITY_NEVER:
			return SIGNATURE_INVALID;
		case GPGME_VALIDITY_UNKNOWN:
		case GPGME_VALIDITY_UNDEFINED:
		case GPGME_VALIDITY_MARGINAL:
		case GPGME_VALIDITY_FULL:
		case GPGME_VALIDITY_ULTIMATE:
			return SIGNATURE_OK;
		default:
			return SIGNATURE_CHECK_FAILED;
		}
	case GPG_ERR_SIG_EXPIRED:
	case GPG_ERR_CERT_REVOKED:
		return SIGNATURE_WARN;
	case GPG_ERR_KEY_EXPIRED:
		return SIGNATURE_KEY_EXPIRED;
	case GPG_ERR_BAD_SIGNATURE:
		return SIGNATURE_INVALID;
	case GPG_ERR_NO_PUBKEY:
		return SIGNATURE_CHECK_NO_KEY;
	default:
		return SIGNATURE_CHECK_FAILED;
	}
	return SIGNATURE_CHECK_FAILED;
}

static const gchar *get_validity_str(unsigned long validity)
{
	switch (gpg_err_code(validity)) {
	case GPGME_VALIDITY_UNKNOWN:
		return _("Unknown");
	case GPGME_VALIDITY_UNDEFINED:
		return _("Undefined");
	case GPGME_VALIDITY_NEVER:
		return _("Never");
	case GPGME_VALIDITY_MARGINAL:
		return _("Marginal");
	case GPGME_VALIDITY_FULL:
		return _("Full");
	case GPGME_VALIDITY_ULTIMATE:
		return _("Ultimate");
	default:
		return _("Error");
	}
}

static const gchar *get_owner_trust_str(unsigned long owner_trust)
{
	switch (gpgme_err_code(owner_trust)) {
	case GPGME_VALIDITY_NEVER:
		return _("Untrusted");
	case GPGME_VALIDITY_MARGINAL:
		return _("Marginal");
	case GPGME_VALIDITY_FULL:
		return _("Full");
	case GPGME_VALIDITY_ULTIMATE:
		return _("Ultimate");
	default:
		return _("Unknown");
	}
}

gchar *get_gpg_executable_name()
{
	gpgme_engine_info_t e;

	if (!gpgme_get_engine_info(&e)) {
		while (e != NULL) {
			if (e->protocol == GPGME_PROTOCOL_OpenPGP
					&& e->file_name != NULL) {
				debug_print("Found gpg executable: '%s'\n", e->file_name);
				return e->file_name;
			}
		}
	}

	return NULL;
}

static gchar *get_gpg_version_string()
{
	gpgme_engine_info_t e;

	if (!gpgme_get_engine_info(&e)) {
		while (e != NULL) {
			if (e->protocol == GPGME_PROTOCOL_OpenPGP
					&& e->version != NULL) {
				debug_print("Got OpenPGP version: '%s'\n", e->version);
				return e->version;
			}
		}
	}

	return NULL;
}

static gchar *extract_name(const char *uid)
{
	if (uid == NULL)
		return NULL;
	if (!strncmp(uid, "CN=", 3)) {
		gchar *result = g_strdup(uid+3);
		if (strstr(result, ","))
			*(strstr(result, ",")) = '\0';
		return result;
	} else if (strstr(uid, ",CN=")) {
		gchar *result = g_strdup(strstr(uid, ",CN=")+4);
		if (strstr(result, ","))
			*(strstr(result, ",")) = '\0';
		return result;
	} else {
		return g_strdup(uid);
	}
}
gchar *sgpgme_sigstat_info_short(gpgme_ctx_t ctx, gpgme_verify_result_t status)
{
	gpgme_signature_t sig = NULL;
	gchar *uname = NULL;
	gpgme_key_t key;
	gchar *result = NULL;
	gpgme_error_t err = 0;
	static gboolean warned = FALSE;

	if (GPOINTER_TO_INT(status) == -GPG_ERR_SYSTEM_ERROR) {
		return g_strdup_printf(_("The signature can't be checked - %s"), privacy_get_error());
	}

	if (status == NULL) {
		return g_strdup(_("The signature has not been checked."));
	}
	sig = status->signatures;
	if (sig == NULL) {
		return g_strdup(_("The signature has not been checked."));
	}

	err = gpgme_get_key(ctx, sig->fpr, &key, 0);
	if (gpg_err_code(err) == GPG_ERR_NO_AGENT) {
		if (!warned)
			alertpanel_error(_("PGP Core: Can't get key - no gpg-agent running."));
		else
			g_warning("PGP Core: can't get key - no gpg-agent running");
		warned = TRUE;
	} else if (gpg_err_code(err) != GPG_ERR_NO_ERROR && gpg_err_code(err) != GPG_ERR_EOF) {
		return g_strdup_printf(_("The signature can't be checked - %s"), 
			gpgme_strerror(err));
  }

	if (key)
		uname = extract_name(key->uids->uid);
	else
		uname = g_strdup("<?>");

	switch (gpg_err_code(sig->status)) {
	case GPG_ERR_NO_ERROR:
               switch ((key && key->uids) ? key->uids->validity : GPGME_VALIDITY_UNKNOWN) {
		case GPGME_VALIDITY_ULTIMATE:
			result = g_strdup_printf(_("Good signature from \"%s\" [ultimate]"), uname);
			break;
		case GPGME_VALIDITY_FULL:
			result = g_strdup_printf(_("Good signature from \"%s\" [full]"), uname);
			break;
		case GPGME_VALIDITY_MARGINAL:
			result = g_strdup_printf(_("Good signature from \"%s\" [marginal]"), uname);
			break;
		case GPGME_VALIDITY_UNKNOWN:
		case GPGME_VALIDITY_UNDEFINED:
		case GPGME_VALIDITY_NEVER:
		default:
			if (key) {
				result = g_strdup_printf(_("Good signature from \"%s\""), uname);
			} else {
				result = g_strdup_printf(_("Key 0x%s not available to verify this signature"), sig->fpr);
			}
			break;
               }
		break;
	case GPG_ERR_SIG_EXPIRED:
		result = g_strdup_printf(_("Expired signature from \"%s\""), uname);
		break;
	case GPG_ERR_KEY_EXPIRED:
		result = g_strdup_printf(_("Good signature from \"%s\", but the key has expired"), uname);
		break;
	case GPG_ERR_CERT_REVOKED:
		result = g_strdup_printf(_("Good signature from \"%s\", but the key has been revoked"), uname);
		break;
	case GPG_ERR_BAD_SIGNATURE:
		result = g_strdup_printf(_("Bad signature from \"%s\""), uname);
		break;
	case GPG_ERR_NO_PUBKEY: {
		result = g_strdup_printf(_("Key 0x%s not available to verify this signature"), sig->fpr);
		break;
		}
	default:
		result = g_strdup(_("The signature has not been checked"));
		break;
	}
	if (result == NULL)
		result = g_strdup(_("Error"));
	g_free(uname);

	if (key)
		gpgme_key_unref(key);

	return result;
}

gchar *sgpgme_sigstat_info_full(gpgme_ctx_t ctx, gpgme_verify_result_t status)
{
	gint i = 0;
	GString *siginfo;
	gpgme_signature_t sig = NULL;

	siginfo = g_string_sized_new(64);
	if (status == NULL) {
		g_string_append_printf(siginfo,
			_("Error checking signature: no status\n"));
		goto bail;
	 }

	sig = status->signatures;
	
	while (sig) {
		char buf[100];
		struct tm lt;
		gpgme_key_t key;
		gpgme_error_t err;
		gpgme_user_id_t tmp;
		const gchar *keytype, *keyid, *uid;
		
		err = gpgme_get_key(ctx, sig->fpr, &key, 0);

		if (err != GPG_ERR_NO_ERROR) {
			key = NULL;
			g_string_append_printf(siginfo, 
				_("Error checking signature: %s\n"),
				gpgme_strerror(err));
			goto bail;
		}
		if (key) {
			keytype = gpgme_pubkey_algo_name(
					key->subkeys->pubkey_algo);
			keyid = key->subkeys->keyid;
			uid = key->uids->uid;
		} else {
			keytype = "?";
			keyid = "?";
			uid = "?";
		}

		memset(buf, 0, sizeof(buf));
		fast_strftime(buf, sizeof(buf)-1, prefs_common_get_prefs()->date_format, localtime_r((time_t *)&sig->timestamp, &lt));
		g_string_append_printf(siginfo,
			_("Signature made on %s using %s key ID %s\n"),
			buf, keytype, keyid);
		
		switch (gpg_err_code(sig->status)) {
		case GPG_ERR_NO_ERROR:
			g_string_append_printf(siginfo,
				_("Good signature from uid \"%s\" (Validity: %s)\n"),
				uid, get_validity_str((key && key->uids) ? key->uids->validity:GPGME_VALIDITY_UNKNOWN));
			break;
		case GPG_ERR_KEY_EXPIRED:
			g_string_append_printf(siginfo,
				_("Expired key uid \"%s\"\n"),
				uid);
			break;
		case GPG_ERR_SIG_EXPIRED:
			g_string_append_printf(siginfo,
				_("Expired signature from uid \"%s\" (Validity: %s)\n"),
				uid, get_validity_str((key && key->uids) ? key->uids->validity:GPGME_VALIDITY_UNKNOWN));
			break;
		case GPG_ERR_CERT_REVOKED:
			g_string_append_printf(siginfo,
				_("Revoked key uid \"%s\"\n"),
				uid);
			break;
		case GPG_ERR_BAD_SIGNATURE:
			g_string_append_printf(siginfo,
				_("BAD signature from \"%s\"\n"),
				uid);
			break;
		default:
			break;
		}
		if (sig->status != GPG_ERR_BAD_SIGNATURE) {
			gint j = 1;
			if (key) {
				tmp = key->uids ? key->uids->next : NULL;
				while (tmp != NULL) {
					g_string_append_printf(siginfo,
						_("                    uid \"%s\" (Validity: %s)\n"),
						tmp->uid,
						tmp->revoked==TRUE?_("Revoked"):get_validity_str(tmp->validity));
					j++;
					tmp = tmp->next;
				}
			}
			g_string_append_printf(siginfo,_("Owner Trust: %s\n"),
					       key ? get_owner_trust_str(key->owner_trust) : _("No key!"));
			g_string_append(siginfo,
				_("Primary key fingerprint:"));
			const char* primary_fpr = NULL;
			if (key && key->subkeys && key->subkeys->fpr)
				primary_fpr = key->subkeys->fpr;
			else
				g_string_append(siginfo, " ?");
			int idx; /* now pretty-print the fingerprint */
			for (idx=0; primary_fpr && *primary_fpr!='\0'; idx++, primary_fpr++) {
				if (idx%4==0)
					g_string_append_c(siginfo, ' ');
				if (idx%20==0)
					g_string_append_c(siginfo, ' ');
				g_string_append_c(siginfo, (gchar)*primary_fpr);
			}
			g_string_append_c(siginfo, '\n');

			if (sig->pka_trust == 1 && sig->pka_address) {
				g_string_append_printf(siginfo,
					_("WARNING: Signer's address \"%s\" "
					"does not match DNS entry\n"),
					sig->pka_address);
			}
			else if (sig->pka_trust == 2 && sig->pka_address) {
				g_string_append_printf(siginfo,
					_("Verified signer's address is \"%s\"\n"),
						sig->pka_address);
						/* FIXME: Compare the address to the
						 * From: address.  */
			}
		}

		g_string_append(siginfo, "\n");
		i++;
		sig = sig->next;
		gpgme_key_unref(key);
	}
bail:
	return g_string_free(siginfo, FALSE);
}

gpgme_data_t sgpgme_data_from_mimeinfo(MimeInfo *mimeinfo)
{
	gpgme_data_t data = NULL;
	gpgme_error_t err;
	FILE *fp = claws_fopen(mimeinfo->data.filename, "rb");

	if (!fp) 
		return NULL;

	err = gpgme_data_new_from_filepart(&data, NULL, fp, mimeinfo->offset, mimeinfo->length);
	claws_fclose(fp);

	debug_print("data %p (%ld %ld)\n", (void *)&data, mimeinfo->offset, mimeinfo->length);
	if (err) {
		debug_print ("gpgme_data_new_from_file failed: %s\n",
			     gpgme_strerror (err));
		privacy_set_error(_("Couldn't get data from message, %s"), gpgme_strerror(err));
		return NULL;
	}
	return data;
}

gpgme_data_t sgpgme_decrypt_verify(gpgme_data_t cipher, gpgme_verify_result_t *status, gpgme_ctx_t ctx)
{
	struct passphrase_cb_info_s info;
	gpgme_data_t plain;
	gpgme_error_t err;

	memset (&info, 0, sizeof info);
	
	if ((err = gpgme_data_new(&plain)) != GPG_ERR_NO_ERROR) {
		gpgme_release(ctx);
		privacy_set_error(_("Couldn't initialize data, %s"), gpgme_strerror(err));
		return NULL;
	}
	
	if (gpgme_get_protocol(ctx) == GPGME_PROTOCOL_OpenPGP) {
		prefs_gpg_enable_agent(prefs_gpg_get_config()->use_gpg_agent);
		if (!g_getenv("GPG_AGENT_INFO") || !prefs_gpg_get_config()->use_gpg_agent) {
        		info.c = ctx;
        		gpgme_set_passphrase_cb (ctx, gpgmegtk_passphrase_cb, &info);
    		}
	} else {
		prefs_gpg_enable_agent(TRUE);
        	info.c = ctx;
        	gpgme_set_passphrase_cb (ctx, NULL, &info);
	}
	
	
	if (gpgme_get_protocol(ctx) == GPGME_PROTOCOL_OpenPGP) {
		err = gpgme_op_decrypt_verify(ctx, cipher, plain);
		if (err != GPG_ERR_NO_ERROR) {
			debug_print("can't decrypt (%s)\n", gpgme_strerror(err));
			privacy_set_error("%s", gpgme_strerror(err));
			gpgmegtk_free_passphrase();
			gpgme_data_release(plain);
			return NULL;
		}

		err = cm_gpgme_data_rewind(plain);
		if (err) {
			debug_print("can't seek (%d %d %s)\n", err, errno, g_strerror(errno));
		}

		debug_print("decrypted.\n");
		*status = gpgme_op_verify_result (ctx);
	} else {
		err = gpgme_op_decrypt(ctx, cipher, plain);
		if (err != GPG_ERR_NO_ERROR) {
			debug_print("can't decrypt (%s)\n", gpgme_strerror(err));
			privacy_set_error("%s", gpgme_strerror(err));
			gpgmegtk_free_passphrase();
			gpgme_data_release(plain);
			return NULL;
		}

		err = cm_gpgme_data_rewind(plain);
		if (err) {
			debug_print("can't seek (%d %d %s)\n", err, errno, g_strerror(errno));
		}

		debug_print("decrypted.\n");
		*status = gpgme_op_verify_result (ctx);
	}
	return plain;
}

gchar *sgpgme_get_encrypt_data(GSList *recp_names, gpgme_protocol_t proto)
{
	SelectionResult result = KEY_SELECTION_CANCEL;
	gpgme_key_t *keys = gpgmegtk_recipient_selection(recp_names, &result,
				proto);
	gchar *ret = NULL;
	int i = 0;

	if (!keys) {
		if (result == KEY_SELECTION_DONT)
			return g_strdup("_DONT_ENCRYPT_");
		else
			return NULL;
	}
	while (keys[i]) {
		gpgme_subkey_t skey = keys[i]->subkeys;
		gchar *fpr = skey->fpr;
		gchar *tmp = NULL;
		debug_print("adding %s\n", fpr);
		tmp = g_strconcat(ret ? ret : "", fpr, " ", NULL);
		if (ret)
			g_free(ret);
		ret = tmp;
		i++;
	}
	g_free(keys);
	return ret;
}

gboolean sgpgme_setup_signers(gpgme_ctx_t ctx, PrefsAccount *account,
			      const gchar *from_addr)
{
	GPGAccountConfig *config;
	const gchar *signer_addr = account->address;
	SignKeyType sk;
	gchar *skid;
	gboolean smime = FALSE;

	gpgme_signers_clear(ctx);

	if (gpgme_get_protocol(ctx) == GPGME_PROTOCOL_CMS)
		smime = TRUE;

	if (from_addr)
		signer_addr = from_addr;
	config = prefs_gpg_account_get_config(account);

	if(smime) {
		debug_print("sgpgme_setup_signers: S/MIME protocol\n");
		sk = config->smime_sign_key;
		skid = config->smime_sign_key_id;
	} else {
		debug_print("sgpgme_setup_signers: OpenPGP protocol\n");
		sk = config->sign_key;
		skid = config->sign_key_id;
	}

	switch(sk) {
	case SIGN_KEY_DEFAULT:
		debug_print("using default gnupg key\n");
		break;
	case SIGN_KEY_BY_FROM:
		debug_print("using key for %s\n", signer_addr);
		break;
	case SIGN_KEY_CUSTOM:
		debug_print("using key for %s\n", skid);
		break;
	}

	if (sk != SIGN_KEY_DEFAULT) {
		const gchar *keyid;
		gpgme_key_t key, found_key;
		gpgme_error_t err;

		if (sk == SIGN_KEY_BY_FROM)
			keyid = signer_addr;
		else if (sk == SIGN_KEY_CUSTOM)
			keyid = skid;
		else
			goto bail;

                found_key = NULL;
		/* Look for any key, not just private ones, or GPGMe doesn't
		 * correctly set the revoked flag. */
		err = gpgme_op_keylist_start(ctx, keyid, 0);
		while (err == 0) {
			if ((err = gpgme_op_keylist_next(ctx, &key)) != 0)
				break;

			if (key == NULL)
				continue;

			if (!key->can_sign) {
				debug_print("skipping a key, can not be used for signing\n");
				gpgme_key_unref(key);
				continue;
			}

			if (key->protocol != gpgme_get_protocol(ctx)) {
				debug_print("skipping a key (wrong protocol %d)\n", key->protocol);
				gpgme_key_unref(key);
				continue;
			}

			if (key->expired) {
				debug_print("skipping a key, expired\n");
				gpgme_key_unref(key);
				continue;
			}
			if (key->revoked) {
				debug_print("skipping a key, revoked\n");
				gpgme_key_unref(key);
				continue;
			}
			if (key->disabled) {
				debug_print("skipping a key, disabled\n");
				gpgme_key_unref(key);
				continue;
			}

			if (found_key != NULL) {
				gpgme_key_unref(key);
				gpgme_op_keylist_end(ctx);
				g_warning("ambiguous specification of secret key '%s'", keyid);
				privacy_set_error(_("Secret key specification is ambiguous"));
				goto bail;
			}

			found_key = key;
		}
		gpgme_op_keylist_end(ctx);

		if (found_key == NULL) {
			g_warning("setup_signers start: %s", gpgme_strerror(err));
			privacy_set_error(_("Secret key not found (%s)"), gpgme_strerror(err));
			goto bail;
                }

		err = gpgme_signers_add(ctx, found_key);
		debug_print("got key (proto %d (pgp %d, smime %d).\n",
			    found_key->protocol, GPGME_PROTOCOL_OpenPGP,
			    GPGME_PROTOCOL_CMS);
		gpgme_key_unref(found_key);

		if (err) {
			g_warning("error adding secret key: %s",
				  gpgme_strerror(err));
			privacy_set_error(_("Error setting secret key: %s"),
					  gpgme_strerror(err));
			goto bail;
		}
        }

	prefs_gpg_account_free_config(config);

	return TRUE;
bail:
	prefs_gpg_account_free_config(config);
	return FALSE;
}

void sgpgme_init()
{
	gchar *ctype_locale = NULL, *messages_locale = NULL;
	gchar *ctype_utf8_locale = NULL, *messages_utf8_locale = NULL;
	gpgme_error_t err = 0;

	gpgme_engine_info_t engineInfo;

	if (strcmp(prefs_gpg_get_config()->gpg_path, "") != 0
	    && access(prefs_gpg_get_config()->gpg_path, X_OK) != -1) {
		err = gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, prefs_gpg_get_config()->gpg_path, NULL);
		if (err != GPG_ERR_NO_ERROR)
			g_warning("failed to set crypto engine configuration: %s", gpgme_strerror(err));
	}

	if (gpgme_check_version("1.0.0")) {
#ifdef LC_CTYPE
		debug_print("setting gpgme CTYPE locale\n");
#ifdef G_OS_WIN32
		ctype_locale = g_win32_getlocale();
#else
		ctype_locale = g_strdup(setlocale(LC_CTYPE, NULL));
#endif
		if (ctype_locale) {
			debug_print("setting gpgme CTYPE locale to: %s\n", ctype_locale);
			if (strchr(ctype_locale, '.'))
				*(strchr(ctype_locale, '.')) = '\0';
			else if (strchr(ctype_locale, '@'))
				*(strchr(ctype_locale, '@')) = '\0';
			ctype_utf8_locale = g_strconcat(ctype_locale, ".UTF-8", NULL);

			debug_print("setting gpgme locale to UTF8: %s\n", ctype_utf8_locale ? ctype_utf8_locale : "NULL");
			gpgme_set_locale(NULL, LC_CTYPE, ctype_utf8_locale);

			debug_print("done\n");
			g_free(ctype_utf8_locale);
			g_free(ctype_locale);
		} else {
			debug_print("couldn't set gpgme CTYPE locale\n");
		}
#endif
#ifdef LC_MESSAGES
		debug_print("setting gpgme MESSAGES locale\n");
#ifdef G_OS_WIN32
		messages_locale = g_win32_getlocale();
#else
		messages_locale = g_strdup(setlocale(LC_MESSAGES, NULL));
#endif
		if (messages_locale) {
			debug_print("setting gpgme MESSAGES locale to: %s\n", messages_locale);
			if (strchr(messages_locale, '.'))
				*(strchr(messages_locale, '.')) = '\0';
			else if (strchr(messages_locale, '@'))
				*(strchr(messages_locale, '@')) = '\0';
			messages_utf8_locale = g_strconcat(messages_locale, ".UTF-8", NULL);
			debug_print("setting gpgme locale to UTF8: %s\n", messages_utf8_locale ? messages_utf8_locale : "NULL");

			gpgme_set_locale(NULL, LC_MESSAGES, messages_utf8_locale);

			debug_print("done\n");
			g_free(messages_utf8_locale);
			g_free(messages_locale);
		} else {
			debug_print("couldn't set gpgme MESSAGES locale\n");
		}
#endif
		if (!gpgme_get_engine_info(&engineInfo)) {
			while (engineInfo) {
				debug_print("GpgME Protocol: %s\n"
					    "Version: %s (req %s)\n"
					    "Executable: %s\n",
					gpgme_get_protocol_name(engineInfo->protocol) ? gpgme_get_protocol_name(engineInfo->protocol):"???",
					engineInfo->version ? engineInfo->version:"???",
					engineInfo->req_version ? engineInfo->req_version:"???",
					engineInfo->file_name ? engineInfo->file_name:"???");
				if (engineInfo->protocol == GPGME_PROTOCOL_OpenPGP
				&&  gpgme_engine_check_version(engineInfo->protocol) != 
					GPG_ERR_NO_ERROR) {
					if (engineInfo->file_name && !engineInfo->version) {
						alertpanel_error(_("Gpgme protocol '%s' is unusable: "
								   "Engine '%s' isn't installed properly."),
								   gpgme_get_protocol_name(engineInfo->protocol),
								   engineInfo->file_name);
					} else if (engineInfo->file_name && engineInfo->version
					  && engineInfo->req_version) {
						alertpanel_error(_("Gpgme protocol '%s' is unusable: "
								   "Engine '%s' version %s is installed, "
								   "but version %s is required.\n"),
								   gpgme_get_protocol_name(engineInfo->protocol),
								   engineInfo->file_name,
								   engineInfo->version,
								   engineInfo->req_version);
					} else {
						alertpanel_error(_("Gpgme protocol '%s' is unusable "
								   "(unknown problem)"),
								   gpgme_get_protocol_name(engineInfo->protocol));
					}
				}
				engineInfo = engineInfo->next;
			}
		}
	} else {
		sgpgme_disable_all();

		if (prefs_gpg_get_config()->gpg_warning) {
			AlertValue val;

			val = alertpanel_full
				(_("Warning"),
				 _("GnuPG is not installed properly, or needs "
				 "to be upgraded.\n"
				 "OpenPGP support disabled."),
				 "window-close-symbolic", _("_Close"), NULL, NULL, NULL, NULL,
				 ALERTFOCUS_FIRST, TRUE, NULL, ALERT_WARNING);
			if (val & G_ALERTDISABLE)
				prefs_gpg_get_config()->gpg_warning = FALSE;
		}
	}
}

void sgpgme_done()
{
        gpgmegtk_free_passphrase();
}

#ifdef G_OS_WIN32
struct _ExportCtx {
	gboolean done;
	gchar *cmd;
	DWORD exitcode;
};

static void *_export_threaded(void *arg)
{
	struct _ExportCtx *ctx = (struct _ExportCtx *)arg;
	gboolean result;

	PROCESS_INFORMATION pi = {0};
	STARTUPINFO si = {0};

	result = CreateProcess(NULL, ctx->cmd, NULL, NULL, FALSE,
			NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW,
			NULL, NULL, &si, &pi);

	if (!result) {
		debug_print("Couldn't execute '%s'\n", ctx->cmd);
	} else {
		WaitForSingleObject(pi.hProcess, 10000);
		result = GetExitCodeProcess(pi.hProcess, &ctx->exitcode);
		if (ctx->exitcode == STILL_ACTIVE) {
			debug_print("Process still running, terminating it.\n");
			TerminateProcess(pi.hProcess, 255);
		}

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		if (!result) {
			debug_print("Process executed, but we couldn't get its exit code (huh?)\n");
		}
	}

	ctx->done = TRUE;
	return NULL;
}
#endif

void sgpgme_create_secret_key(PrefsAccount *account, gboolean ask_create)
{
	AlertValue val = G_ALERTDEFAULT;
	gchar *key_parms = NULL;
	gchar *name = NULL;
	gchar *email = NULL;
	gchar *passphrase = NULL, *passphrase_second = NULL;
	gint prev_bad = 0;
	gchar *tmp = NULL, *gpgver;
	gpgme_error_t err = 0;
	gpgme_ctx_t ctx;
	GtkWidget *window = NULL;
	gpgme_genkey_result_t key;
	gboolean exported = FALSE;

	if (account == NULL)
		account = account_get_default();

	if (account->address == NULL) {
		alertpanel_error(_("You have to save the account's information with \"OK\" "
				   "before being able to generate a key pair.\n"));
		return;
	}
	if (ask_create) {
		val = alertpanel(_("No PGP key found"),
				_("Claws Mail did not find a secret PGP key, "
				  "which means that you won't be able to sign "
				  "emails or receive encrypted emails.\n"
				  "Do you want to create a new key pair now?"),
				  NULL, _("_No"), NULL, _("_Yes"), NULL, NULL,
				 ALERTFOCUS_SECOND);
		if (val == G_ALERTDEFAULT) {
			return;
		}
	}

	if (account->name) {
		name = g_strdup(account->name);
	} else {
		name = g_strdup(account->address);
	}
	email = g_strdup(account->address);
	tmp = g_strdup_printf("%s <%s>", account->name?account->name:account->address, account->address);
	gpgver = get_gpg_version_string();
	if (gpgver == NULL || !strncmp(gpgver, "1.", 2)) {
		debug_print("Using gpg 1.x, using builtin passphrase dialog.\n");
again:
		passphrase = passphrase_mbox(tmp, NULL, prev_bad, 1);
		if (passphrase == NULL) {
			g_free(tmp);
			g_free(email);
			g_free(name);
			return;
		}
		passphrase_second = passphrase_mbox(tmp, NULL, 0, 2);
		if (passphrase_second == NULL) {
			g_free(tmp);
			g_free(email);
			if (passphrase != NULL) {
				memset(passphrase, 0, strlen(passphrase));
				g_free(passphrase);
			}
			g_free(name);
			return;
		}
		if (strcmp(passphrase, passphrase_second)) {
			if (passphrase != NULL) {
				memset(passphrase, 0, strlen(passphrase));
				g_free(passphrase);
			}
			if (passphrase_second != NULL) {
				memset(passphrase_second, 0, strlen(passphrase_second));
				g_free(passphrase_second);
			}
			prev_bad = 1;
			goto again;
		}
	}
	
	key_parms = g_strdup_printf("<GnupgKeyParms format=\"internal\">\n"
					"Key-Type: RSA\n"
					"Key-Length: 2048\n"
					"Subkey-Type: RSA\n"
					"Subkey-Length: 2048\n"
					"Name-Real: %s\n"
					"Name-Email: %s\n"
					"Expire-Date: 0\n"
					"%s%s%s"
					"</GnupgKeyParms>\n",
					name, email, 
					passphrase?"Passphrase: ":"",
					passphrase?passphrase:"",
					passphrase?"\n":"");
#ifndef G_PLATFORM_WIN32
	if (passphrase &&
			mlock(passphrase, strlen(passphrase)) == -1)
		debug_print("couldn't lock passphrase\n");
	if (passphrase_second &&
			mlock(passphrase_second, strlen(passphrase_second)) == -1)
		debug_print("couldn't lock passphrase2\n");
#endif
	g_free(tmp);
	g_free(email);
	g_free(name);
	if (passphrase_second != NULL) {
		memset(passphrase_second, 0, strlen(passphrase_second));
		g_free(passphrase_second);
	}
	if (passphrase != NULL) {
		memset(passphrase, 0, strlen(passphrase));
		g_free(passphrase);
	}
	
	err = gpgme_new (&ctx);
	if (err) {
		alertpanel_error(_("Couldn't generate a new key pair: %s"),
				 gpgme_strerror(err));
		if (key_parms != NULL) {
			memset(key_parms, 0, strlen(key_parms));
			g_free(key_parms);
		}
		return;
	}
	

	window = label_window_create(_("Generating your new key pair... Please move the mouse "
			      "around to help generate entropy..."));

	err = gpgme_op_genkey(ctx, key_parms, NULL, NULL);
	if (key_parms != NULL) {
		memset(key_parms, 0, strlen(key_parms));
		g_free(key_parms);
	}

	label_window_destroy(window);

	if (err) {
		alertpanel_error(_("Couldn't generate a new key pair: %s"), gpgme_strerror(err));
		gpgme_release(ctx);
		return;
	}
	key = gpgme_op_genkey_result(ctx);
	if (key == NULL) {
		alertpanel_error(_("Couldn't generate a new key pair: unknown error"));
		gpgme_release(ctx);
		return;
	} else {
		gchar *buf = g_strdup_printf(_("Your new key pair has been generated. "
				    "Its fingerprint is:\n%s\n\nDo you want to export it "
				    "to a keyserver?"),
				    key->fpr ? key->fpr:"null");
		AlertValue val = alertpanel(_("Key generated"), buf,
				  NULL, _("_No"), NULL, _("_Yes"), NULL, NULL, ALERTFOCUS_SECOND);
		g_free(buf);
		if (val == G_ALERTALTERNATE) {
			gchar *gpgbin = get_gpg_executable_name();
			gchar *cmd = g_strdup_printf("\"%s\" --batch --no-tty --send-keys %s",
				(gpgbin ? gpgbin : "gpg"), key->fpr);
			debug_print("Executing command: %s\n", cmd);

#ifndef G_OS_WIN32
			int res = 0;
			pid_t pid = 0;
			pid = fork();
			if (pid == -1) {
				res = -1;
			} else if (pid == 0) {
				/* son */
				res = system(cmd);
				res = WEXITSTATUS(res);
				_exit(res);
			} else {
				int status = 0;
				time_t start_wait = time(NULL);
				res = -1;
				do {
					if (waitpid(pid, &status, WNOHANG) == 0 || !WIFEXITED(status)) {
						usleep(200000);
					} else {
						res = WEXITSTATUS(status);
						break;
					}
					if (time(NULL) - start_wait > 5) {
						debug_print("SIGTERM'ing gpg\n");
						kill(pid, SIGTERM);
					}
					if (time(NULL) - start_wait > 6) {
						debug_print("SIGKILL'ing gpg\n");
						kill(pid, SIGKILL);
						break;
					}
				} while(1);
			}

			if (res == 0)
				exported = TRUE;
#else
			/* We need to call gpg in a separate thread, so that waiting for
			 * it to finish does not block the UI. */
			pthread_t pt;
			struct _ExportCtx *ectx = malloc(sizeof(struct _ExportCtx));

			ectx->done = FALSE;
			ectx->exitcode = STILL_ACTIVE;
			ectx->cmd = cmd;

			if (pthread_create(&pt, NULL,
						_export_threaded, (void *)ectx) != 0) {
				debug_print("Couldn't create thread, continuing unthreaded.\n");
				_export_threaded(ctx);
			} else {
				debug_print("Thread created, waiting for it to finish...\n");
				while (!ectx->done)
					claws_do_idle();
			}

			debug_print("Thread finished.\n");
			pthread_join(pt, NULL);

			if (ectx->exitcode == 0)
				exported = TRUE;

			g_free(ectx);
#endif
			g_free(cmd);

			if (exported) {
				alertpanel_notice(_("Key exported."));
			} else {
				alertpanel_error(_("Couldn't export key."));
			}
		}
	}
	gpgme_release(ctx);
}

gboolean sgpgme_has_secret_key(void)
{
	gpgme_error_t err = 0;
	gpgme_ctx_t ctx;
	gpgme_key_t key;

	err = gpgme_new (&ctx);
	if (err) {
		debug_print("err : %s\n", gpgme_strerror(err));
		return TRUE;
	}
check_again:
	err = gpgme_op_keylist_start(ctx, NULL, TRUE);
	if (!err) {
		err = gpgme_op_keylist_next(ctx, &key);
		gpgme_key_unref(key); /* We're not interested in the key itself. */
	}
	gpgme_op_keylist_end(ctx);
	if (gpg_err_code(err) == GPG_ERR_EOF) {
		if (gpgme_get_protocol(ctx) != GPGME_PROTOCOL_CMS) {
			gpgme_set_protocol(ctx, GPGME_PROTOCOL_CMS);
			goto check_again;
		}
		gpgme_release(ctx);
		return FALSE;
	} else {
		gpgme_release(ctx);
		return TRUE;
	}
}

void sgpgme_check_create_key(void)
{
	if (prefs_gpg_get_config()->gpg_ask_create_key &&
	    !sgpgme_has_secret_key()) {
		sgpgme_create_secret_key(NULL, TRUE);
	}

	prefs_gpg_get_config()->gpg_ask_create_key = FALSE;
	prefs_gpg_save_config();
}

void *sgpgme_data_release_and_get_mem(gpgme_data_t data, size_t *len)
{
	char buf[BUFSIZ];
	void *result = NULL;
	ssize_t r = 0;
	size_t w = 0;
	
	cm_return_val_if_fail(data != NULL, NULL);
	cm_return_val_if_fail(len != NULL, NULL);

	/* I know it's deprecated, but we don't compile with _LARGEFILE */
	cm_gpgme_data_rewind(data);
	while ((r = gpgme_data_read(data, buf, BUFSIZ)) > 0) {
		void *rresult = realloc(result, r + w);
		if (rresult == NULL) {
			g_warning("can't allocate memory");
			if (result != NULL)
				free(result);
			return NULL;
		}
		result = rresult;
		memcpy(result+w, buf, r);
		w += r;
	}
	
	*len = w;

	gpgme_data_release(data);
	if (r < 0) {
		g_warning("gpgme_data_read() returned an error: %d", (int)r);
		free(result);
		*len = 0;
		return NULL;
	}
	return result;
}

gpgme_error_t cm_gpgme_data_rewind(gpgme_data_t dh)
{
#if defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64
	if (gpgme_data_seek(dh, (off_t)0, SEEK_SET) == -1)
		return gpg_error_from_errno(errno);
	else
		return 0;
#else
	return gpgme_data_rewind(dh);
#endif
}


/* custom replacement for GPGME's gpgme_get_key. For more info see
 * https://lists.gnupg.org/pipermail/gnupg-devel/2025-November/036087.html
 *
 * Code adapted from GPGME/src/keylist.c (LGPL-2.1-or-later):
 * - removed TRACE calls
 * - replaced gpg_error with gpgme_error alias
 * - removed context duplication as we already pass a brand new one
 * - indented according to CLaws-Mail rules
 * - skipped secret, revoked and invalid keys
 * - properly end the keylisting since listctx comes as a argument
 * - skip expired keys when a usable key exists
 * - only check for ambiguity (to return GPG_ERR_AMBIGUOUS_NAME) if
 *   the key found is neither expired nor revoked
 *
 * Original checkout from libgpgme last commit at 2025-10-29T09:22:34
 * 2360b937cf8f9bc52655e45dccd1885dd4c7ac32
 */
static gpgme_error_t
sgpgme_get_public_key (gpgme_ctx_t listctx, const char *fpr, gpgme_key_t *r_key)
{
	gpgme_error_t err;
	gpgme_key_t key = NULL;
	gpgme_key_t result = NULL;
	gpgme_key_t expired = NULL;

	if (r_key)
		*r_key = NULL;

	if (!listctx || !r_key || !fpr)
		return gpgme_error(GPG_ERR_INV_VALUE);

	if (strlen(fpr) < 8)	/* We have at least a key ID.  */
		return gpgme_error(GPG_ERR_INV_VALUE);

	err = gpgme_op_keylist_start(listctx, fpr, 0);
	pick_a_candidate_result:
	if (!err) {
		err = gpgme_op_keylist_next(listctx, &result);
		if (result && result->secret) {
			/* we need a public key */
			gpgme_key_unref(result);
			goto pick_a_candidate_result;
		}
		if (result && (result->invalid || result->revoked)) {
			/* we can't handle invalid keys */
			gpgme_key_unref(result);
			goto pick_a_candidate_result;
		}
		if (result && result->expired) {
			/* we return expired keys only if no better one is available */
			if (expired) {
				if (expired->subkeys->timestamp < result->subkeys->timestamp) {
					/* we only keep the most recent expired key */
					gpgme_key_unref(expired);
					expired = result;
				} else {
					gpgme_key_unref(result);
				}
			} else
				expired = result;
			result = NULL;
			goto pick_a_candidate_result;
		}
	}
	if (result == NULL) {
		if (expired != NULL) {
			result = expired;
			err = 0;
		}
	} else {
		gpgme_key_unref(expired);
	}
	expired = NULL;
	if (!err && result && !result->expired && !result->revoked) {
		try_next_key:
		err = gpgme_op_keylist_next(listctx, &key);
		if (gpgme_err_code(err) == GPG_ERR_EOF)
			err = 0;
		else if (!err && key && (key->secret || key->invalid ||
					 key->expired || key->revoked)) {
			/* we only consider usable keys as alternatives */
			gpgme_key_unref(key);
			goto try_next_key;
		}
		else {
			if (!err && result && result->subkeys &&
			    result->subkeys->fpr && key && key->subkeys &&
			    key->subkeys->fpr &&
			    !strcmp(result->subkeys->fpr, key->subkeys->fpr)) {
				/* The fingerprint is identical.  We assume that this is
				   the same key and don't mark it as an ambiguous.  This
				   problem may occur with corrupted keyrings and has
				   been noticed often with gpgsm.  In fact gpgsm uses a
				   similar hack to sort out such duplicates but it can't
				   do that while listing keys.  */
				gpgme_key_unref(key);
				goto try_next_key;
			}
			if (!err) {
				gpgme_key_unref(key);
				err = gpgme_error(GPG_ERR_AMBIGUOUS_NAME);
			}
			gpgme_key_unref(result);
			result = NULL;
		}
	}
	if (!err)
		*r_key = result;
	gpgme_op_keylist_end(listctx);
	return err;
}


/* Returns the proper message for proposing the user a key search
 * for the given email address.
 * Check if the key already exists in the keyring and returns NULL
 * if a valid key is found
 */
static gchar* requires_online_search_for(const gchar *email_addr)
{
	gpgme_ctx_t ctx = NULL;
	gpgme_key_t r_key = NULL;
	gpgme_error_t err;
	gchar *message = NULL;
	if ((err = gpgme_new(&ctx)) != GPG_ERR_NO_ERROR) {
		debug_print("Couldn't initialize GPG context, %s\n", gpgme_strerror(err));
		privacy_set_error(_("Couldn't initialize GPG context, %s"), gpgme_strerror(err));
		return _("Couldn't initialize GPG context.");
	}
	gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
	gpgme_set_keylist_mode(ctx, GPGME_KEYLIST_MODE_LOCAL);
	err = sgpgme_get_public_key(ctx, email_addr, &r_key);
	if (r_key == NULL) {
		if(gpgme_err_code(err) != GPG_ERR_AMBIGUOUS_NAME)
			message = _("This key is not in your keyring. Do you want "
				    "Claws Mail to try to import it?");
		/* else: when multiple valid matching keys exist in
		 * 	 the keyring, the user will be able to choose
		 * 	 one when sending an email and the correct one
		 * 	 will be automatically used during signature
		 * 	 verification.
		 */
	}
	else if (r_key->expired)
		message = _("The key in your keyring has expired. Do you want "
			    "Claws Mail to try to update it?");
	else if (r_key->revoked)
		message = _("The key in your keyring has been revoked. Do you want "
			    "Claws Mail to try to import a new one?");
	if (r_key != NULL)
		gpgme_key_unref(r_key);
	gpgme_release(ctx);

	return message;
}

static gboolean
save_key_in_default_keyring(gpgme_ctx_t from, gpgme_key_t r_key)
{
	gpgme_error_t err;
	gpgme_ctx_t ctx = NULL;
	gpgme_data_t key_data;
	gpgme_key_t ekey[2] = {NULL,NULL};
	gboolean result;

	if (gpgme_data_new(&key_data) != GPG_ERR_NO_ERROR)
		goto SaveFailed0;
	ekey[0] = r_key;
	if ((err = gpgme_op_export_keys(from, ekey, 0, key_data)) != GPG_ERR_NO_ERROR)
		goto SaveFailed1;
	gpgme_data_seek(key_data, 0, SEEK_SET);
	if ((err = gpgme_new(&ctx)) != GPG_ERR_NO_ERROR)
		goto SaveFailed1;
	if ((err = gpgme_op_import(ctx, key_data)) != GPG_ERR_NO_ERROR)
		goto SaveFailed2;

	gpgme_import_result_t import = gpgme_op_import_result(ctx);
	result = import->imported > 0;

	gpgme_release(ctx);
	gpgme_data_release(key_data);
	return result;

SaveFailed2:
	gpgme_release(ctx);
SaveFailed1:
	gpgme_data_release(key_data);
SaveFailed0:
	return FALSE;
}

static char *
sgpgme_make_tmp_gpghome(void){
	gchar* home;
	GError *mkderr = NULL;
	GFile *src;
	GFile *dest;
	home = g_dir_make_tmp ("claws-gpg-home-XXXXXX", &mkderr);
	if (mkderr != NULL) {
		alertpanel_notice(_("Cannot create a temporary home for GPG: %s"),
				  mkderr->message);
		g_error_free (mkderr);
		return NULL;
	}
	const char *originalHome = gpgme_get_dirinfo("homedir");
	src = g_file_new_build_filename(originalHome, "gpg.conf", NULL);
	dest = g_file_new_build_filename(home, "gpg.conf", NULL);

	if (!g_file_copy (src, dest, G_FILE_COPY_NONE, NULL, NULL, NULL, &mkderr)) {
		alertpanel_notice(_("Cannot copy gpg.conf into temporary home %s: %s"),
				  home, mkderr->message);
		g_error_free (mkderr);
		g_free(home);
		home = NULL;
	}
	g_free(src);
	g_free(dest);

	return home;
}

static const char *
isotimestr (unsigned long value, char *buffer, size_t size)
{
	time_t t;
	struct tm *tp;

	if (!value)
		return "";
	t = value;

	tp = gmtime (&t);
	snprintf (buffer, size, "%04d-%02d-%02d %02d:%02d:%02d",
		1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
		tp->tm_hour, tp->tm_min, tp->tm_sec);
	return buffer;
}

static char*
key_warning_message(gpgme_key_t key) {
	if (key->invalid)
		return _("The key is invalid.");
	if (key->revoked)
		return _("Revoked");
	if (key->expired)
		return _("Expired");
	if (key->disabled)
		return _("The key has been disabled.");
	return "Unknown issue";
}

static GtkWidget *
gpgkey_property_view(gpgme_key_t key){
	enum
	{
		COL_NAME = 0,
		COL_VALUE,
		NUM_COLS
	};
	static char buffer[72];
	gboolean dangerous_key = key->expired || key->revoked || key->disabled || key->invalid;
	GtkWidget *view = gtk_tree_view_new ();

	GtkCellRenderer *renderer;

	GtkListStore *store = gtk_list_store_new (NUM_COLS,
						G_TYPE_STRING,
						G_TYPE_STRING);
	GtkTreeIter iter;
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
		COL_NAME, _("ID"),
		COL_VALUE, key->subkeys->keyid,
		-1);
	if (dangerous_key) {
		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter,
			COL_NAME, "",
			COL_VALUE, key_warning_message(key),
			-1);
	}
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
		COL_NAME, _("Primary Name"),
		COL_VALUE, key->uids->name,
		-1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
		COL_NAME, _("Primary Email"),
		COL_VALUE, key->uids->email,
		-1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
		COL_NAME, _("Created"),
		COL_VALUE, key->subkeys->timestamp == ((unsigned long)-1)
			? _("Invalid")
			: isotimestr(key->subkeys->timestamp, buffer, sizeof(buffer)),
		-1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
		COL_NAME, key->expired
			? _("Expired on")
			: _("Expires"),
		COL_VALUE, key->subkeys->expires
			? isotimestr(key->subkeys->expires, buffer, sizeof(buffer))
			: _("Never"),
		-1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
		COL_NAME, "Fingerprint",
		COL_VALUE, key->fpr,
		-1);

	GtkTreeModel * model = GTK_TREE_MODEL (store);

	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (view),
		-1,
		"Property",
		renderer,
		"text", COL_NAME,
		NULL);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (view),
		-1,
		"Value",
		renderer,
		"text", COL_VALUE,
		NULL);

	gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(view), FALSE);

	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	g_object_unref(model);
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(GTK_TREE_VIEW(view)),
		GTK_SELECTION_NONE);

	return view;
}

enum AmbiguousKeySelectorColumns
{
	SEL_ID = 0,
	SEL_PRIMARY_NAME,
	SEL_PRIMARY_EMAIL,
	SEL_CREATED,
	SEL_EXPIRES,
	SEL_FINGERPRINT,
	NUM_COLS
};

static gboolean
_ambiguous_key_selection_func (GtkTreeSelection *selection,
				GtkTreeModel     *model,
				GtkTreePath      *path,
				gboolean          path_currently_selected,
				gpointer          userdata)
{
	char *fpr;
	GtkTreeIter iter;
	char* selected_key = userdata;

	if (gtk_tree_model_get_iter(model, &iter, path)) {
		gtk_tree_model_get(model, &iter, SEL_FINGERPRINT, &fpr, -1);

		if (!path_currently_selected) {
			// was not selected, thus it's selected now.
			strncpy(selected_key, fpr, PGP_FINGERPRINT_MAX_LENGTH+1);
		} else if (strncmp(fpr, selected_key, PGP_FINGERPRINT_MAX_LENGTH+1) == 0) {
			// was unselected, clean up
			memset(selected_key, '\0', PGP_FINGERPRINT_MAX_LENGTH+1); 
		}

		g_free(fpr);
	}
	return TRUE;
}
static GtkWidget *
ambiguous_key_selection(
	gpgme_ctx_t listctx,
	const char* email_addr,
	char* selected_key)
{
	gpgme_error_t err;
	gpgme_key_t key = NULL;
	gboolean dangerous_key = FALSE;
	static char tbuffer[72];
	static char ebuffer[72];
	GtkWidget *view = gtk_tree_view_new ();

	GtkCellRenderer *renderer;

	GtkListStore *store = gtk_list_store_new (NUM_COLS,
						G_TYPE_STRING,
						G_TYPE_STRING,
						G_TYPE_STRING,
						G_TYPE_STRING,
						G_TYPE_STRING,
						G_TYPE_STRING);
	GtkTreeIter iter;

	err = gpgme_op_keylist_start(listctx, email_addr, 0);
	while (!err && !(err = gpgme_op_keylist_next(listctx, &key))) {
		dangerous_key = key->expired || key->revoked || key->disabled || key->invalid;
		if (!dangerous_key) {
			gtk_list_store_append (store, &iter);
			gtk_list_store_set (store, &iter,
				SEL_ID, key->subkeys->keyid,
				SEL_PRIMARY_NAME, key->uids->name,
				SEL_PRIMARY_EMAIL, key->uids->email,
				SEL_CREATED, key->subkeys->timestamp != -1
					? isotimestr(key->subkeys->timestamp, tbuffer, sizeof(tbuffer))
					: _("Invalid Value"),
				SEL_EXPIRES, key->subkeys->expires
					? isotimestr(key->subkeys->expires, ebuffer, sizeof(ebuffer))
					: _("Never"),
				SEL_FINGERPRINT, key->fpr,
				-1);
		}
		gpgme_key_unref(key);
	}
	gpgme_op_keylist_end(listctx);

	GtkTreeModel * model = GTK_TREE_MODEL(store);

	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW (view),
		-1,
		"ID",
		renderer,
		"text", SEL_ID,
		NULL);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW (view),
		-1,
		_("Owner"),
		renderer,
		"text", SEL_PRIMARY_NAME,
		NULL);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW (view),
		-1,
		_("Email"),
		renderer,
		"text", SEL_PRIMARY_EMAIL,
		NULL);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW (view),
		-1,
		_("Created"),
		renderer,
		"text", SEL_CREATED,
		NULL);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW (view),
		-1,
		_("Expires"),
		renderer,
		"text", SEL_EXPIRES,
		NULL);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW (view),
		-1,
		_("Fingerprint"),
		renderer,
		"text", SEL_FINGERPRINT,
		NULL);

	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	g_object_unref(model);
	GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(view));

	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(GTK_TREE_VIEW(view)),
		GTK_SELECTION_SINGLE);
	gtk_tree_selection_set_select_function(selection, _ambiguous_key_selection_func, selected_key, NULL);
	return view;
}

static gboolean
import_desired_key(gpgme_ctx_t ctx, const char* email_addr)
{
	gpgme_error_t err;
	gboolean res = FALSE;
	gpgme_key_t r_key = NULL;
	AlertValue val = G_ALERTDEFAULT;
	char selected_key[PGP_FINGERPRINT_MAX_LENGTH+1];
	char *buf = g_strdup_printf(
			_("More than one public key for <b>%s</b> were found.\nSelect the key you want to add to your keyring.\n"),
			email_addr
			);

	memset(selected_key, 0, PGP_FINGERPRINT_MAX_LENGTH+1);
	GtkWidget * selector = ambiguous_key_selection(ctx, email_addr, selected_key);

	val = alertpanel_full(_("Notice"), buf,
			NULL, _("_Add to keyring"),
			NULL, _("_Cancel"),
			NULL, NULL,
			ALERTFOCUS_FIRST,
			FALSE,
			selector,
			ALERT_QUESTION);
	g_free(buf);

	if (val == G_ALERTDEFAULT && selected_key[0]){
		gpgme_set_keylist_mode(ctx, GPGME_KEYLIST_MODE_LOCAL);
		gpgme_set_ctx_flag(ctx, "auto-key-locate","clear,nodefault");
		err = sgpgme_get_public_key(ctx, selected_key, &r_key);
		if (err) {
			debug_print("Couldn't load key %s: %s\n", selected_key, gpgme_strerror(err));
			privacy_set_error(_("Couldn't load key %s: %s"), selected_key, gpgme_strerror(err));
			return FALSE;
		}
		GtkWidget * properties = gpgkey_property_view(r_key);
		val = alertpanel_full(
			_("Are you sure?"),
			_("Add the following public key to your keyring?"),
			NULL, _("_Add to keyring"),
			NULL, _("_Cancel"),
			NULL, NULL,
			ALERTFOCUS_FIRST,
			FALSE,
			properties,
			ALERT_QUESTION
			);
		if (val == G_ALERTDEFAULT)
			res = save_key_in_default_keyring(ctx, r_key);
		else
			res = FALSE;
		gpgme_key_unref(r_key);
	}

	return res;
}

gboolean sgpgme_propose_pgp_key_search(const gchar *email_addr)
{
	AlertValue val = G_ALERTDEFAULT;
	gpgme_ctx_t ctx = NULL;
	gpgme_key_t r_key = NULL;
	gpgme_error_t err;
	gboolean res = TRUE;
	gchar *buf = NULL;
	gchar* home;
	gchar *message = requires_online_search_for(email_addr);

	if (message == NULL) {
		// a NULL message means that at least one valid key
		// is already present in the keyring
		alertpanel_notice(_("The public key for %s is already "
				    "in your keyring."), email_addr);
		return TRUE;
	}

	val = alertpanel(_("Key import"),
			 message, NULL,
			 _("_No"), NULL, _("from keyserver"), NULL,
			 _("from Web Key Directory"), ALERTFOCUS_SECOND);
	GTK_EVENTS_FLUSH();
	if (val == G_ALERTDEFAULT)
		return FALSE;
	if (val != G_ALERTALTERNATE && val != G_ALERTOTHER)
		return FALSE;
	if ((home = sgpgme_make_tmp_gpghome()) == NULL)
		return FALSE;

	if ((err = gpgme_new(&ctx)) != GPG_ERR_NO_ERROR) {
		debug_print("Couldn't initialize GPG context, %s\n", gpgme_strerror(err));
		privacy_set_error(_("Couldn't initialize GPG context, %s"), gpgme_strerror(err));
		g_free(home);
		return FALSE;
	}

	gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP, NULL, home);
	gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
	gpgme_set_keylist_mode(ctx, GPGME_KEYLIST_MODE_LOCATE);
	/* Note that we do NOT add "clear" when keyserver import is requested.
	 * That's because the gpg.conf might contain keyserver urls that
	 * the user wants queried: nodefault is enough to avoid a WKD
	 * request to be sent before the keyserver one.
	 */
	gpgme_set_ctx_flag(ctx, "auto-key-locate",
		(val == G_ALERTOTHER)? "clear,nodefault,wkd" : "nodefault,keyserver");

	err = sgpgme_get_public_key(ctx, email_addr, &r_key);
	if (r_key == NULL && val != G_ALERTOTHER && gpgme_err_code(err) == GPG_ERR_EOF) {
		// inefficient workaround to https://dev.gnupg.org/T8093
		gpgme_set_keylist_mode(ctx, GPGME_KEYLIST_MODE_LOCAL);
		gpgme_set_ctx_flag(ctx, "auto-key-locate","clear,nodefault");
		err = sgpgme_get_public_key(ctx, email_addr, &r_key);
	}
	if (err != GPG_ERR_NO_ERROR && gpgme_err_code(err) != GPG_ERR_AMBIGUOUS_NAME)
		res = FALSE;
	if (r_key == NULL && gpgme_err_code(err) != GPG_ERR_AMBIGUOUS_NAME)
		res = FALSE;

	if (res) {
		if (gpgme_err_code(err) == GPG_ERR_AMBIGUOUS_NAME) {
			res = import_desired_key(ctx, email_addr);
		} else {
			GtkWidget * properties = gpgkey_property_view(r_key);
			buf = g_strdup_printf(
					r_key->expired
					? _("An <b>expired</b> public key for <b>%s</b> was found.\nAdd it to your keyring?\n")
					: _("A public key for <b>%s</b> was found.\nAdd it to your keyring?\n"),
					email_addr
					);

			val = alertpanel_full(_("Notice"), buf,
					NULL, _("_Add to keyring"),
					NULL, _("_Cancel"),
					NULL, NULL,
					ALERTFOCUS_FIRST,
					FALSE,
					properties,
					ALERT_QUESTION);
			g_free(buf);
			if (val == G_ALERTDEFAULT)
				res = save_key_in_default_keyring(ctx, r_key);

			else
				res = FALSE;
		}
		if (res)
			alertpanel_notice(_("The public key for <b>%s</b> is now in your keyring."), email_addr);
	} else {
		if (val == G_ALERTOTHER)
			alertpanel_error(_("Cannot locate the missing key from Web Key Directory."));
		else
			alertpanel_error(_("Cannot locate the missing key from keyserver."));
	}

	gpgme_key_unref(r_key);
	gpgme_release(ctx);
	g_free(home);

	return res;
}

#endif /* USE_GPGME */
