/*
 * Claws Mail -- a GTK based, lightweight, and fast e-mail client
 * Copyright (C) 1999-2026 the Claws Mail team and Hiroyuki Yamamoto
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
#include <string.h>
#include <ctype.h>

#include "utils.h"
#include "codeconv.h"
#include "quoted-printable.h"

#define ENCODED_WORD_SEPARATOR	'?'
#define ENCODED_WORD_BEGIN	"=?"
#define ENCODED_WORD_END	"?="

/* Decodes headers based on RFC2045 and RFC2047. */

#define THIS_SELECTOR(x) (x)
#define OTHER_SELECTOR(x) ((x) == 0 ? 1 : 0)
#define TOGGLE_SELECTOR(x) do { (x) = OTHER_SELECTOR(x); } while(0)

#define MAX_CHARSET_LENGTH 32

static inline
void unconv_helper (const gchar *instr, gsize len, gchar *charset, GString *dest)
{
	gchar *conv_str = NULL;

	/* convert to UTF-8 */
	conv_str = conv_codeset_strdup(instr, charset, NULL);
	if (!conv_str || !g_utf8_validate(conv_str, -1, NULL)) {
		g_message("error conving to utf8: '%s' -> copying displaysafe",conv_str);
		if (conv_str != NULL)
			g_free(conv_str);
		conv_str = g_malloc(len + 1);
		conv_utf8todisp(conv_str, len + 1, instr);
	}
	g_string_append(dest, conv_str);
	g_free(conv_str);
	conv_str = NULL;
}

gchar *unmime_header(const gchar *encoded_str, gboolean addr_field)
{
	const gchar *p = encoded_str;
	const gchar *eword_begin_p, *encoding_begin_p, *text_begin_p,
		    *eword_end_p = NULL; /* init indicator for previous encoded-word */

	/* TODO do we want to alloca() these? */
	gchar csetA[MAX_CHARSET_LENGTH+1] = {0,};
	gchar csetB[MAX_CHARSET_LENGTH+1] = {0,};
	gchar *charset[2] = { csetA, csetB };
	gchar encoding[2] = { 0, };
	int selector = 0;

	gchar *decoded_part = NULL;
	gsize part_len = 0;

	GString *outbuf;

	cm_return_val_if_fail(encoded_str != NULL, NULL);

	outbuf = g_string_sized_new(strlen(encoded_str) * 2);
	do {
		gint cs_len;
		const gchar *qstart_p, *crlf_p;
		gboolean non_ascii_warned = FALSE;
		gboolean bad_quote_warned = FALSE;
		gboolean continued_encoding = FALSE;

		if  (*p == '\0')
			goto finish_loop;

		eword_begin_p = strstr(p, ENCODED_WORD_BEGIN);
		if (!eword_begin_p)
			goto finish_loop;

		/* literally copy complete RFC822 quoted-strings before decoding */
		qstart_p = strchr(p, '"');
		if (qstart_p != NULL && qstart_p < eword_begin_p) {
			const gchar *qend_p = qstart_p + 1;
			while (qend_p[0] != '\0') {
				if (!isascii(qend_p[0])) {
					goto no_ascii_char; /* non-conforming RFC2047 */
				} else if ( qend_p[0] == '"' ) {
					goto break_loop;
				} else if ( qend_p[0] == '\r' ) { /* non-conforming RFC2047 */
					if (bad_quote_warned == FALSE) {
						bad_quote_warned = TRUE;
						g_message("Malformed RFC822 quoted-string: '%s'"
							"(CR within quotation marks)."
							"Continuing with next character, though.",
							encoded_str);
					}
					qend_p ++;
					if ( qend_p[1] == '\n' ) {
						qend_p ++;
					}
					goto break_loop;
				} else if (qend_p[0] == '\\' ) {
					if (isascii(qend_p[1])) {
						qend_p ++;
						goto cont_loop;
					} else { /* non-conforming RFC2047 */
						goto no_ascii_char;
					}
				} else 
					goto cont_loop;

				no_ascii_char: {
					if (non_ascii_warned == FALSE) {
						non_ascii_warned = TRUE;
						g_message("Malformed RFC822 quoted-string: '%s'"
							"(non-ASCII character)."
							"Continuing with next character, though.",
							encoded_str);
					}

				} /* fallthrough */
				break_loop:
					break;
				cont_loop:
					qend_p ++;
					continue;
			}
			if (qend_p[0] == '\0')
				goto finish_loop;
			else { /* copy from current p to quote end, start over */
				g_message("%s\n%s", p, qend_p);
				qend_p ++;
				g_string_append_len(outbuf, p, qend_p - p);
				p = qend_p;
				continue;
			}
		}

		/* Skip RFC822 linear-white-space between encoded-words */
		if (eword_end_p != NULL && p == eword_end_p + 2) {
			const gchar *wspend = p;
			while ( wspend[0] == ' ' || wspend[0] ==  '\t') {
				wspend ++;
			}
			if (wspend != eword_begin_p &&
				p[0] == '\r' && p[1] == '\n' &&
				(p[2] == ' ' || p[2] == '\t')) {
				wspend = p + 3;
				while ( wspend[0] == ' ' || wspend[0] ==  '\t') {
					wspend ++;
				}
			}
			if ( wspend == eword_begin_p ) {
				p = wspend;
				continued_encoding = TRUE;
				TOGGLE_SELECTOR(selector);
			}
		}

		/* Ensure we deal with a complete encoded word within line */
		crlf_p = strstr(eword_begin_p, "\r\n");
		encoding_begin_p = strchr(eword_begin_p + 2, ENCODED_WORD_SEPARATOR);
		if (!encoding_begin_p || (crlf_p != NULL && encoding_begin_p > crlf_p))
			goto next_line_or_finish;
		text_begin_p = strchr(encoding_begin_p + 1, ENCODED_WORD_SEPARATOR);
		if (!text_begin_p || (crlf_p != NULL && encoding_begin_p > crlf_p))
			goto next_line_or_finish;
		eword_end_p = strstr(text_begin_p + 1, ENCODED_WORD_END);
		if (!eword_end_p || (crlf_p != NULL && encoding_begin_p > crlf_p))
			goto next_line_or_finish;

		/* decode the encoded word, appended to previous one, if present */
		cs_len = MIN(MAX_CHARSET_LENGTH, encoding_begin_p - (eword_begin_p + 2));
		strncpy(&charset[THIS_SELECTOR(selector)][0], eword_begin_p + 2, cs_len);
		charset[THIS_SELECTOR(selector)][cs_len] = '\0';
		encoding[THIS_SELECTOR(selector)] = g_ascii_toupper(*(encoding_begin_p + 1));

		if (decoded_part /* decode previous word, if required */
			&& (!continued_encoding
				|| (strncmp (charset[THIS_SELECTOR(selector)],
					charset[OTHER_SELECTOR(selector)],
					MAX_CHARSET_LENGTH) != 0)
				|| (encoding[THIS_SELECTOR(selector)] !=
					encoding[OTHER_SELECTOR(selector)]) )) {
			char* cs = g_strdup(charset[OTHER_SELECTOR(selector)]);
			if (strlen(cs) == 0) {
				g_free(cs);
				cs = g_strdup(charset[THIS_SELECTOR(selector)]);
			}
			unconv_helper(decoded_part, part_len, cs, outbuf);
			g_free(decoded_part);
			g_free(cs);
			decoded_part = NULL;
			part_len = 0;
		}

		/* copy text until encoding */
		if (p < eword_begin_p) {
					g_string_append_len(outbuf, p, eword_begin_p - p);
					p = eword_begin_p;
				}

		if (encoding[THIS_SELECTOR(selector)] == 'B') {
			gchar *tmp;
			gchar *decoded_text;
			gsize line_len;
			tmp = g_strndup(text_begin_p + 1, eword_end_p - (text_begin_p + 1) + 1);
			decoded_text = g_base64_decode(tmp, &line_len);
			decoded_part = realloc(decoded_part, part_len + line_len + 1);
			strncpy(decoded_part + part_len, decoded_text, line_len);
			part_len += line_len;
			decoded_part[part_len]='\0';

			g_free(decoded_text);
			g_free(tmp);
		} else if (encoding[THIS_SELECTOR(selector)] == 'Q') {
			gchar *decoded_text;
			gsize line_len;
			decoded_text = g_malloc
				(eword_end_p - (text_begin_p + 1) + 1);
			line_len = qp_decode_q_encoding
				(decoded_text, text_begin_p + 1,
				eword_end_p - (text_begin_p + 1));
			decoded_part = realloc(decoded_part, part_len + line_len + 1);
			strncpy(decoded_part + part_len, decoded_text, line_len);
			part_len += line_len;
			decoded_part[part_len]='\0';

			g_free(decoded_text);
		} else { /* Unknown encoding, copy literally */
			decoded_part = realloc(decoded_part,
					part_len + eword_end_p + 2 - p + 1);
			strncpy(decoded_part + part_len, p, eword_end_p + 2 - p);
		}
#if 0
		/* An encoded word MUST not appear within a quoted string,
		 * so quoting that word after decoding should be safe.
		 * We check there are no quotes just to be sure. If there
		 * are, well, the comma won't pose a problem, probably.
		 */
		if (addr_field && strchr(decoded_text, ',') && !in_quote &&
		    !strchr(decoded_text, '"')) {
			gchar *tmp = g_strdup_printf("\"%s\"", decoded_text);
			g_free(decoded_text);
			decoded_text = tmp;
		}
#endif
		p = eword_end_p + 2;
		goto continue_loop;

	next_line_or_finish:
		if (crlf_p != NULL ) {
			g_string_append_len(outbuf, p, crlf_p - p);
			p = crlf_p + 2;
			goto continue_loop;
		} else { /* fallthrough */ }
	finish_loop:
		if ( decoded_part != NULL ) {
			char* cs = g_strdup(charset[OTHER_SELECTOR(selector)]);
			if (strlen(cs) == 0) {
				g_free(cs);
				cs = g_strdup(charset[THIS_SELECTOR(selector)]);
			}
			unconv_helper(decoded_part, part_len, cs, outbuf);
			g_free(decoded_part);
			g_free(cs);
			decoded_part = NULL;
			part_len = 0;
		}
		g_string_append(outbuf, p);
		break;
	continue_loop:
		continue;
	} while (TRUE);
	
	gsize outlen = outbuf->len;
	gchar *rv = g_string_free_and_steal(outbuf);
	rv[outlen] = '\0';

	return rv;
}
