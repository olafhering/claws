/*
 * Sylpheed -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 1999,2000 Hiroyuki Yamamoto
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

#include "config.h"

#include <ctype.h>

#define UUDECODE(c) (c=='`' ? 0 : c - ' ')
#define N64(i) (i & ~63)

const char uudigit[64] = {
	'`', '!', '"', '#', '$', '%', '&', '\'',
	'(', ')', '*', '+', ',', '-', '.', '/',
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', ':', ';', '<', '=', '>', '?',
	'@', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
	'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
	'X', 'Y', 'Z', '[', '\\', ']', '^', '_'
};

int fromuutobits(char *out, const char *in)
{
	int len, outlen, inlen;
	register unsigned char digit1, digit2;

	outlen = UUDECODE(in[0]);
	in += 1;
	if (outlen < 0 || outlen > 45)
		return -2;
	if (outlen == 0)
		return 0;
	inlen = (outlen * 4 + 2) / 3;
	len = 0;

	for (; inlen > 0; inlen -= 4) {
		digit1 = UUDECODE(in[0]);
		if (N64(digit1))
			return -1;
		digit2 = UUDECODE(in[1]);
		if (N64(digit2))
			return -1;
		out[len++] = (digit1 << 2) | (digit2 >> 4);
		if (inlen > 2) {
			digit1 = UUDECODE(in[2]);
			if (N64(digit1))
				return -1;
			out[len++] = (digit2 << 4) | (digit1 >> 2);
			if (inlen > 3) {
				digit2 = UUDECODE(in[3]);
				if (N64(digit2))
					return -1;
				out[len++] = (digit1 << 6) | digit2;
			}
		}
		in += 4;
	}

	return len == outlen ? len : -3;
}
/*
 * vim: noet ts=4 shiftwidth=4 nowrap
 */
