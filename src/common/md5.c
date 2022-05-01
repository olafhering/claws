/* md5.c - MD5 Message-Digest Algorithm
 *	Copyright (C) 1995, 1996, 1998, 1999 Free Software Foundation, Inc.
 *
 * according to the definition of MD5 in RFC 1321 from April 1992.
 * NOTE: This is *not* the same file as the one from glibc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 3, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
/* Written by Ulrich Drepper <drepper@gnu.ai.mit.edu>, 1995.  */
/* heavily modified for GnuPG by <werner.koch@guug.de> */
/* modified again for Sylpheed by <wk@gnupg.org> 2001-02-11 */

/* Test values:
 * ""                  D4 1D 8C D9 8F 00 B2 04  E9 80 09 98 EC F8 42 7E
 * "a"                 0C C1 75 B9 C0 F1 B6 A8  31 C3 99 E2 69 77 26 61
 * "abc                90 01 50 98 3C D2 4F B0  D6 96 3F 7D 28 E1 7F 72
 * "message digest"    F9 6B 69 7D 7C B7 93 8D  52 5A 2F 31 AA F1 61 D0
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <glib.h>
#include <glib/gstdio.h>

#include "md5.h"

/****************
 * Rotate a 32 bit integer by n bytes
 */
#if defined(__GNUC__) && defined(__i386__)
static inline guint32 rol(guint32 x, int n)
{
 __asm__("roll %%cl,%0":"=r"(x)
 :		"0"(x), "c"(n));
	return x;
}
#else
#define rol(x,n) ( ((x) << (n)) | ((x) >> (32-(n))) )
#endif

typedef struct {
	guint32 A, B, C, D;
	guint32 nblocks;
	unsigned char buf[64];
	int count;
	int finalized;
} MD5_CONTEXT;

static void md5_init(MD5_CONTEXT *ctx)
{
	ctx->A = 0x67452301;
	ctx->B = 0xefcdab89;
	ctx->C = 0x98badcfe;
	ctx->D = 0x10325476;

	ctx->nblocks = 0;
	ctx->count = 0;
	ctx->finalized = 0;
}

/* These are the four functions used in the four steps of the MD5 algorithm
   and defined in the RFC 1321.  The first function is a little bit optimized
   (as found in Colin Plumbs public domain implementation).  */
/* #define FF(b, c, d) ((b & c) | (~b & d)) */
#define FF(b, c, d) (d ^ (b & (c ^ d)))
#define FG(b, c, d) FF (d, b, c)
#define FH(b, c, d) (b ^ c ^ d)
#define FI(b, c, d) (c ^ (b | ~d))

/****************
 * transform n*64 bytes
 */
static void transform(MD5_CONTEXT *ctx, const unsigned char *data)
{
	guint32 correct_words[16];
	guint32 A = ctx->A;
	guint32 B = ctx->B;
	guint32 C = ctx->C;
	guint32 D = ctx->D;
	guint32 *cwp = correct_words;

#ifdef BIG_ENDIAN_HOST
	{
		int i;
		unsigned char *p2;
		const unsigned char *p1;

		for (i = 0, p1 = data, p2 = (unsigned char *)correct_words; i < 16; i++, p2 += 4) {
			p2[3] = *p1++;
			p2[2] = *p1++;
			p2[1] = *p1++;
			p2[0] = *p1++;
		}
	}
#else
	memcpy(correct_words, data, 64);
#endif

#define OP(a, b, c, d, s, T)				\
	do {						\
		a += FF (b, c, d) + (*cwp++) + T; 	\
		a = rol(a, s);				\
		a += b;					\
	} while (0)

	/* Before we start, one word about the strange constants.
	   They are defined in RFC 1321 as

	   T[i] = (int) (4294967296.0 * fabs (sin (i))), i=1..64
	 */

	/* Round 1.  */
	OP(A, B, C, D, 7, 0xd76aa478);
	OP(D, A, B, C, 12, 0xe8c7b756);
	OP(C, D, A, B, 17, 0x242070db);
	OP(B, C, D, A, 22, 0xc1bdceee);
	OP(A, B, C, D, 7, 0xf57c0faf);
	OP(D, A, B, C, 12, 0x4787c62a);
	OP(C, D, A, B, 17, 0xa8304613);
	OP(B, C, D, A, 22, 0xfd469501);
	OP(A, B, C, D, 7, 0x698098d8);
	OP(D, A, B, C, 12, 0x8b44f7af);
	OP(C, D, A, B, 17, 0xffff5bb1);
	OP(B, C, D, A, 22, 0x895cd7be);
	OP(A, B, C, D, 7, 0x6b901122);
	OP(D, A, B, C, 12, 0xfd987193);
	OP(C, D, A, B, 17, 0xa679438e);
	OP(B, C, D, A, 22, 0x49b40821);

#undef OP
#define OP(f, a, b, c, d, k, s, T)  \
	do {							\
		a += f (b, c, d) + correct_words[k] + T;	\
		a = rol(a, s);					\
		a += b; 					\
	} while (0)

	/* Round 2.  */
	OP(FG, A, B, C, D, 1, 5, 0xf61e2562);
	OP(FG, D, A, B, C, 6, 9, 0xc040b340);
	OP(FG, C, D, A, B, 11, 14, 0x265e5a51);
	OP(FG, B, C, D, A, 0, 20, 0xe9b6c7aa);
	OP(FG, A, B, C, D, 5, 5, 0xd62f105d);
	OP(FG, D, A, B, C, 10, 9, 0x02441453);
	OP(FG, C, D, A, B, 15, 14, 0xd8a1e681);
	OP(FG, B, C, D, A, 4, 20, 0xe7d3fbc8);
	OP(FG, A, B, C, D, 9, 5, 0x21e1cde6);
	OP(FG, D, A, B, C, 14, 9, 0xc33707d6);
	OP(FG, C, D, A, B, 3, 14, 0xf4d50d87);
	OP(FG, B, C, D, A, 8, 20, 0x455a14ed);
	OP(FG, A, B, C, D, 13, 5, 0xa9e3e905);
	OP(FG, D, A, B, C, 2, 9, 0xfcefa3f8);
	OP(FG, C, D, A, B, 7, 14, 0x676f02d9);
	OP(FG, B, C, D, A, 12, 20, 0x8d2a4c8a);

	/* Round 3.  */
	OP(FH, A, B, C, D, 5, 4, 0xfffa3942);
	OP(FH, D, A, B, C, 8, 11, 0x8771f681);
	OP(FH, C, D, A, B, 11, 16, 0x6d9d6122);
	OP(FH, B, C, D, A, 14, 23, 0xfde5380c);
	OP(FH, A, B, C, D, 1, 4, 0xa4beea44);
	OP(FH, D, A, B, C, 4, 11, 0x4bdecfa9);
	OP(FH, C, D, A, B, 7, 16, 0xf6bb4b60);
	OP(FH, B, C, D, A, 10, 23, 0xbebfbc70);
	OP(FH, A, B, C, D, 13, 4, 0x289b7ec6);
	OP(FH, D, A, B, C, 0, 11, 0xeaa127fa);
	OP(FH, C, D, A, B, 3, 16, 0xd4ef3085);
	OP(FH, B, C, D, A, 6, 23, 0x04881d05);
	OP(FH, A, B, C, D, 9, 4, 0xd9d4d039);
	OP(FH, D, A, B, C, 12, 11, 0xe6db99e5);
	OP(FH, C, D, A, B, 15, 16, 0x1fa27cf8);
	OP(FH, B, C, D, A, 2, 23, 0xc4ac5665);

	/* Round 4.  */
	OP(FI, A, B, C, D, 0, 6, 0xf4292244);
	OP(FI, D, A, B, C, 7, 10, 0x432aff97);
	OP(FI, C, D, A, B, 14, 15, 0xab9423a7);
	OP(FI, B, C, D, A, 5, 21, 0xfc93a039);
	OP(FI, A, B, C, D, 12, 6, 0x655b59c3);
	OP(FI, D, A, B, C, 3, 10, 0x8f0ccc92);
	OP(FI, C, D, A, B, 10, 15, 0xffeff47d);
	OP(FI, B, C, D, A, 1, 21, 0x85845dd1);
	OP(FI, A, B, C, D, 8, 6, 0x6fa87e4f);
	OP(FI, D, A, B, C, 15, 10, 0xfe2ce6e0);
	OP(FI, C, D, A, B, 6, 15, 0xa3014314);
	OP(FI, B, C, D, A, 13, 21, 0x4e0811a1);
	OP(FI, A, B, C, D, 4, 6, 0xf7537e82);
	OP(FI, D, A, B, C, 11, 10, 0xbd3af235);
	OP(FI, C, D, A, B, 2, 15, 0x2ad7d2bb);
	OP(FI, B, C, D, A, 9, 21, 0xeb86d391);

	/* Put checksum in context given as argument.  */
	ctx->A += A;
	ctx->B += B;
	ctx->C += C;
	ctx->D += D;
}

/* The routine updates the message-digest context to
 * account for the presence of each of the characters inBuf[0..inLen-1]
 * in the message whose digest is being computed.
 */
static void md5_update(MD5_CONTEXT *hd, const unsigned char *inbuf, size_t inlen)
{
	if (hd->count == 64) { /* flush the buffer */
		transform(hd, hd->buf);
		hd->count = 0;
		hd->nblocks++;
	}
	if (!inbuf)
		return;
	if (hd->count) {
		for (; inlen && hd->count < 64; inlen--)
			hd->buf[hd->count++] = *inbuf++;
		md5_update(hd, NULL, 0);
		if (!inlen)
			return;
	}

	while (inlen >= 64) {
		transform(hd, inbuf);
		hd->count = 0;
		hd->nblocks++;
		inlen -= 64;
		inbuf += 64;
	}

	for (; inlen && hd->count < 64; inlen--)
		hd->buf[hd->count++] = *inbuf++;
}

/* The routine final terminates the message-digest computation and
 * ends with the desired message digest in mdContext->digest[0...15].
 * The handle is prepared for a new MD5 cycle.
 * Returns 16 bytes representing the digest.
 */

static void do_final(MD5_CONTEXT *hd)
{
	guint32 t, msb, lsb;
	unsigned char *p;

	md5_update(hd, NULL, 0); /* flush */

	msb = 0;
	t = hd->nblocks;
	if ((lsb = t << 6) < t)	/* multiply by 64 to make a byte count */
		msb++;
	msb += t >> 26;
	t = lsb;
	if ((lsb = t + hd->count) < t) /* add the count */
		msb++;
	t = lsb;
	if ((lsb = t << 3) < t)	/* multiply by 8 to make a bit count */
		msb++;
	msb += t >> 29;

	if (hd->count < 56) { /* enough room */
		hd->buf[hd->count++] = 0x80; /* pad */
		while (hd->count < 56)
			hd->buf[hd->count++] = 0; /* pad */
	} else { /* need one extra block */
		hd->buf[hd->count++] = 0x80; /* pad character */
		while (hd->count < 64)
			hd->buf[hd->count++] = 0;
		md5_update(hd, NULL, 0); /* flush */
		memset(hd->buf, 0, 56);	/* fill next block with zeroes */
	}

	/* append the 64 bit count */
	hd->buf[56] = lsb;
	hd->buf[57] = lsb >> 8;
	hd->buf[58] = lsb >> 16;
	hd->buf[59] = lsb >> 24;
	hd->buf[60] = msb;
	hd->buf[61] = msb >> 8;
	hd->buf[62] = msb >> 16;
	hd->buf[63] = msb >> 24;
	transform(hd, hd->buf);

	p = hd->buf;
#ifdef BIG_ENDIAN_HOST
#define X(a) do { *p++ = hd->a      ; *p++ = hd->a >> 8;      \
		  *p++ = hd->a >> 16; *p++ = hd->a >> 24; } while(0)
#else /* little endian */
	/*#define X(a) do { *(guint32*)p = hd->##a ; p += 4; } while(0) */
	/* Unixware's cpp doesn't like the above construct so we do it his way:
	 * (reported by Allan Clark) */
#define X(a) do { *(guint32*)p = (*hd).a ; p += 4; } while(0)
#endif
	X(A);
	X(B);
	X(C);
	X(D);
#undef X
	hd->finalized = 1;
}

static void md5_final(unsigned char *digest, MD5_CONTEXT *ctx)
{
	if (!ctx->finalized)
		do_final(ctx);
	memcpy(digest, ctx->buf, 16);
}

/*
 * Creates a MD5 digest in hex fomrat (lowercase letters) from the
 * string S.  hextdigest but be buffer of at lease 33 bytes!
 */
static void md5_hex_digest_binary(char *hexdigest, const unsigned char *s, size_t len)
{
	int i;
	MD5_CONTEXT context;
	unsigned char digest[16];

	md5_init(&context);
	md5_update(&context, s, len);
	md5_final(digest, &context);

	for (i = 0; i < 16; i++)
		sprintf(hexdigest + 2 * i, "%02x", digest[i]);
}

int md5_hex_digest_file(char *hexdigest, const unsigned char *file)
{
	int READ_BLOCK_SIZE = 4096;
	int len;
	char *buf = malloc(READ_BLOCK_SIZE); /* alloc the first block */
	char *lastp = buf; /* point to the start of the buffer */
	size_t total = 0; /* total length read */
	int num_alloc = 1; /* number of blocks allocated */
	int fd = g_open(file, O_RDONLY, 0);

	if (fd == -1) {
		FILE_OP_ERROR(file, "open");
		free(buf);
		return -1;
	}

	while ((len = read(fd, lastp, READ_BLOCK_SIZE)) > 0) { /* read one block (which is allocated) */
		total += len; /* update the total length */
		num_alloc++; /* increase number of allocs */
		buf = realloc(buf, READ_BLOCK_SIZE * num_alloc); /* allocate one more block for next read */
		lastp = buf + total; /* point to the end of read stuff to buf */
	}

	close(fd);
	md5_hex_digest_binary(hexdigest, buf, total);
	free(buf);
	// printf("%s  %s\n", hexdigest, file);
	return 0;
}

/*
 * Creates a MD5 digest in hex fomrat (lowercase letters) from the
 * string S.  hextdigest but be buffer of at lease 33 bytes!
 */
void md5_hex_digest(char *hexdigest, const unsigned char *s)
{
	g_return_if_fail(hexdigest != NULL);
	g_return_if_fail(s != NULL);
	md5_hex_digest_binary(hexdigest, s, strlen(s));
}

/*
** Function: md5_hmac
** taken from the file rfc2104.txt
** written by Martin Schaaf <mascha@ma-scha.de>
*/
static void md5_hmac(unsigned char *digest, const unsigned char *text, int text_len, const unsigned char *key, int key_len)
{
	MD5_CONTEXT context;
	unsigned char k_ipad[64]; /* inner padding -
				   * key XORd with ipad
				   */
	unsigned char k_opad[64]; /* outer padding -
				   * key XORd with opad
				   */
	/* unsigned char tk[16]; */
	int i;

	/* start out by storing key in pads */
	memset(k_ipad, 0, sizeof k_ipad);
	memset(k_opad, 0, sizeof k_opad);
	if (key_len > 64) {
		/* if key is longer than 64 bytes reset it to key=MD5(key) */
		MD5_CONTEXT tctx;

		md5_init(&tctx);
		md5_update(&tctx, key, key_len);
		md5_final(k_ipad, &tctx);
		md5_final(k_opad, &tctx);
	} else {
		memcpy(k_ipad, key, key_len);
		memcpy(k_opad, key, key_len);
	}

	/*
	 * the HMAC_MD5 transform looks like:
	 *
	 * MD5(K XOR opad, MD5(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected
	 */

	/* XOR key with ipad and opad values */
	for (i = 0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/*
	 * perform inner MD5
	 */
	md5_init(&context); /* init context for 1st
			     * pass */
	md5_update(&context, k_ipad, 64); /* start with inner pad */
	md5_update(&context, text, text_len); /* then text of datagram */
	md5_final(digest, &context); /* finish up 1st pass */
	/*
	 * perform outer MD5
	 */
	md5_init(&context); /* init context for 2nd
			     * pass */
	md5_update(&context, k_opad, 64); /* start with outer pad */
	md5_update(&context, digest, 16); /* then results of 1st
					   * hash */
	md5_final(digest, &context); /* finish up 2nd pass */
}

void md5_hex_hmac(char *hexdigest, const unsigned char *text, int text_len, const unsigned char *key, int key_len)
{
	unsigned char digest[16];
	int i;

	g_return_if_fail(key != NULL);
	g_return_if_fail(key_len >= 0);
	g_return_if_fail(text != NULL);
	g_return_if_fail(text_len >= 0);
	g_return_if_fail(hexdigest != NULL);

	md5_hmac(digest, text, text_len, key, key_len);
	for (i = 0; i < 16; i++)
		sprintf(hexdigest + 2 * i, "%02x", digest[i]);
}
/*
 * vim: noet ts=4 shiftwidth=4 nowrap
 */
