/*
 * libEtPan! -- a mail stuff library
 *
 * Copyright (C) 2001, 2002 - DINH Viet Hoa
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the libEtPan! project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * $Id $
 */

#include "config.h"

#include "maillock.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#include "utils.h"

/* ********************************************************************** */

/* lock primitives */

/* the lock code is modified from the dot lock file code from mail.local.c */

/*
			     SENDMAIL LICENSE

The following license terms and conditions apply, unless a different
license is obtained from Sendmail, Inc., 6425 Christie Ave, Fourth Floor,
Emeryville, CA 94608, or by electronic mail at license@sendmail.com.

License Terms:

Use, Modification and Redistribution (including distribution of any
modified or derived work) in source and binary forms is permitted only if
each of the following conditions is met:

1. Redistributions qualify as "freeware" or "Open Source Software" under
   one of the following terms:

   (a) Redistributions are made at no charge beyond the reasonable cost of
       materials and delivery.

   (b) Redistributions are accompanied by a copy of the Source Code or by an
       irrevocable offer to provide a copy of the Source Code for up to three
       years at the cost of materials and delivery.  Such redistributions
       must allow further use, modification, and redistribution of the Source
       Code under substantially the same terms as this license.  For the
       purposes of redistribution "Source Code" means the complete compilable
       and linkable source code of sendmail including all modifications.

2. Redistributions of source code must retain the copyright notices as they
   appear in each source code file, these license terms, and the
   disclaimer/limitation of liability set forth as paragraph 6 below.

3. Redistributions in binary form must reproduce the Copyright Notice,
   these license terms, and the disclaimer/limitation of liability set
   forth as paragraph 6 below, in the documentation and/or other materials
   provided with the distribution.  For the purposes of binary distribution
   the "Copyright Notice" refers to the following language:
   "Copyright (c) 1998-2002 Sendmail, Inc.  All rights reserved."

4. Neither the name of Sendmail, Inc. nor the University of California nor
   the names of their contributors may be used to endorse or promote
   products derived from this software without specific prior written
   permission.  The name "sendmail" is a trademark of Sendmail, Inc.

5. All redistributions must comply with the conditions imposed by the
   University of California on certain embedded code, whose copyright
   notice and conditions for redistribution are as follows:

   (a) Copyright (c) 1988, 1993 The Regents of the University of
       California.  All rights reserved.

   (b) Redistribution and use in source and binary forms, with or without
       modification, are permitted provided that the following conditions
       are met:

      (i)   Redistributions of source code must retain the above copyright
            notice, this list of conditions and the following disclaimer.

      (ii)  Redistributions in binary form must reproduce the above
            copyright notice, this list of conditions and the following
            disclaimer in the documentation and/or other materials provided
            with the distribution.

      (iii) Neither the name of the University nor the names of its
            contributors may be used to endorse or promote products derived
            from this software without specific prior written permission.

6. Disclaimer/Limitation of Liability: THIS SOFTWARE IS PROVIDED BY
   SENDMAIL, INC. AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
   NO EVENT SHALL SENDMAIL, INC., THE REGENTS OF THE UNIVERSITY OF
   CALIFORNIA OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
   USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
   ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
*/

/*
  TODO : lock, prefer fcntl() over flock()
         AND use dotlock code above
*/

#define LOCKTO_RM	300 /* timeout for stale lockfile removal */
#define LOCKTO_GLOB	400 /* global timeout for lockfile creation */

static int lock_common(const char *filename, int fd, short locktype)
{
	char lockfilename[PATH_MAX];
	struct flock lock;
	/* dot lock file */
	int statfailed = 0;
	time_t start;
	int r;
	int res;

	lock.l_start = 0;
	lock.l_len = 0;
	lock.l_pid = getpid();
	lock.l_type = locktype;
	lock.l_whence = SEEK_SET;

	r = fcntl(fd, F_SETLKW, &lock);
	if (r < 0) {
		/* WARNING POSIX lock could not be applied */
		perror("lock");
	}

	/* dot lock file */

	if (strlen(filename) + 6 > PATH_MAX) {
		res = -1;
		goto unlock;
	}

	snprintf(lockfilename, PATH_MAX, "%s.lock", filename);

	time(&start);
	while (1) {
		int fd;
		GStatBuf st;
		time_t now;

		/* global timeout */
		time(&now);
		if (now > start + LOCKTO_GLOB) {
			res = -1;
			goto unlock;
		}

		fd = open(lockfilename, O_WRONLY | O_EXCL | O_CREAT, 0);
		if (fd >= 0) {
			/* defeat lock checking programs which test pid */
			if (write(fd, "0", 2) < 0)
				FILE_OP_ERROR(lockfilename, "write");
			close(fd);
			break;
		} else {
			FILE_OP_ERROR(lockfilename, "open");
		}

		/* libEtPan! - adds a delay of 5 seconds between each tries */
		sleep(5);

		if (g_stat(lockfilename, &st) < 0) {
			if (statfailed++ > 5) {
				res = -1;
				goto unlock;
			}
			continue;
		}
		statfailed = 0;
		time(&now);

		if (now < st.st_ctime + LOCKTO_RM)
			continue;

		/* try to remove stale lockfile */
		if (unlink(lockfilename) < 0) {
			res = -1;
			goto unlock;
		}

		/*
		   libEtPan! - removes this delay of 5 seconds,
		   maybe it was misplaced ?
		 */
#if 0
		sleep(5);
#endif
	}

	return 0;

 unlock:
	lock.l_start = 0;
	lock.l_len = 0;
	lock.l_pid = getpid();
	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;

	r = fcntl(fd, F_SETLK, &lock);
	if (r < 0) {
		/* WARNING POSIX lock could not be applied */
		perror("lock");
	}
	return res;
}

static int unlock_common(const char *filename, int fd)
{
	char lockfilename[PATH_MAX];
	struct flock lock;
	int r;

	if (strlen(filename) + 6 > PATH_MAX)
		return -1;

	snprintf(lockfilename, PATH_MAX, "%s.lock", filename);

	unlink(lockfilename);

	lock.l_start = 0;
	lock.l_len = 0;
	lock.l_pid = getpid();
	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;

	r = fcntl(fd, F_SETLK, &lock);
	if (r < 0) {
		/* WARNING POSIX lock could not be applied */
	}

	return 0;
}

int maillock_read_lock(const char *filename, int fd)
{
	return lock_common(filename, fd, F_RDLCK);
}

int maillock_read_unlock(const char *filename, int fd)
{
	return unlock_common(filename, fd);
}

int maillock_write_lock(const char *filename, int fd)
{
	return lock_common(filename, fd, F_WRLCK);
}

int maillock_write_unlock(const char *filename, int fd)
{
	return unlock_common(filename, fd);
}
/*
 * vim: noet ts=4 shiftwidth=4 nowrap
 */
