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

#ifndef MAILMBOX_TYPES_H

#define MAILMBOX_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <limits.h>

/* The Hurd doesn't have this limit */
#ifndef PATH_MAX
#define PATH_MAX 4196
#endif

#include "mailimf.h"
#include "carray.h"
#include "chash.h"

	enum {
		MAILMBOX_NO_ERROR = 0,
		MAILMBOX_ERROR_PARSE,
		MAILMBOX_ERROR_INVAL,
		MAILMBOX_ERROR_FILE_NOT_FOUND,
		MAILMBOX_ERROR_MEMORY,
		MAILMBOX_ERROR_TEMPORARY_FILE,
		MAILMBOX_ERROR_FILE,
		MAILMBOX_ERROR_MSG_NOT_FOUND,
		MAILMBOX_ERROR_READONLY,
	};

	struct claws_mailmbox_folder {
		char mb_filename[PATH_MAX];

		time_t mb_mtime;

		int mb_fd;
		int mb_read_only;
		int mb_no_uid;

		int mb_changed;
		unsigned int mb_deleted_count;

		char *mb_mapping;
		size_t mb_mapping_size;

		uint32_t mb_written_uid;
		uint32_t mb_max_uid;

		chash *mb_hash;
		carray *mb_tab;
	};

	struct claws_mailmbox_folder *claws_mailmbox_folder_new(const char *mb_filename);
	void claws_mailmbox_folder_free(struct claws_mailmbox_folder *folder);

	struct claws_mailmbox_msg_info {
		unsigned int msg_index;
		uint32_t msg_uid;
		int msg_written_uid;
		int msg_deleted;

		size_t msg_start;
		size_t msg_start_len;

		size_t msg_headers;
		size_t msg_headers_len;

		size_t msg_body;
		size_t msg_body_len;

		size_t msg_size;

		size_t msg_padding;
	};

	int claws_mailmbox_msg_info_update(struct claws_mailmbox_folder *folder, size_t msg_start, size_t msg_start_len, size_t msg_headers, size_t msg_headers_len, size_t msg_body, size_t msg_body_len, size_t msg_size, size_t msg_padding, uint32_t msg_uid);

	struct claws_mailmbox_msg_info *claws_mailmbox_msg_info_new(size_t msg_start, size_t msg_start_len, size_t msg_headers, size_t msg_headers_len, size_t msg_body, size_t msg_body_len, size_t msg_size, size_t msg_padding, uint32_t msg_uid);

	void claws_mailmbox_msg_info_free(struct claws_mailmbox_msg_info *info);

	struct claws_mailmbox_append_info {
		const char *ai_message;
		size_t ai_size;
	};

	struct claws_mailmbox_append_info *claws_mailmbox_append_info_new(const char *ai_message, size_t ai_size);

	void claws_mailmbox_append_info_free(struct claws_mailmbox_append_info *info);

#ifdef __cplusplus
}
#endif
#endif
