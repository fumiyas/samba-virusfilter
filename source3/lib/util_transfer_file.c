/*
 * Unix SMB/CIFS implementation.
 * Utility functions to transfer files.
 *
 * Copyright (C) Jeremy Allison 2001-2002
 * Copyright (C) Michael Adam 2008
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <includes.h>
#include "transfer_file.h"
#include "lib/util/sys_rw.h"

/****************************************************************************
 Transfer some data between two fd's.
****************************************************************************/

#ifndef TRANSFER_BUF_SIZE
#define TRANSFER_BUF_SIZE 65536
#endif


ssize_t transfer_file_internal(void *in_file,
			       void *out_file,
			       size_t n,
			       ssize_t (*pread_fn)(void *, void *, size_t, off_t),
			       ssize_t (*pwrite_fn)(void *, const void *, size_t, off_t))
{
	char *buf;
	size_t total = 0;
	ssize_t read_ret;
	ssize_t write_ret;
	size_t num_to_read_thistime;
	size_t num_written = 0;
	off_t offset = 0;

	if (n == 0) {
		return 0;
	}

	if ((buf = SMB_MALLOC_ARRAY(char, TRANSFER_BUF_SIZE)) == NULL) {
		return -1;
	}

	do {
		num_to_read_thistime = MIN((n - total), TRANSFER_BUF_SIZE);

		read_ret = (*pread_fn)(in_file, buf, num_to_read_thistime, offset);
		if (read_ret == -1) {
			DEBUG(0,("transfer_file_internal: read failure. "
				 "Error = %s\n", strerror(errno) ));
			SAFE_FREE(buf);
			return -1;
		}
		if (read_ret == 0) {
			break;
		}

		num_written = 0;

		while (num_written < read_ret) {
			write_ret = (*pwrite_fn)(out_file, buf + num_written,
					        read_ret - num_written,
						offset + num_written);

			if (write_ret == -1) {
				DEBUG(0,("transfer_file_internal: "
					 "write failure. Error = %s\n",
					 strerror(errno) ));
				SAFE_FREE(buf);
				return -1;
			}
			if (write_ret == 0) {
				return (ssize_t)total;
			}

			num_written += (size_t)write_ret;
		}

		total += (size_t)read_ret;
		offset += (off_t)read_ret;
	} while (total < n);

	SAFE_FREE(buf);
	return (ssize_t)total;
}

static ssize_t sys_pread_fn(void *file, void *buf, size_t len, off_t offset)
{
	int *fd = (int *)file;

	return sys_pread(*fd, buf, len, offset);
}

static ssize_t sys_pwrite_fn(void *file, const void *buf, size_t len, off_t offset)
{
	int *fd = (int *)file;

	return sys_pwrite(*fd, buf, len, offset);
}

off_t transfer_file(int infd, int outfd, off_t n)
{
	return (off_t)transfer_file_internal(&infd, &outfd, (size_t)n,
						 sys_pread_fn, sys_pwrite_fn);
}
