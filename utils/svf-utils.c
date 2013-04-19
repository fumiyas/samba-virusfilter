/*
   Samba-VirusFilter VFS modules
   Copyright (C) 2010-2012 SATOH Fumiyasu @ OSS Technology Corp., Japan

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "svf-common.h"
#include "svf-utils.h"

#include <poll.h>

#define SVF_ENV_SIZE_CHUNK 32

/* ====================================================================== */

#ifndef HAVE_MEMMEM
void *memmem(const void *m1, size_t m1_len, const void *m2, size_t m2_len)
{
	const char *m1_cur = (const char *)m1;
	const char *m1_end = (const char *)m1 + m1_len - m2_len;
	const char *m2_cur = (const char *)m2;

	if (m1_len == 0 || m2_len == 0 || m1_len < m2_len) {
		return NULL;
	}

	if (m2_len == 1) {
		return memchr(m1_cur, *m2_cur, m1_len);
	}

	while (m1_cur <= m1_end) {
		if (*m1_cur == *m2_cur) {
			if (memcmp(m1_cur+1, m2_cur+1, m2_len-1) == 0) {
				return (void *)m1_cur;
			}
		}
		m1_cur++;
	}

	return NULL;
}
#endif

/* ====================================================================== */

char *svf_string_sub(TALLOC_CTX *mem_ctx, connection_struct *conn, const char *str)
{
	return talloc_sub_advanced(mem_ctx,
		lp_servicename(SNUM(conn)),
		conn_session_info(conn)->unix_name,
		conn->connectpath,
		conn_session_info(conn)->utok.gid,
		conn_session_info(conn)->sanitized_username,
		conn_domain_name(conn),
		str);
}

/* Python's urllib.quote(string[, safe]) clone */
int svf_url_quote(const char *src, char *dst, int dst_size)
{
	char *dst_c = dst;
        static char hex[] = "0123456789ABCDEF";

	for (; *src != '\0'; src++) {
		if ((*src < '0' && *src != '-' && *src != '.' && *src != '/') ||
		    (*src > '9' && *src < 'A') ||
		    (*src > 'Z' && *src < 'a' && *src != '_') ||
		    (*src > 'z')) {
			if (dst_size < 4) {
				return -1;
			}
			*dst_c++ = '%';
			*dst_c++ = hex[(*src >> 4) & 0x0F];
			*dst_c++ = hex[*src & 0x0F];
			dst_size -= 3;
		} else {
			if (dst_size < 2) {
				return -1;
			}
			*dst_c++ = *src;
			dst_size--;
		}
	}

        *dst_c = '\0';

	return (dst_c - dst);
}

#if SAMBA_VERSION_NUMBER >= 30600
/*********************************************************
 For rename across filesystems initial Patch from Warren Birnbaum
 <warrenb@hpcvscdp.cv.hp.com>
**********************************************************/

static int svf_copy_reg(const char *source, const char *dest)
{
	SMB_STRUCT_STAT source_stats;
	int saved_errno;
	int ifd = -1;
	int ofd = -1;

	if (sys_lstat(source, &source_stats, false) == -1)
		return -1;

	if (!S_ISREG (source_stats.st_ex_mode))
		return -1;

#if 0
	if (source_stats.st_ex_size > module_sizelimit) {
		DEBUG(5,
			("%s: size of %s larger than sizelimit (%lld > %lld), rename prohititted\n",
			MODULE, source,
			(long long)source_stats.st_ex_size,
			(long long)module_sizelimit));
		return -1;
	}
#endif

	if((ifd = sys_open (source, O_RDONLY, 0)) < 0)
		return -1;

	if (unlink (dest) && errno != ENOENT)
		return -1;

#ifdef O_NOFOLLOW
	if((ofd = sys_open (dest, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600)) < 0 )
#else
	if((ofd = sys_open (dest, O_WRONLY | O_CREAT | O_TRUNC , 0600)) < 0 )
#endif
		goto err;

	if (transfer_file(ifd, ofd, (size_t)-1) == -1)
		goto err;

	/*
	 * Try to preserve ownership.  For non-root it might fail, but that's ok.
	 * But root probably wants to know, e.g. if NFS disallows it.
	 */

#ifdef HAVE_FCHOWN
	if ((fchown(ofd, source_stats.st_ex_uid, source_stats.st_ex_gid) == -1) && (errno != EPERM))
#else
	if ((chown(dest, source_stats.st_ex_uid, source_stats.st_ex_gid) == -1) && (errno != EPERM))
#endif
		goto err;

	/*
	 * fchown turns off set[ug]id bits for non-root,
	 * so do the chmod last.
	 */

#if defined(HAVE_FCHMOD)
	if (fchmod (ofd, source_stats.st_ex_mode & 07777))
#else
	if (chmod (dest, source_stats.st_ex_mode & 07777))
#endif
		goto err;

	if (close (ifd) == -1)
		goto err;

	if (close (ofd) == -1)
		return -1;

	/* Try to copy the old file's modtime and access time.  */
#if defined(HAVE_UTIMENSAT)
	{
		struct timespec ts[2];

		ts[0] = source_stats.st_ex_atime;
		ts[1] = source_stats.st_ex_mtime;
		utimensat(AT_FDCWD, dest, ts, AT_SYMLINK_NOFOLLOW);
	}
#elif defined(HAVE_UTIMES)
	{
		struct timeval tv[2];

		tv[0] = convert_timespec_to_timeval(source_stats.st_ex_atime);
		tv[1] = convert_timespec_to_timeval(source_stats.st_ex_mtime);
#ifdef HAVE_LUTIMES
		lutimes(dest, tv);
#else
		utimes(dest, tv);
#endif
	}
#elif defined(HAVE_UTIME)
	{
		struct utimbuf tv;

		tv.actime = convert_timespec_to_time_t(source_stats.st_ex_atime);
		tv.modtime = convert_timespec_to_time_t(source_stats.st_ex_mtime);
		utime(dest, &tv);
	}
#endif

	if (unlink (source) == -1)
		return -1;

	return 0;

  err:

	saved_errno = errno;
	if (ifd != -1)
		close(ifd);
	if (ofd != -1)
		close(ofd);
	errno = saved_errno;
	return -1;
}
#endif /* SAMBA_VERSION_NUMBER >= 30600 */

#if SAMBA_VERSION_NUMBER >= 30600
int svf_vfs_next_move(
	vfs_handle_struct *vfs_h,
	const struct smb_filename *smb_fname_src,
	const struct smb_filename *smb_fname_dst)
{
	int result;

	result = SMB_VFS_NEXT_RENAME(vfs_h, smb_fname_src, smb_fname_dst);
	if (result == 0 || errno != EXDEV) {
		return result;
	}

	return svf_copy_reg(smb_fname_src->base_name, smb_fname_dst->base_name);
}
#endif /* SAMBA_VERSION_NUMBER >= 30600 */

/* Line-based socket I/O
 * ====================================================================== */

svf_io_handle *svf_io_new(TALLOC_CTX *mem_ctx, int connect_timeout, int io_timeout)
{
	svf_io_handle *io_h = TALLOC_ZERO_P(mem_ctx, svf_io_handle);

	if (!io_h) {
		return NULL;
	}

	io_h->socket = -1;
	svf_io_set_connect_timeout(io_h, connect_timeout);
	svf_io_set_io_timeout(io_h, io_timeout);
	svf_io_set_writel_eol(io_h, "\x0A", 1);
	svf_io_set_readl_eol(io_h, "\x0A", 1);

	return io_h;
}

int svf_io_set_connect_timeout(svf_io_handle *io_h, int timeout)
{
	int timeout_old = io_h->connect_timeout;

	/* timeout <= 0 means infinite */
	io_h->connect_timeout =  (timeout > 0) ? timeout : -1;

	return timeout_old;
}

int svf_io_set_io_timeout(svf_io_handle *io_h, int timeout)
{
	int timeout_old = io_h->io_timeout;

	/* timeout <= 0 means infinite */
	io_h->io_timeout =  (timeout > 0) ? timeout : -1;

	return timeout_old;
}

void svf_io_set_writel_eol(svf_io_handle *io_h, const char *eol, int eol_size)
{
	if (eol_size < 1 || eol_size > SVF_IO_EOL_SIZE) {
		return;
	}

	memcpy(io_h->w_eol, eol, eol_size);
	io_h->w_eol_size = eol_size;
}

void svf_io_set_readl_eol(svf_io_handle *io_h, const char *eol, int eol_size)
{
	if (eol_size < 1 || eol_size > SVF_IO_EOL_SIZE) {
		return;
	}

	memcpy(io_h->r_eol, eol, eol_size);
	io_h->r_eol_size = eol_size;
}

svf_result svf_io_connect_path(svf_io_handle *io_h, const char *path)
{
	struct sockaddr_un addr;
	NTSTATUS status;

	ZERO_STRUCT(addr);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));

	status = open_socket_out((struct sockaddr_storage *)&addr, 0,
		io_h->connect_timeout,
		&io_h->socket);
	if (!NT_STATUS_IS_OK(status)) {
		io_h->socket = -1;
		return SVF_RESULT_ERROR;
	}

	return SVF_RESULT_OK;
}

svf_result svf_io_disconnect(svf_io_handle *io_h)
{
	if (io_h->socket != -1) {
		close(io_h->socket);
		io_h->socket = -1;
	}

	io_h->r_size = io_h->r_rest_size = 0;
	io_h->r_rest_buffer = NULL;

	return SVF_RESULT_OK;
}

svf_result svf_io_write(svf_io_handle *io_h, const char *data, size_t data_size)
{
	struct pollfd pollfd;
	ssize_t wrote_size;

	if (data_size == 0) {
		return SVF_RESULT_OK;
	}

	pollfd.fd = io_h->socket;
	pollfd.events = POLLOUT;

	while (data_size > 0) {
		switch (poll(&pollfd, 1, io_h->io_timeout)) {
		case -1:
			if (errno == EINTR) {
				errno = 0;
				continue;
			}
			return SVF_RESULT_ERROR;
		case 0:
			errno = ETIMEDOUT;
			return SVF_RESULT_ERROR;
		}

		wrote_size = write(io_h->socket, data, data_size);
		if (wrote_size == -1) {
			if (errno == EINTR) {
				errno = 0;
				continue;
			}
			return SVF_RESULT_ERROR;
		}

		data += wrote_size;
		data_size -= wrote_size;
	}

	return SVF_RESULT_OK;
}

svf_result svf_io_writel(svf_io_handle *io_h, const char *data, size_t data_size)
{
	svf_result result;

	result = svf_io_write(io_h, data, data_size);
	if (result != SVF_RESULT_OK) {
		return result;
	}

	return svf_io_write(io_h, io_h->w_eol, io_h->w_eol_size);
}

svf_result svf_io_writefl(svf_io_handle *io_h, const char *data_fmt, ...)
{
	va_list ap;
	char data[SVF_IO_BUFFER_SIZE + SVF_IO_EOL_SIZE];
	size_t data_size;

	va_start(ap, data_fmt);
	data_size = vsnprintf(data, SVF_IO_BUFFER_SIZE, data_fmt, ap);
	va_end(ap);

	memcpy(data + data_size, io_h->w_eol, io_h->w_eol_size);
	data_size += io_h->w_eol_size;

	return svf_io_write(io_h, data, data_size);
}

svf_result svf_io_vwritefl(svf_io_handle *io_h, const char *data_fmt, va_list ap)
{
	char data[SVF_IO_BUFFER_SIZE + SVF_IO_EOL_SIZE];
	size_t data_size;

	data_size = vsnprintf(data, SVF_IO_BUFFER_SIZE, data_fmt, ap);

	memcpy(data + data_size, io_h->w_eol, io_h->w_eol_size);
	data_size += io_h->w_eol_size;

	return svf_io_write(io_h, data, data_size);
}

svf_result svf_io_writev(svf_io_handle *io_h, ...)
{
	va_list ap;
	struct iovec iov[SVF_IO_IOV_MAX], *iov_p;
	int iov_n;
	struct pollfd pollfd;
	size_t data_size;
	ssize_t wrote_size;

	va_start(ap, io_h);
	for (iov_p = iov, iov_n = 0, data_size = 0;
	     iov_n < SVF_IO_IOV_MAX;
	     iov_p++, iov_n++) {
		iov_p->iov_base = va_arg(ap, void *);
		if (!iov_p->iov_base) {
			break;
		}
		iov_p->iov_len = va_arg(ap, int);
		data_size += iov_p->iov_len;
	}
	va_end(ap);

	pollfd.fd = io_h->socket;
	pollfd.events = POLLOUT;

	for (iov_p = iov;;) {
		switch (poll(&pollfd, 1, io_h->io_timeout)) {
		case -1:
			if (errno == EINTR) {
				errno = 0;
				continue;
			}
			return SVF_RESULT_ERROR;
		case 0:
			errno = ETIMEDOUT;
			return SVF_RESULT_ERROR;
		}

		wrote_size = writev(io_h->socket, iov_p, iov_n);
		if (wrote_size == -1) {
			if (errno == EINTR) {
				errno = 0;
				continue;
			}
			return SVF_RESULT_ERROR;
		}

		data_size -= wrote_size;
		if (data_size <= 0) {
			return SVF_RESULT_OK;
		}

		while (iov_n > 0 && wrote_size >= iov_p->iov_len) {
			wrote_size -= iov_p->iov_len;
			iov_p++;
			iov_n--;
		}
		if (wrote_size > 0) {
			iov_p->iov_base = (char *)iov_p->iov_base + wrote_size;
			iov_p->iov_len -= wrote_size;
		}
	}

#if 0
	/* Not reached */
	return SVF_RESULT_OK;
#endif
}

svf_result svf_io_writevl(svf_io_handle *io_h, ...)
{
	va_list ap;
	struct iovec iov[SVF_IO_IOV_MAX + 1], *iov_p;
	int iov_n;
	struct pollfd pollfd;
	size_t data_size;
	ssize_t wrote_size;

	va_start(ap, io_h);
	for (iov_p = iov, iov_n = 0, data_size = 0;
	     iov_n < SVF_IO_IOV_MAX;
	     iov_p++, iov_n++) {
		iov_p->iov_base = va_arg(ap, void *);
		if (!iov_p->iov_base) {
			break;
		}
		iov_p->iov_len = va_arg(ap, int);
		data_size += iov_p->iov_len;
	}
	va_end(ap);

	iov_p->iov_base = io_h->r_eol;
	iov_p->iov_len = io_h->r_eol_size;
	data_size += io_h->r_eol_size;
	iov_n++;

	pollfd.fd = io_h->socket;
	pollfd.events = POLLOUT;

	for (iov_p = iov;;) {
		switch (poll(&pollfd, 1, io_h->io_timeout)) {
		case -1:
			if (errno == EINTR) {
				errno = 0;
				continue;
			}
			return SVF_RESULT_ERROR;
		case 0:
			errno = ETIMEDOUT;
			return SVF_RESULT_ERROR;
		}

		wrote_size = writev(io_h->socket, iov_p, iov_n);
		if (wrote_size == -1) {
			if (errno == EINTR) {
				errno = 0;
				continue;
			}
			return SVF_RESULT_ERROR;
		}

		data_size -= wrote_size;
		if (data_size <= 0) {
			return SVF_RESULT_OK;
		}

		while (iov_n > 0 && wrote_size >= iov_p->iov_len) {
			wrote_size -= iov_p->iov_len;
			iov_p++;
			iov_n--;
		}
		if (wrote_size > 0) {
			iov_p->iov_base = (char *)iov_p->iov_base + wrote_size;
			iov_p->iov_len -= wrote_size;
		}
	}

#if 0
	/* Not reached */
	return SVF_RESULT_OK;
#endif
}

svf_result svf_io_readl(svf_io_handle *io_h)
{
	char *buffer;
	ssize_t buffer_size = SVF_IO_BUFFER_SIZE;
	struct pollfd pollfd;
	ssize_t read_size;
	char *eol;

	if (io_h->r_rest_buffer == NULL) {
		DEBUG(11,("Rest data not found in read buffer\n"));
		buffer = io_h->r_buffer = io_h->r_buffer_real;
		buffer_size = SVF_IO_BUFFER_SIZE;
	} else {
		DEBUG(11,("Rest data found in read buffer: %s, size=%ld\n",
			io_h->r_rest_buffer, (long)io_h->r_rest_size));
		eol = memmem(io_h->r_rest_buffer, io_h->r_rest_size, io_h->r_eol, io_h->r_eol_size);
		if (eol) {
			*eol = '\0';
			io_h->r_buffer = io_h->r_rest_buffer;
			io_h->r_size = eol - io_h->r_rest_buffer;
			DEBUG(11,("Read line data from read buffer: %s\n", io_h->r_buffer));

			io_h->r_rest_size -= io_h->r_size + io_h->r_eol_size;
			io_h->r_rest_buffer = (io_h->r_rest_size > 0) ?
				(eol + io_h->r_eol_size) : NULL;

			return SVF_RESULT_OK;
		}

		io_h->r_buffer = io_h->r_buffer_real;
		memmove(io_h->r_buffer, io_h->r_rest_buffer, io_h->r_rest_size);

		buffer = io_h->r_buffer + io_h->r_size;
		buffer_size = SVF_IO_BUFFER_SIZE - io_h->r_rest_size;
	}

	io_h->r_rest_buffer = NULL;
	io_h->r_rest_size = 0;

	pollfd.fd = io_h->socket;
	pollfd.events = POLLIN;

	while (buffer_size > 0) {
		switch (poll(&pollfd, 1, io_h->io_timeout)) {
		case -1:
			if (errno == EINTR) {
				errno = 0;
				continue;
			}
			return SVF_RESULT_ERROR;
		case 0:
			errno = ETIMEDOUT;
			return SVF_RESULT_ERROR;
		}

		read_size = read(io_h->socket, buffer, buffer_size);
		if (read_size == -1) {
			if (errno == EINTR) {
				errno = 0;
				continue;
			}
			return SVF_RESULT_ERROR;
		}

		buffer[read_size] = '\0';

		if (read_size == 0) { /* EOF */
			return SVF_RESULT_OK;
		}

		io_h->r_size += read_size;

		eol = memmem(io_h->r_buffer, read_size, io_h->r_eol, io_h->r_eol_size);
		if (eol) {
			*eol = '\0';
			DEBUG(11,("Read line data from socket: %s\n", io_h->r_buffer));
			io_h->r_size = eol - io_h->r_buffer;
			io_h->r_rest_size = read_size - (eol - buffer + io_h->r_eol_size);
			if (io_h->r_rest_size > 0) {
				io_h->r_rest_buffer = eol + io_h->r_eol_size;
				DEBUG(11,("Rest data in read buffer: %s, size=%ld\n",
					io_h->r_rest_buffer, (long)io_h->r_rest_size));
			}
			return SVF_RESULT_OK;
		}

		buffer += read_size;
		buffer_size -= read_size;
	}

	errno = E2BIG;

	return SVF_RESULT_ERROR;
}

svf_result svf_io_writefl_readl(svf_io_handle *io_h, const char *fmt, ...)
{
	if (fmt) {
		va_list ap;
		svf_result result;

		va_start(ap, fmt);
		result = svf_io_vwritefl(io_h, fmt, ap);
		va_end(ap);

		if (result != SVF_RESULT_OK) {
			return result;
		}
	}

	if (svf_io_readl(io_h) != SVF_RESULT_OK) {
		return SVF_RESULT_ERROR;
	}
	if (io_h->r_size == 0) { /* EOF */
		return SVF_RESULT_ERROR; /* FIXME: SVF_RESULT_EOF? */
	}

	return SVF_RESULT_OK;
}

/* Generic "stupid" cache
 * ====================================================================== */

svf_cache_handle *svf_cache_new(TALLOC_CTX *ctx, int entry_limit, time_t time_limit)
{
	svf_cache_handle *cache_h = TALLOC_ZERO_P(ctx, svf_cache_handle);
	if (!cache_h) {
		DEBUG(0,("TALLOC_ZERO_P failed\n"));
		return NULL;
	}
	cache_h->entry_limit = entry_limit;
	cache_h->time_limit = time_limit;

	return cache_h;
}

svf_cache_entry *svf_cache_entry_new(
	svf_cache_handle *cache_h,
	const char *fname,
	int fname_len)
{
	svf_cache_entry *cache_e = TALLOC_ZERO_P(cache_h, svf_cache_entry);

	if (!cache_e) {
		return NULL;
	}

	cache_e->fname = talloc_strdup(cache_e, fname);
	if (!cache_e->fname) {
		TALLOC_FREE(cache_e);
		return NULL;
	}

	cache_e->fname_len = (fname_len >= 0) ? fname_len : strlen(fname);

	return cache_e;
}

svf_cache_entry *svf_cache_entry_rename(
	svf_cache_entry *cache_e,
	const char *fname,
	int fname_len)
{
	TALLOC_FREE(cache_e->fname);
	cache_e->fname_len = -1;

	cache_e->fname = talloc_strdup(cache_e, fname);
	if (!cache_e->fname) {
		TALLOC_FREE(cache_e);
		return NULL;
	}

	cache_e->fname_len = (fname_len >= 0) ? fname_len : strlen(fname);

	return cache_e;
}

void svf_cache_purge(svf_cache_handle *cache_h)
{
	svf_cache_entry *cache_e;
	time_t time_now = time(NULL);

	DEBUG(10,("Crawling cache entries to find purge entry\n"));

	for (cache_e = cache_h->end; cache_e; cache_e = cache_h->end) {
		time_t time_age = time_now - cache_e->time;
		DEBUG(10,("Checking cache entry: fname=%s, age=%ld\n", cache_e->fname, (long)time_age));
		if (cache_h->entry_num <= cache_h->entry_limit &&
		    time_age < cache_h->time_limit) {
			break;
		}

		svf_cache_remove(cache_h, cache_e);
		svf_cache_entry_free(cache_e);
	}
}

svf_cache_entry *svf_cache_get(svf_cache_handle *cache_h, const char *fname, int fname_len)
{
	svf_cache_entry *cache_e;

	svf_cache_purge(cache_h);

	if (fname_len <= 0) {
		fname_len = strlen(fname);
	}

	DEBUG(10,("Searching cache entry: fname=%s\n", fname));

	for (cache_e = cache_h->list; cache_e; cache_e = cache_e->next) {
		DEBUG(10,("Checking cache entry: fname=%s\n", cache_e->fname));
		if (cache_e->fname_len == fname_len && str_eq(cache_e->fname, fname)) {
			break;
		}
	}

	return cache_e;
}

void svf_cache_add(svf_cache_handle *cache_h, svf_cache_entry *cache_e)
{
	cache_e->fname_len = strlen(cache_e->fname);
	cache_e->time = time(NULL);

	DLIST_ADD(cache_h->list, cache_e);

	cache_h->entry_num++;
	if (!cache_h->end) {
		cache_h->end = cache_e;
	}

	svf_cache_purge(cache_h);
}

void svf_cache_remove(svf_cache_handle *cache_h, svf_cache_entry *cache_e)
{
	cache_e->fname_len = strlen(cache_e->fname);
	cache_e->time = time(NULL);

	DEBUG(10,("Purging cache entry: %s\n", cache_e->fname));

	if (cache_h->end == cache_e) {
                if (cache_e = cache_e-> prev) {
                        // its the last entry in the list
                        cache_h->end = NULL;
                } else {
                        cache_h->end = cache_e->prev;
                }
	}
	cache_h->entry_num--;
	DLIST_REMOVE(cache_h->list, cache_e);
}

/* Environment variable handling for execle(2)
 * ====================================================================== */

svf_env_struct *svf_env_new(TALLOC_CTX *ctx)
{
	svf_env_struct *env_h = TALLOC_ZERO_P(ctx, svf_env_struct);
	if (!env_h) {
		DEBUG(0, ("TALLOC_ZERO_P failed\n"));
		goto svf_env_init_failed;
	}

	env_h->env_num = 0;
	env_h->env_size = SVF_ENV_SIZE_CHUNK;
	env_h->env_list = TALLOC_ARRAY(env_h, char *, env_h->env_size);
	if (!env_h->env_list) {
		DEBUG(0, ("TALLOC_ARRAY failed\n"));
		goto svf_env_init_failed;
	}

	env_h->env_list[0] = NULL;

	return env_h;

svf_env_init_failed:
	TALLOC_FREE(env_h);
	return NULL;
}

char * const *svf_env_list(svf_env_struct *env_h)
{
	return env_h->env_list;
}

int svf_env_set(svf_env_struct *env_h, const char *name, const char *value)
{
	size_t name_len = strlen(name);
	size_t env_len = name_len + 1 + strlen(value); /* strlen("name=value") */
	char **env_p;

	/* Named env value already exists? */
	for (env_p = env_h->env_list; *env_p != NULL; env_p++) {
		if ((*env_p)[name_len] == '=' && strn_eq(*env_p, name, name_len)) {
			break;
		}
	}

	if (!*env_p) {
		/* Not exist. Adding a new env entry */
		char *env_new;

		if (env_h->env_size == env_h->env_num + 1) {
			/* Enlarge env_h->env_list */
			size_t env_size_new = env_h->env_size + SVF_ENV_SIZE_CHUNK;
			char **env_list_new = TALLOC_REALLOC_ARRAY(
				env_h, env_h->env_list, char *, env_size_new);
			if (!env_list_new) {
				DEBUG(0,("TALLOC_REALLOC_ARRAY failed\n"));
				return -1;
			}
			env_h->env_list = env_list_new;
			env_h->env_size = env_size_new;
		}

		env_new = talloc_asprintf(env_h, "%s=%s", name, value);
		if (!env_new) {
			DEBUG(0,("talloc_asprintf failed\n"));
			return -1;
		}
		*env_p = env_new;
		env_h->env_num++;
		env_h->env_list[env_h->env_num] = NULL;

		return 0;
	}

	if (strlen(*env_p) < env_len) {
		/* Exist, but buffer is too short */
		char *env_new = talloc_asprintf(env_h, "%s=%s", name, value);
		if (!env_new) {
			DEBUG(0,("talloc_asprintf failed\n"));
			return -1;
		}
		TALLOC_FREE(*env_p);
		*env_p = env_new;

		return 0;
	}

	/* Exist and buffer is enough to overwrite */
	snprintf(*env_p, env_len + 1, "%s=%s", name, value);

	return 0;
}

/* Shell scripting
 * ====================================================================== */

/* svf_env version Samba's *_sub_advanced() in substitute.c */
int svf_shell_set_conn_env(svf_env_struct *env_h, connection_struct *conn)
{
	int snum = SNUM(conn);
	char addr[INET6_ADDRSTRLEN];
	const char *addr_p;
	const char *local_machine_name = get_local_machine_name();
	fstring pidstr;

	if (!local_machine_name || !*local_machine_name) {
		local_machine_name = global_myname();
	}

	addr_p = conn_server_addr(conn, addr);
	if (strncmp("::ffff:", addr_p, 7) == 0) {
		addr_p += 7;
	}
	svf_env_set(env_h, "SVF_SERVER_IP", addr_p);
	svf_env_set(env_h, "SVF_SERVER_NAME", myhostname());
	svf_env_set(env_h, "SVF_SERVER_NETBIOS_NAME", local_machine_name);
	slprintf(pidstr,sizeof(pidstr)-1, "%ld", (long)sys_getpid());
	svf_env_set(env_h, "SVF_SERVER_PID", pidstr);

	svf_env_set(env_h, "SVF_SERVICE_NAME", lp_servicename(snum));
	svf_env_set(env_h, "SVF_SERVICE_PATH", conn->connectpath);

	addr_p = conn_client_addr(conn, addr);
	if (strncmp("::ffff:", addr_p, 7) == 0) {
		addr_p += 7;
	}
	svf_env_set(env_h, "SVF_CLIENT_IP", addr_p);
	svf_env_set(env_h, "SVF_CLIENT_NAME", conn_client_name(conn));
	svf_env_set(env_h, "SVF_CLIENT_NETBIOS_NAME", get_remote_machine_name());

	svf_env_set(env_h, "SVF_USER_NAME", get_current_username());
	svf_env_set(env_h, "SVF_USER_DOMAIN", current_user_info.domain);

	return 0;
}

/* Modified version of Samba's smbrun() in smbrun.c */
int svf_shell_run(
	const char *cmd,
	uid_t uid,
	gid_t gid,
	svf_env_struct *env_h,
	connection_struct *conn,
	bool sanitize)
{
	pid_t pid;

	if (!env_h) {
		env_h = svf_env_new(talloc_tos());
		if (!env_h) {
			return -1;
		}
	}

	if (conn && svf_shell_set_conn_env(env_h, conn) == -1) {
		return -1;
	}

#ifdef SVF_RUN_OUTFD_SUPPORT
	/* point our stdout at the file we want output to go into */
	if (outfd && ((*outfd = setup_out_fd()) == -1)) {
		return -1;
	}
#endif

	/* in this method we will exec /bin/sh with the correct
	   arguments, after first setting stdout to point at the file */

	/*
	 * We need to temporarily stop CatchChild from eating
	 * SIGCLD signals as it also eats the exit status code. JRA.
	 */

	CatchChildLeaveStatus();

	if ((pid=sys_fork()) < 0) {
		DEBUG(0,("svf_run: fork failed with error %s\n", strerror(errno)));
		CatchChild();
#ifdef SVF_RUN_OUTFD_SUPPORT
		if (outfd) {
			close(*outfd);
			*outfd = -1;
		}
#endif
		return errno;
	}

	if (pid) {
		/*
		 * Parent.
		 */
		int status=0;
		pid_t wpid;

		/* the parent just waits for the child to exit */
		while((wpid = sys_waitpid(pid,&status,0)) < 0) {
			if(errno == EINTR) {
				errno = 0;
				continue;
			}
			break;
		}

		CatchChild();

		if (wpid != pid) {
			DEBUG(2,("waitpid(%d) : %s\n",(int)pid,strerror(errno)));
#ifdef SVF_RUN_OUTFD_SUPPORT
			if (outfd) {
				close(*outfd);
				*outfd = -1;
			}
#endif
			return -1;
		}

#ifdef SVF_RUN_OUTFD_SUPPORT
		/* Reset the seek pointer. */
		if (outfd) {
			sys_lseek(*outfd, 0, SEEK_SET);
		}
#endif

#if defined(WIFEXITED) && defined(WEXITSTATUS)
		if (WIFEXITED(status)) {
			return WEXITSTATUS(status);
		}
#endif

		return status;
	}

	CatchChild();

	/* we are in the child. we exec /bin/sh to do the work for us. we
	   don't directly exec the command we want because it may be a
	   pipeline or anything else the config file specifies */

#ifdef SVF_RUN_OUTFD_SUPPORT
	/* point our stdout at the file we want output to go into */
	if (outfd) {
		close(1);
		if (dup2(*outfd,1) != 1) {
			DEBUG(2,("Failed to create stdout file descriptor\n"));
			close(*outfd);
			exit(80);
		}
	}
#endif

	/* now completely lose our privileges. This is a fairly paranoid
	   way of doing it, but it does work on all systems that I know of */

	become_user_permanently(uid, gid);

	if (!non_root_mode()) {
		if (getuid() != uid || geteuid() != uid ||
		    getgid() != gid || getegid() != gid) {
			/* we failed to lose our privileges - do not execute
			   the command */
			exit(81); /* we can't print stuff at this stage,
				     instead use exit codes for debugging */
		}
	}

#ifndef __INSURE__
	/* close all other file descriptors, leaving only 0, 1 and 2. 0 and
	   2 point to /dev/null from the startup code */
	{
	int fd;
	for (fd=3;fd<256;fd++) close(fd);
	}
#endif

	{
		char *newcmd = NULL;
		if (sanitize) {
			newcmd = escape_shell_string(cmd);
			if (!newcmd)
				exit(82);
		}

		execle("/bin/sh","sh","-c",
		    newcmd ? (const char *)newcmd : cmd, NULL, svf_env_list(env_h));

		SAFE_FREE(newcmd);
	}

	/* Not reached */
	exit(83);
	return 1;
}
