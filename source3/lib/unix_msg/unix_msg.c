/*
 * Unix SMB/CIFS implementation.
 * Copyright (C) Volker Lendecke 2013
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

#include "replace.h"
#include "unix_msg.h"
#include "system/select.h"
#include "system/time.h"
#include "system/network.h"
#include "lib/util/dlinklist.h"
#include "pthreadpool/pthreadpool_pipe.h"
#include "lib/util/iov_buf.h"
#include "lib/util/msghdr.h"
#include <fcntl.h>
#include "lib/util/time.h"

/*
 * This file implements two abstractions: The "unix_dgram" functions implement
 * queueing for unix domain datagram sockets. You can send to a destination
 * socket, and if that has no free space available, it will fall back to an
 * anonymous socket that will poll for writability. "unix_dgram" expects the
 * data size not to exceed the system limit.
 *
 * The "unix_msg" functions implement the fragmentation of large messages on
 * top of "unix_dgram". This is what is exposed to the user of this API.
 */

struct unix_dgram_msg {
	struct unix_dgram_msg *prev, *next;

	int sock;
	ssize_t sent;
	int sys_errno;
};

struct unix_dgram_send_queue {
	struct unix_dgram_send_queue *prev, *next;
	struct unix_dgram_ctx *ctx;
	int sock;
	struct unix_dgram_msg *msgs;
	struct poll_timeout *timeout;
	char path[];
};

struct unix_dgram_ctx {
	int sock;
	pid_t created_pid;
	const struct poll_funcs *ev_funcs;
	size_t max_msg;

	void (*recv_callback)(struct unix_dgram_ctx *ctx,
			      uint8_t *msg, size_t msg_len,
			      int *fds, size_t num_fds,
			      void *private_data);
	void *private_data;

	struct poll_watch *sock_read_watch;
	struct unix_dgram_send_queue *send_queues;

	struct pthreadpool_pipe *send_pool;
	struct poll_watch *pool_read_watch;

	uint8_t *recv_buf;
	char path[];
};

static void unix_dgram_recv_handler(struct poll_watch *w, int fd, short events,
				    void *private_data);

/* Set socket non blocking. */
static int prepare_socket_nonblock(int sock, bool nonblock)
{
	int flags;
#ifdef O_NONBLOCK
#define FLAG_TO_SET O_NONBLOCK
#else
#ifdef SYSV
#define FLAG_TO_SET O_NDELAY
#else /* BSD */
#define FLAG_TO_SET FNDELAY
#endif
#endif

	flags = fcntl(sock, F_GETFL);
	if (flags == -1) {
		return errno;
	}
	if (nonblock) {
		flags |= FLAG_TO_SET;
	} else {
		flags &= ~FLAG_TO_SET;
	}
	if (fcntl(sock, F_SETFL, flags) == -1) {
		return errno;
	}

#undef FLAG_TO_SET
	return 0;
}

/* Set socket close on exec. */
static int prepare_socket_cloexec(int sock)
{
#ifdef FD_CLOEXEC
	int flags;

	flags = fcntl(sock, F_GETFD, 0);
	if (flags == -1) {
		return errno;
	}
	flags |= FD_CLOEXEC;
	if (fcntl(sock, F_SETFD, flags) == -1) {
		return errno;
	}
#endif
	return 0;
}

/* Set socket non blocking and close on exec. */
static int prepare_socket(int sock)
{
	int ret = prepare_socket_nonblock(sock, true);

	if (ret) {
		return ret;
	}
	return prepare_socket_cloexec(sock);
}

static size_t unix_dgram_msg_size(void)
{
	size_t msgsize = sizeof(struct unix_dgram_msg);
	msgsize = (msgsize + 15) & ~15; /* align to 16 */
	return msgsize;
}

static struct msghdr_buf *unix_dgram_msghdr(struct unix_dgram_msg *msg)
{
	/*
	 * Not portable in C99, but "msg" is aligned and so is
	 * unix_dgram_msg_size()
	 */
	return (struct msghdr_buf *)(((char *)msg) + unix_dgram_msg_size());
}

static void close_fd_array(int *fds, size_t num_fds)
{
	size_t i;

	for (i = 0; i < num_fds; i++) {
		if (fds[i] == -1) {
			continue;
		}

		close(fds[i]);
		fds[i] = -1;
	}
}

static void close_fd_array_dgram_msg(struct unix_dgram_msg *dmsg)
{
	struct msghdr_buf *hdr = unix_dgram_msghdr(dmsg);
	struct msghdr *msg = msghdr_buf_msghdr(hdr);
	size_t num_fds = msghdr_extract_fds(msg, NULL, 0);
	int fds[num_fds];

	msghdr_extract_fds(msg, fds, num_fds);

	close_fd_array(fds, num_fds);
}

static int unix_dgram_init(const struct sockaddr_un *addr, size_t max_msg,
			   const struct poll_funcs *ev_funcs,
			   void (*recv_callback)(struct unix_dgram_ctx *ctx,
						 uint8_t *msg, size_t msg_len,
						 int *fds, size_t num_fds,
						 void *private_data),
			   void *private_data,
			   struct unix_dgram_ctx **result)
{
	struct unix_dgram_ctx *ctx;
	size_t pathlen;
	int ret;

	if (addr != NULL) {
		pathlen = strlen(addr->sun_path)+1;
	} else {
		pathlen = 1;
	}

	ctx = malloc(offsetof(struct unix_dgram_ctx, path) + pathlen);
	if (ctx == NULL) {
		return ENOMEM;
	}
	if (addr != NULL) {
		memcpy(ctx->path, addr->sun_path, pathlen);
	} else {
		ctx->path[0] = '\0';
	}

	*ctx = (struct unix_dgram_ctx) {
		.max_msg = max_msg,
		.ev_funcs = ev_funcs,
		.recv_callback = recv_callback,
		.private_data = private_data,
		.created_pid = (pid_t)-1
	};

	ctx->recv_buf = malloc(max_msg);
	if (ctx->recv_buf == NULL) {
		free(ctx);
		return ENOMEM;
	}

	ctx->sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (ctx->sock == -1) {
		ret = errno;
		goto fail_free;
	}

	/* Set non-blocking and close-on-exec. */
	ret = prepare_socket(ctx->sock);
	if (ret != 0) {
		goto fail_close;
	}

	if (addr != NULL) {
		ret = bind(ctx->sock,
			   (const struct sockaddr *)(const void *)addr,
			   sizeof(*addr));
		if (ret == -1) {
			ret = errno;
			goto fail_close;
		}

		ctx->created_pid = getpid();

		ctx->sock_read_watch = ctx->ev_funcs->watch_new(
			ctx->ev_funcs, ctx->sock, POLLIN,
			unix_dgram_recv_handler, ctx);

		if (ctx->sock_read_watch == NULL) {
			ret = ENOMEM;
			goto fail_close;
		}
	}

	*result = ctx;
	return 0;

fail_close:
	close(ctx->sock);
fail_free:
	free(ctx->recv_buf);
	free(ctx);
	return ret;
}

static void unix_dgram_recv_handler(struct poll_watch *w, int fd, short events,
				    void *private_data)
{
	struct unix_dgram_ctx *ctx = (struct unix_dgram_ctx *)private_data;
	ssize_t received;
	int flags = 0;
	struct msghdr msg;
	struct iovec iov;
	size_t bufsize = msghdr_prep_recv_fds(NULL, NULL, 0, INT8_MAX);
	uint8_t buf[bufsize];

	iov = (struct iovec) {
		.iov_base = (void *)ctx->recv_buf,
		.iov_len = ctx->max_msg,
	};

	msg = (struct msghdr) {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	msghdr_prep_recv_fds(&msg, buf, bufsize, INT8_MAX);

#ifdef MSG_CMSG_CLOEXEC
	flags |= MSG_CMSG_CLOEXEC;
#endif

	received = recvmsg(fd, &msg, flags);
	if (received == -1) {
		if ((errno == EAGAIN) ||
		    (errno == EWOULDBLOCK) ||
		    (errno == EINTR) || (errno == ENOMEM)) {
			/* Not really an error - just try again. */
			return;
		}
		/* Problem with the socket. Set it unreadable. */
		ctx->ev_funcs->watch_update(w, 0);
		return;
	}
	if (received > ctx->max_msg) {
		/* More than we expected, not for us */
		return;
	}

	{
		size_t num_fds = msghdr_extract_fds(&msg, NULL, 0);
		int fds[num_fds];
		int i;

		msghdr_extract_fds(&msg, fds, num_fds);

		for (i = 0; i < num_fds; i++) {
			int err;

			err = prepare_socket_cloexec(fds[i]);
			if (err != 0) {
				close_fd_array(fds, num_fds);
				num_fds = 0;
			}
		}

		ctx->recv_callback(ctx, ctx->recv_buf, received,
				   fds, num_fds, ctx->private_data);
	}
}

static void unix_dgram_job_finished(struct poll_watch *w, int fd, short events,
				    void *private_data);

static int unix_dgram_init_pthreadpool(struct unix_dgram_ctx *ctx)
{
	int ret, signalfd;

	if (ctx->send_pool != NULL) {
		return 0;
	}

	ret = pthreadpool_pipe_init(0, &ctx->send_pool);
	if (ret != 0) {
		return ret;
	}

	signalfd = pthreadpool_pipe_signal_fd(ctx->send_pool);

	ctx->pool_read_watch = ctx->ev_funcs->watch_new(
		ctx->ev_funcs, signalfd, POLLIN,
		unix_dgram_job_finished, ctx);
	if (ctx->pool_read_watch == NULL) {
		pthreadpool_pipe_destroy(ctx->send_pool);
		ctx->send_pool = NULL;
		return ENOMEM;
	}

	return 0;
}

static int unix_dgram_sendq_schedule_free(struct unix_dgram_send_queue *q);

static int unix_dgram_send_queue_init(
	struct unix_dgram_ctx *ctx, const struct sockaddr_un *dst,
	struct unix_dgram_send_queue **result)
{
	struct unix_dgram_send_queue *q;
	size_t pathlen;
	int ret, err;

	pathlen = strlen(dst->sun_path)+1;

	q = malloc(offsetof(struct unix_dgram_send_queue, path) + pathlen);
	if (q == NULL) {
		return ENOMEM;
	}
	q->ctx = ctx;
	q->msgs = NULL;
	q->timeout = NULL;
	memcpy(q->path, dst->sun_path, pathlen);

	q->sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (q->sock == -1) {
		err = errno;
		goto fail_free;
	}

	err = prepare_socket(q->sock);
	if (err != 0) {
		goto fail_close;
	}

	do {
		ret = connect(q->sock,
			      (const struct sockaddr *)(const void *)dst,
			      sizeof(*dst));
	} while ((ret == -1) && (errno == EINTR));

	if (ret == -1) {
		err = errno;
		goto fail_close;
	}

	err = unix_dgram_init_pthreadpool(ctx);
	if (err != 0) {
		goto fail_close;
	}

	ret = unix_dgram_sendq_schedule_free(q);
	if (ret != 0) {
		err = ENOMEM;
		goto fail_close;
	}

	DLIST_ADD(ctx->send_queues, q);

	*result = q;
	return 0;

fail_close:
	close(q->sock);
fail_free:
	free(q);
	return err;
}

static void unix_dgram_send_queue_free(struct unix_dgram_send_queue *q)
{
	struct unix_dgram_ctx *ctx = q->ctx;

	while (q->msgs != NULL) {
		struct unix_dgram_msg *msg;
		msg = q->msgs;
		DLIST_REMOVE(q->msgs, msg);
		close_fd_array_dgram_msg(msg);
		free(msg);
	}
	close(q->sock);
	DLIST_REMOVE(ctx->send_queues, q);
	ctx->ev_funcs->timeout_free(q->timeout);
	free(q);
}

static void unix_dgram_sendq_scheduled_free_handler(
	struct poll_timeout *t, void *private_data);

static int unix_dgram_sendq_schedule_free(struct unix_dgram_send_queue *q)
{
	struct unix_dgram_ctx *ctx = q->ctx;
	struct timeval timeout;

	if (q->timeout != NULL) {
		return 0;
	}

	GetTimeOfDay(&timeout);
	timeout.tv_sec += SENDQ_CACHE_TIME_SECS;

	q->timeout = ctx->ev_funcs->timeout_new(
		ctx->ev_funcs,
		timeout,
		unix_dgram_sendq_scheduled_free_handler,
		q);
	if (q->timeout == NULL) {
		return ENOMEM;
	}

	return 0;
}

static void unix_dgram_sendq_scheduled_free_handler(struct poll_timeout *t,
						    void *private_data)
{
	struct unix_dgram_send_queue *q = private_data;
	int ret;

	q->ctx->ev_funcs->timeout_free(q->timeout);
	q->timeout = NULL;

	if (q->msgs == NULL) {
		unix_dgram_send_queue_free(q);
		return;
	}

	ret = unix_dgram_sendq_schedule_free(q);
	if (ret != 0) {
		unix_dgram_send_queue_free(q);
		return;
	}
}

static int find_send_queue(struct unix_dgram_ctx *ctx,
			   const struct sockaddr_un *dst,
			   struct unix_dgram_send_queue **ps)
{
	struct unix_dgram_send_queue *s;
	int ret;

	for (s = ctx->send_queues; s != NULL; s = s->next) {
		if (strcmp(s->path, dst->sun_path) == 0) {
			*ps = s;
			return 0;
		}
	}
	ret = unix_dgram_send_queue_init(ctx, dst, &s);
	if (ret != 0) {
		return ret;
	}
	*ps = s;
	return 0;
}

static int queue_msg(struct unix_dgram_send_queue *q,
		     const struct iovec *iov, int iovcnt,
		     const int *fds, size_t num_fds)
{
	struct unix_dgram_msg *msg;
	struct msghdr_buf *hdr;
	size_t msglen, needed;
	ssize_t msghdrlen;
	int fds_copy[MIN(num_fds, INT8_MAX)];
	int i, ret;

	for (i=0; i<num_fds; i++) {
		fds_copy[i] = -1;
	}

	for (i = 0; i < num_fds; i++) {
		fds_copy[i] = dup(fds[i]);
		if (fds_copy[i] == -1) {
			ret = errno;
			goto fail;
		}
	}

	msglen = unix_dgram_msg_size();

	msghdrlen = msghdr_copy(NULL, 0, NULL, 0, iov, iovcnt,
				fds_copy, num_fds);
	if (msghdrlen == -1) {
		ret = EMSGSIZE;
		goto fail;
	}

	needed = msglen + msghdrlen;
	if (needed < msglen) {
		ret = EMSGSIZE;
		goto fail;
	}

	msg = malloc(needed);
	if (msg == NULL) {
		ret = ENOMEM;
		goto fail;
	}
	hdr = unix_dgram_msghdr(msg);

	msg->sock = q->sock;
	msghdr_copy(hdr, msghdrlen, NULL, 0, iov, iovcnt,
		    fds_copy, num_fds);

	DLIST_ADD_END(q->msgs, msg);
	return 0;
fail:
	close_fd_array(fds_copy, num_fds);
	return ret;
}

static void unix_dgram_send_job(void *private_data)
{
	struct unix_dgram_msg *dmsg = private_data;

	do {
		struct msghdr_buf *hdr = unix_dgram_msghdr(dmsg);
		struct msghdr *msg = msghdr_buf_msghdr(hdr);
		dmsg->sent = sendmsg(dmsg->sock, msg, 0);
	} while ((dmsg->sent == -1) && (errno == EINTR));

	if (dmsg->sent == -1) {
		dmsg->sys_errno = errno;
	}
}

static void unix_dgram_job_finished(struct poll_watch *w, int fd, short events,
				    void *private_data)
{
	struct unix_dgram_ctx *ctx = private_data;
	struct unix_dgram_send_queue *q;
	struct unix_dgram_msg *msg;
	int ret, job;

	ret = pthreadpool_pipe_finished_jobs(ctx->send_pool, &job, 1);
	if (ret != 1) {
		return;
	}

	for (q = ctx->send_queues; q != NULL; q = q->next) {
		if (job == q->sock) {
			break;
		}
	}

	if (q == NULL) {
		/* Huh? Should not happen */
		return;
	}

	msg = q->msgs;
	DLIST_REMOVE(q->msgs, msg);
	close_fd_array_dgram_msg(msg);
	free(msg);

	if (q->msgs != NULL) {
		ret = pthreadpool_pipe_add_job(ctx->send_pool, q->sock,
					       unix_dgram_send_job, q->msgs);
		if (ret != 0) {
			unix_dgram_send_queue_free(q);
			return;
		}
		return;
	}

	ret = prepare_socket_nonblock(q->sock, true);
	if (ret != 0) {
		unix_dgram_send_queue_free(q);
	}
}

static int unix_dgram_send(struct unix_dgram_ctx *ctx,
			   const struct sockaddr_un *dst,
			   const struct iovec *iov, int iovlen,
			   const int *fds, size_t num_fds)
{
	struct unix_dgram_send_queue *q;
	struct msghdr msg;
	ssize_t fdlen;
	int ret;
	int i;

	if (num_fds > INT8_MAX) {
		return EINVAL;
	}

#if !defined(HAVE_STRUCT_MSGHDR_MSG_CONTROL) && !defined(HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS)
	if (num_fds > 0) {
		return ENOSYS;
	}
#endif

	for (i = 0; i < num_fds; i++) {
		/*
		 * Make sure we only allow fd passing
		 * for communication channels,
		 * e.g. sockets, pipes, fifos, ...
		 */
		ret = lseek(fds[i], 0, SEEK_CUR);
		if (ret == -1 && errno == ESPIPE) {
			/* ok */
			continue;
		}

		/*
		 * Reject the message as we may need to call dup(),
		 * if we queue the message.
		 *
		 * That might result in unexpected behavior for the caller
		 * for files and broken posix locking.
		 */
		return EINVAL;
	}

	ret = find_send_queue(ctx, dst, &q);
	if (ret != 0) {
		return ret;
	}

	if (q->msgs) {
		/*
		 * To preserve message ordering, we have to queue a
		 * message when others are waiting in line already.
		 */
		return queue_msg(q, iov, iovlen, fds, num_fds);
	}

	/*
	 * Try a cheap nonblocking send
	 */

	msg = (struct msghdr) {
		.msg_iov = discard_const_p(struct iovec, iov),
		.msg_iovlen = iovlen
	};

	fdlen = msghdr_prep_fds(&msg, NULL, 0, fds, num_fds);
	if (fdlen == -1) {
		return EINVAL;
	}

	{
		uint8_t buf[fdlen];
		msghdr_prep_fds(&msg, buf, fdlen, fds, num_fds);

		ret = sendmsg(q->sock, &msg, 0);
	}

	if (ret >= 0) {
		return 0;
	}
	if ((errno != EWOULDBLOCK) &&
	    (errno != EAGAIN) &&
#ifdef ENOBUFS
	    /* FreeBSD can give this for large messages */
	    (errno != ENOBUFS) &&
#endif
	    (errno != EINTR)) {
		return errno;
	}

	ret = queue_msg(q, iov, iovlen, fds, num_fds);
	if (ret != 0) {
		unix_dgram_send_queue_free(q);
		return ret;
	}

	/*
	 * While sending the messages via the pthreadpool, we set the
	 * socket back to blocking mode. When the sendqueue becomes
	 * empty and we could attempt direct sends again, the
	 * finished-jobs-handler of the pthreadpool will set it back
	 * to non-blocking.
	 */
	ret = prepare_socket_nonblock(q->sock, false);
	if (ret != 0) {
		unix_dgram_send_queue_free(q);
		return ret;
	}
	ret = pthreadpool_pipe_add_job(ctx->send_pool, q->sock,
				       unix_dgram_send_job, q->msgs);
	if (ret != 0) {
		unix_dgram_send_queue_free(q);
		return ret;
	}
	return 0;
}

static int unix_dgram_sock(struct unix_dgram_ctx *ctx)
{
	return ctx->sock;
}

static int unix_dgram_free(struct unix_dgram_ctx *ctx)
{
	struct unix_dgram_send_queue *q;

	for (q = ctx->send_queues; q != NULL;) {
		struct unix_dgram_send_queue *q_next = q->next;

		if (q->msgs != NULL) {
			return EBUSY;
		}
		unix_dgram_send_queue_free(q);
		q = q_next;
	}

	if (ctx->send_pool != NULL) {
		int ret = pthreadpool_pipe_destroy(ctx->send_pool);
		if (ret != 0) {
			return ret;
		}
		ctx->ev_funcs->watch_free(ctx->pool_read_watch);
	}

	ctx->ev_funcs->watch_free(ctx->sock_read_watch);

	close(ctx->sock);
	if (getpid() == ctx->created_pid) {
		/* If we created it, unlink. Otherwise someone else might
		 * still have it open */
		unlink(ctx->path);
	}

	free(ctx->recv_buf);
	free(ctx);
	return 0;
}

/*
 * Every message starts with a uint64_t cookie.
 *
 * A value of 0 indicates a single-fragment message which is complete in
 * itself. The data immediately follows the cookie.
 *
 * Every multi-fragment message has a cookie != 0 and starts with a cookie
 * followed by a struct unix_msg_header and then the data. The pid and sock
 * fields are used to assure uniqueness on the receiver side.
 */

struct unix_msg_hdr {
	size_t msglen;
	pid_t pid;
	int sock;
};

struct unix_msg {
	struct unix_msg *prev, *next;
	size_t msglen;
	size_t received;
	pid_t sender_pid;
	int sender_sock;
	uint64_t cookie;
	uint8_t buf[1];
};

struct unix_msg_ctx {
	struct unix_dgram_ctx *dgram;
	size_t fragment_len;
	uint64_t cookie;

	void (*recv_callback)(struct unix_msg_ctx *ctx,
			      uint8_t *msg, size_t msg_len,
			      int *fds, size_t num_fds,
			      void *private_data);
	void *private_data;

	struct unix_msg *msgs;
};

static void unix_msg_recv(struct unix_dgram_ctx *dgram_ctx,
			  uint8_t *buf, size_t buflen,
			  int *fds, size_t num_fds,
			  void *private_data);

int unix_msg_init(const struct sockaddr_un *addr,
		  const struct poll_funcs *ev_funcs,
		  size_t fragment_len,
		  void (*recv_callback)(struct unix_msg_ctx *ctx,
					uint8_t *msg, size_t msg_len,
					int *fds, size_t num_fds,
					void *private_data),
		  void *private_data,
		  struct unix_msg_ctx **result)
{
	struct unix_msg_ctx *ctx;
	int ret;

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL) {
		return ENOMEM;
	}

	*ctx = (struct unix_msg_ctx) {
		.fragment_len = fragment_len,
		.cookie = 1,
		.recv_callback = recv_callback,
		.private_data = private_data
	};

	ret = unix_dgram_init(addr, fragment_len, ev_funcs,
			      unix_msg_recv, ctx, &ctx->dgram);
	if (ret != 0) {
		free(ctx);
		return ret;
	}

	*result = ctx;
	return 0;
}

int unix_msg_send(struct unix_msg_ctx *ctx, const struct sockaddr_un *dst,
		  const struct iovec *iov, int iovlen,
		  const int *fds, size_t num_fds)
{
	ssize_t msglen;
	size_t sent;
	int ret = 0;
	struct iovec iov_copy[iovlen+2];
	struct unix_msg_hdr hdr;
	struct iovec src_iov;

	if (iovlen < 0) {
		return EINVAL;
	}

	msglen = iov_buflen(iov, iovlen);
	if (msglen == -1) {
		return EINVAL;
	}

	if (num_fds > INT8_MAX) {
		return EINVAL;
	}

	if (msglen <= (ctx->fragment_len - sizeof(uint64_t))) {
		uint64_t cookie = 0;

		iov_copy[0].iov_base = &cookie;
		iov_copy[0].iov_len = sizeof(cookie);
		if (iovlen > 0) {
			memcpy(&iov_copy[1], iov,
			       sizeof(struct iovec) * iovlen);
		}

		return unix_dgram_send(ctx->dgram, dst, iov_copy, iovlen+1,
				       fds, num_fds);
	}

	hdr = (struct unix_msg_hdr) {
		.msglen = msglen,
		.pid = getpid(),
		.sock = unix_dgram_sock(ctx->dgram)
	};

	iov_copy[0].iov_base = &ctx->cookie;
	iov_copy[0].iov_len = sizeof(ctx->cookie);
	iov_copy[1].iov_base = &hdr;
	iov_copy[1].iov_len = sizeof(hdr);

	sent = 0;
	src_iov = iov[0];

	/*
	 * The following write loop sends the user message in pieces. We have
	 * filled the first two iovecs above with "cookie" and "hdr". In the
	 * following loops we pull message chunks from the user iov array and
	 * fill iov_copy piece by piece, possibly truncating chunks from the
	 * caller's iov array. Ugly, but hopefully efficient.
	 */

	while (sent < msglen) {
		size_t fragment_len;
		size_t iov_index = 2;

		fragment_len = sizeof(ctx->cookie) + sizeof(hdr);

		while (fragment_len < ctx->fragment_len) {
			size_t space, chunk;

			space = ctx->fragment_len - fragment_len;
			chunk = MIN(space, src_iov.iov_len);

			iov_copy[iov_index].iov_base = src_iov.iov_base;
			iov_copy[iov_index].iov_len = chunk;
			iov_index += 1;

			src_iov.iov_base = (char *)src_iov.iov_base + chunk;
			src_iov.iov_len -= chunk;
			fragment_len += chunk;

			if (src_iov.iov_len == 0) {
				iov += 1;
				iovlen -= 1;
				if (iovlen == 0) {
					break;
				}
				src_iov = iov[0];
			}
		}
		sent += (fragment_len - sizeof(ctx->cookie) - sizeof(hdr));

		/*
		 * only the last fragment should pass the fd array.
		 * That simplifies the receiver a lot.
		 */
		if (sent < msglen) {
			ret = unix_dgram_send(ctx->dgram, dst,
					      iov_copy, iov_index,
					      NULL, 0);
		} else {
			ret = unix_dgram_send(ctx->dgram, dst,
					      iov_copy, iov_index,
					      fds, num_fds);
		}
		if (ret != 0) {
			break;
		}
	}

	ctx->cookie += 1;
	if (ctx->cookie == 0) {
		ctx->cookie += 1;
	}

	return ret;
}

static void unix_msg_recv(struct unix_dgram_ctx *dgram_ctx,
			  uint8_t *buf, size_t buflen,
			  int *fds, size_t num_fds,
			  void *private_data)
{
	struct unix_msg_ctx *ctx = (struct unix_msg_ctx *)private_data;
	struct unix_msg_hdr hdr;
	struct unix_msg *msg;
	size_t space;
	uint64_t cookie;

	if (buflen < sizeof(cookie)) {
		goto close_fds;
	}

	memcpy(&cookie, buf, sizeof(cookie));

	buf += sizeof(cookie);
	buflen -= sizeof(cookie);

	if (cookie == 0) {
		ctx->recv_callback(ctx, buf, buflen, fds, num_fds,
				   ctx->private_data);
		return;
	}

	if (buflen < sizeof(hdr)) {
		goto close_fds;
	}
	memcpy(&hdr, buf, sizeof(hdr));

	buf += sizeof(hdr);
	buflen -= sizeof(hdr);

	for (msg = ctx->msgs; msg != NULL; msg = msg->next) {
		if ((msg->sender_pid == hdr.pid) &&
		    (msg->sender_sock == hdr.sock)) {
			break;
		}
	}

	if ((msg != NULL) && (msg->cookie != cookie)) {
		DLIST_REMOVE(ctx->msgs, msg);
		free(msg);
		msg = NULL;
	}

	if (msg == NULL) {
		msg = malloc(offsetof(struct unix_msg, buf) + hdr.msglen);
		if (msg == NULL) {
			goto close_fds;
		}
		*msg = (struct unix_msg) {
			.msglen = hdr.msglen,
			.sender_pid = hdr.pid,
			.sender_sock = hdr.sock,
			.cookie = cookie
		};
		DLIST_ADD(ctx->msgs, msg);
	}

	space = msg->msglen - msg->received;
	if (buflen > space) {
		goto close_fds;
	}

	memcpy(msg->buf + msg->received, buf, buflen);
	msg->received += buflen;

	if (msg->received < msg->msglen) {
		goto close_fds;
	}

	DLIST_REMOVE(ctx->msgs, msg);
	ctx->recv_callback(ctx, msg->buf, msg->msglen, fds, num_fds,
			   ctx->private_data);
	free(msg);
	return;

close_fds:
	close_fd_array(fds, num_fds);
}

int unix_msg_free(struct unix_msg_ctx *ctx)
{
	int ret;

	ret = unix_dgram_free(ctx->dgram);
	if (ret != 0) {
		return ret;
	}

	while (ctx->msgs != NULL) {
		struct unix_msg *msg = ctx->msgs;
		DLIST_REMOVE(ctx->msgs, msg);
		free(msg);
	}

	free(ctx);
	return 0;
}
