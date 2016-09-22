/*
 * Simulate Posix AIO using Linux kernel AIO.
 *
 * Copyright (C) Jeremy Allison 2012
 * Copyright (C) Volker Lendecke 2012
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/sys_rw.h"
#include <sys/eventfd.h>
#include <libaio.h>
#include "smbprofile.h"

static int event_fd = -1;
static io_context_t io_ctx;
static struct tevent_fd *aio_read_event;
static bool used;
static unsigned num_busy;

static void aio_linux_done(struct tevent_context *event_ctx,
			   struct tevent_fd *event,
			   uint16_t flags, void *private_data);

/************************************************************************
 Housekeeping. Cleanup if no activity for 30 seconds.
***********************************************************************/

static void aio_linux_housekeeping(struct tevent_context *event_ctx,
                                        struct tevent_timer *te,
                                        struct timeval now,
                                        void *private_data)
{
	/* Remove this timed event handler. */
	TALLOC_FREE(te);

	if ((num_busy != 0) || used) {
		used = false;

		/* Still busy. Look again in 30 seconds. */
		(void)tevent_add_timer(event_ctx,
					NULL,
					timeval_current_ofs(30, 0),
					aio_linux_housekeeping,
					NULL);
		return;
	}

	/* No activity for 30 seconds. Close out kernel resources. */
	io_queue_release(io_ctx);
	memset(&io_ctx, '\0', sizeof(io_ctx));

	if (event_fd != -1) {
		close(event_fd);
		event_fd = -1;
	}

	TALLOC_FREE(aio_read_event);
}

/************************************************************************
 Ensure event fd and aio context are initialized.
***********************************************************************/

static bool init_aio_linux(struct vfs_handle_struct *handle)
{
	struct tevent_timer *te = NULL;

	if (event_fd != -1) {
		/* Already initialized. */
		return true;
	}

	/* Schedule a shutdown event for 30 seconds from now. */
	te = tevent_add_timer(handle->conn->sconn->ev_ctx,
				NULL,
				timeval_current_ofs(30, 0),
				aio_linux_housekeeping,
				NULL);

	if (te == NULL) {
		goto fail;
	}

	event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (event_fd == -1) {
		goto fail;
	}

	aio_read_event = tevent_add_fd(server_event_context(),
				NULL,
				event_fd,
				TEVENT_FD_READ,
				aio_linux_done,
				NULL);
	if (aio_read_event == NULL) {
		goto fail;
	}

	if (io_queue_init(lp_aio_max_threads(), &io_ctx)) {
		goto fail;
	}

	DEBUG(10,("init_aio_linux: initialized with up to %d events\n",
		  (int)lp_aio_max_threads()));

	return true;

  fail:

	DEBUG(10,("init_aio_linux: initialization failed\n"));

	TALLOC_FREE(te);
	TALLOC_FREE(aio_read_event);
	if (event_fd != -1) {
		close(event_fd);
		event_fd = -1;
	}
	memset(&io_ctx, '\0', sizeof(io_ctx));
	return false;
}

struct aio_linux_state {
	struct iocb event_iocb;
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
	struct timespec start;
};

static struct tevent_req *aio_linux_pread_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp,
	void *data, size_t n, off_t offset)
{
	struct tevent_req *req;
	struct aio_linux_state *state;
	struct iocb *piocb;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct aio_linux_state);
	if (req == NULL) {
		return NULL;
	}
	if (!init_aio_linux(handle)) {
		tevent_req_error(req, EIO);
		return tevent_req_post(req, ev);
	}

	io_prep_pread(&state->event_iocb, fsp->fh->fd, data, n, offset);
	io_set_eventfd(&state->event_iocb, event_fd);
	state->event_iocb.data = req;

	piocb = &state->event_iocb;

	PROFILE_TIMESTAMP(&state->start);
	ret = io_submit(io_ctx, 1, &piocb);
	if (ret < 0) {
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}
	num_busy += 1;
	used = true;
	return req;
}

static struct tevent_req *aio_linux_pwrite_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp,
	const void *data, size_t n, off_t offset)
{
	struct tevent_req *req;
	struct aio_linux_state *state;
	struct iocb *piocb;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct aio_linux_state);
	if (req == NULL) {
		return NULL;
	}
	if (!init_aio_linux(handle)) {
		tevent_req_error(req, EIO);
		return tevent_req_post(req, ev);
	}

	io_prep_pwrite(&state->event_iocb, fsp->fh->fd, discard_const(data),
		       n, offset);
	io_set_eventfd(&state->event_iocb, event_fd);
	state->event_iocb.data = req;

	piocb = &state->event_iocb;

	PROFILE_TIMESTAMP(&state->start);
	ret = io_submit(io_ctx, 1, &piocb);
	if (ret < 0) {
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}
	num_busy += 1;
	used = true;
	return req;
}

static struct tevent_req *aio_linux_fsync_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp)
{
	struct tevent_req *req;
	struct aio_linux_state *state;
	struct iocb *piocb;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct aio_linux_state);
	if (req == NULL) {
		return NULL;
	}
	if (!init_aio_linux(handle)) {
		tevent_req_error(req, EIO);
		return tevent_req_post(req, ev);
	}

	io_prep_fsync(&state->event_iocb, fsp->fh->fd);
	io_set_eventfd(&state->event_iocb, event_fd);
	state->event_iocb.data = req;

	piocb = &state->event_iocb;

	PROFILE_TIMESTAMP(&state->start);
	ret = io_submit(io_ctx, 1, &piocb);
	if (ret < 0) {
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}
	num_busy += 1;
	used = true;
	return req;
}

static void aio_linux_done(struct tevent_context *event_ctx,
			   struct tevent_fd *event,
			   uint16_t flags, void *private_data)
{
	uint64_t num_events = 0;
	struct timespec end;

	DEBUG(10, ("aio_linux_done called with flags=%d\n",
		   (int)flags));

	PROFILE_TIMESTAMP(&end);

	/* Read the number of events available. */
	if (sys_read(event_fd, &num_events, sizeof(num_events)) !=
			sizeof(num_events)) {
		smb_panic("aio_linux_handle_completion: invalid read");
	}

	while (num_events > 0) {
		struct timespec ts = { 0, };
		struct io_event finished;
		struct tevent_req *req;
		struct aio_linux_state *state;
		int ret;

		ret = io_getevents(io_ctx, 1, 1, &finished, &ts);
		if (ret < 0) {
			DEBUG(1, ("aio_linux_done: io_getevents returned %s\n",
				  strerror(-ret)));
			return;
		}
		if (ret == 0) {
			DEBUG(10, ("aio_linux_done: io_getvents returned "
				   "0\n"));
			continue;
		}

		num_busy -= 1;

		req = talloc_get_type_abort(finished.data,
					    struct tevent_req);
		state = tevent_req_data(req, struct aio_linux_state);

		if (finished.res < 0) {
			state->ret = -1;
			state->vfs_aio_state.error = -finished.res;
		} else {
			state->ret = finished.res;
		}
		state->vfs_aio_state.duration = nsec_time_diff(&end, &state->start);
		tevent_req_done(req);
		num_events -= 1;
	}
}

static ssize_t aio_linux_recv(struct tevent_req *req,
			      struct vfs_aio_state *vfs_aio_state)
{
	struct aio_linux_state *state = tevent_req_data(
		req, struct aio_linux_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static int aio_linux_int_recv(struct tevent_req *req,
			      struct vfs_aio_state *vfs_aio_state)
{
	/*
	 * Use implicit conversion ssize_t->int
	 */
	return aio_linux_recv(req, vfs_aio_state);
}

static struct vfs_fn_pointers vfs_aio_linux_fns = {
	.pread_send_fn = aio_linux_pread_send,
	.pread_recv_fn = aio_linux_recv,
	.pwrite_send_fn = aio_linux_pwrite_send,
	.pwrite_recv_fn = aio_linux_recv,
	.fsync_send_fn = aio_linux_fsync_send,
	.fsync_recv_fn = aio_linux_int_recv,
};

static_decl_vfs;
NTSTATUS vfs_aio_linux_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"aio_linux", &vfs_aio_linux_fns);
}
