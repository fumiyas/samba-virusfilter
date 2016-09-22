/* 
   Unix SMB/CIFS implementation.

   process model: standard (1 process per client connection)

   Copyright (C) Andrew Tridgell 1992-2005
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
   Copyright (C) Stefan (metze) Metzmacher 2004
   
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

#include "includes.h"
#include "lib/events/events.h"
#include "smbd/process_model.h"
#include "system/filesys.h"
#include "cluster/cluster.h"
#include "param/param.h"
#include "ldb_wrap.h"

struct standard_child_state {
	const char *name;
	pid_t pid;
	int to_parent_fd;
	int from_child_fd;
	struct tevent_fd *from_child_fde;
};

NTSTATUS process_model_standard_init(void);

/* we hold a pipe open in the parent, and the any child
   processes wait for EOF on that pipe. This ensures that
   children die when the parent dies */
static int child_pipe[2] = { -1, -1 };

/*
  called when the process model is selected
*/
static void standard_model_init(void)
{
	int rc;

	rc = pipe(child_pipe);
	if (rc < 0) {
		smb_panic("Failed to initialze pipe!");
	}
}

/*
  handle EOF on the parent-to-all-children pipe in the child
*/
static void standard_pipe_handler(struct tevent_context *event_ctx, struct tevent_fd *fde, 
				  uint16_t flags, void *private_data)
{
	DEBUG(10,("Child %d exiting\n", (int)getpid()));
	exit(0);
}

/*
  handle EOF on the child pipe in the parent, so we know when a
  process terminates without using SIGCHLD or waiting on all possible pids.

  We need to ensure we do not ignore SIGCHLD because we need it to
  work to get a valid error code from samba_runcmd_*().
 */
static void standard_child_pipe_handler(struct tevent_context *ev,
					struct tevent_fd *fde,
					uint16_t flags,
					void *private_data)
{
	struct standard_child_state *state
		= talloc_get_type_abort(private_data, struct standard_child_state);
	int status = 0;
	pid_t pid;

	/* the child has closed the pipe, assume its dead */
	errno = 0;
	pid = waitpid(state->pid, &status, 0);

	if (pid != state->pid) {
		if (errno == ECHILD) {
			/*
			 * this happens when the
			 * parent has set SIGCHLD to
			 * SIG_IGN. In that case we
			 * can only get error
			 * information for the child
			 * via its logging. We should
			 * stop using SIG_IGN on
			 * SIGCHLD in the standard
			 * process model.
			 */
			DEBUG(0, ("Error in waitpid() unexpectedly got ECHILD "
				  "for child %d (%s) - %s, someone has set SIGCHLD "
				  "to SIG_IGN!\n",
				  (int)state->pid, state->name,
				  strerror(errno)));
			TALLOC_FREE(state);
			return;
		}
		DEBUG(0, ("Error in waitpid() for child %d (%s) - %s \n",
			  (int)state->pid, state->name, strerror(errno)));
		if (errno == 0) {
			errno = ECHILD;
		}
		TALLOC_FREE(state);
		return;
	}
	if (WIFEXITED(status)) {
		status = WEXITSTATUS(status);
		DEBUG(2, ("Child %d (%s) exited with status %d\n",
			  (int)state->pid, state->name, status));
	} else if (WIFSIGNALED(status)) {
		status = WTERMSIG(status);
		DEBUG(0, ("Child %d (%s) terminated with signal %d\n",
			  (int)state->pid, state->name, status));
	}
	TALLOC_FREE(state);
	return;
}

static struct standard_child_state *setup_standard_child_pipe(struct tevent_context *ev,
							      const char *name)
{
	struct standard_child_state *state;
	int parent_child_pipe[2];
	int ret;

	/*
	 * Prepare a pipe to allow us to know when the child exits,
	 * because it will trigger a read event on this private
	 * pipe.
	 *
	 * We do all this before the accept and fork(), so we can
	 * clean up if it fails.
	 */
	state = talloc_zero(ev, struct standard_child_state);
	if (state == NULL) {
		return NULL;
	}

	if (name == NULL) {
		name = "";
	}

	state->name = talloc_strdup(state, name);
	if (state->name == NULL) {
		TALLOC_FREE(state);
		return NULL;
	}

	ret = pipe(parent_child_pipe);
	if (ret == -1) {
		DEBUG(0, ("Failed to create parent-child pipe to handle "
			  "SIGCHLD to track new process for socket\n"));
		TALLOC_FREE(state);
		return NULL;
	}

	smb_set_close_on_exec(parent_child_pipe[0]);
	smb_set_close_on_exec(parent_child_pipe[1]);

	state->from_child_fd = parent_child_pipe[0];
	state->to_parent_fd = parent_child_pipe[1];

	/*
	 * The basic purpose of calling this handler is to ensure we
	 * call waitpid() and so avoid zombies (now that we no longer
	 * user SIGIGN on for SIGCHLD), but it also allows us to clean
	 * up other resources in the future.
	 */
	state->from_child_fde = tevent_add_fd(ev, state,
					      state->from_child_fd,
					      TEVENT_FD_READ,
					      standard_child_pipe_handler,
					      state);
	if (state->from_child_fde == NULL) {
		TALLOC_FREE(state);
		return NULL;
	}
	tevent_fd_set_auto_close(state->from_child_fde);

	return state;
}

/*
  called when a listening socket becomes readable. 
*/
static void standard_accept_connection(struct tevent_context *ev, 
				       struct loadparm_context *lp_ctx,
				       struct socket_context *sock, 
				       void (*new_conn)(struct tevent_context *,
							struct loadparm_context *, struct socket_context *, 
							struct server_id , void *), 
				       void *private_data)
{
	NTSTATUS status;
	struct socket_context *sock2;
	pid_t pid;
	struct socket_address *c, *s;
	struct standard_child_state *state;

	state = setup_standard_child_pipe(ev, NULL);
	if (state == NULL) {
		return;
	}

	/* accept an incoming connection. */
	status = socket_accept(sock, &sock2);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("standard_accept_connection: accept: %s\n",
			 nt_errstr(status)));
		/* this looks strange, but is correct. We need to throttle things until
		   the system clears enough resources to handle this new socket */
		sleep(1);
		close(state->to_parent_fd);
		state->to_parent_fd = -1;
		TALLOC_FREE(state);
		return;
	}

	pid = fork();

	if (pid != 0) {
		close(state->to_parent_fd);
		state->to_parent_fd = -1;

		if (pid > 0) {
			state->pid = pid;
		} else {
			TALLOC_FREE(state);
		}

		/* parent or error code ... */
		talloc_free(sock2);
		/* go back to the event loop */
		return;
	}

	/* this leaves state->to_parent_fd open */
	TALLOC_FREE(state);

	pid = getpid();

	/* This is now the child code. We need a completely new event_context to work with */

	if (tevent_re_initialise(ev) != 0) {
		smb_panic("Failed to re-initialise tevent after fork");
	}

	/* this will free all the listening sockets and all state that
	   is not associated with this new connection */
	talloc_free(sock);

	/* we don't care if the dup fails, as its only a select()
	   speed optimisation */
	socket_dup(sock2);
			
	/* tdb needs special fork handling */
	ldb_wrap_fork_hook();

	tevent_add_fd(ev, ev, child_pipe[0], TEVENT_FD_READ,
		      standard_pipe_handler, NULL);
	if (child_pipe[1] != -1) {
		close(child_pipe[1]);
		child_pipe[1] = -1;
	}

	/* setup the process title */
	c = socket_get_peer_addr(sock2, ev);
	s = socket_get_my_addr(sock2, ev);
	if (s && c) {
		setproctitle("conn c[%s:%u] s[%s:%u] server_id[%d]",
			     c->addr, c->port, s->addr, s->port, (int)pid);
	}
	talloc_free(c);
	talloc_free(s);

	/* setup this new connection.  Cluster ID is PID based for this process model */
	new_conn(ev, lp_ctx, sock2, cluster_id(pid, 0), private_data);

	/* we can't return to the top level here, as that event context is gone,
	   so we now process events in the new event context until there are no
	   more to process */	   
	tevent_loop_wait(ev);

	talloc_free(ev);
	exit(0);
}

/*
  called to create a new server task
*/
static void standard_new_task(struct tevent_context *ev, 
			      struct loadparm_context *lp_ctx,
			      const char *service_name,
			      void (*new_task)(struct tevent_context *, struct loadparm_context *lp_ctx, struct server_id , void *),
			      void *private_data)
{
	pid_t pid;
	struct standard_child_state *state;

	state = setup_standard_child_pipe(ev, service_name);
	if (state == NULL) {
		return;
	}

	pid = fork();

	if (pid != 0) {
		close(state->to_parent_fd);
		state->to_parent_fd = -1;

		if (pid > 0) {
			state->pid = pid;
		} else {
			TALLOC_FREE(state);
		}

		/* parent or error code ... go back to the event loop */
		return;
	}

	/* this leaves state->to_parent_fd open */
	TALLOC_FREE(state);

	pid = getpid();

	/* this will free all the listening sockets and all state that
	   is not associated with this new connection */
	if (tevent_re_initialise(ev) != 0) {
		smb_panic("Failed to re-initialise tevent after fork");
	}

	/* ldb/tdb need special fork handling */
	ldb_wrap_fork_hook();

	tevent_add_fd(ev, ev, child_pipe[0], TEVENT_FD_READ,
		      standard_pipe_handler, NULL);
	if (child_pipe[1] != -1) {
		close(child_pipe[1]);
		child_pipe[1] = -1;
	}

	setproctitle("task %s server_id[%d]", service_name, (int)pid);

	/* setup this new task.  Cluster ID is PID based for this process model */
	new_task(ev, lp_ctx, cluster_id(pid, 0), private_data);

	/* we can't return to the top level here, as that event context is gone,
	   so we now process events in the new event context until there are no
	   more to process */	   
	tevent_loop_wait(ev);

	talloc_free(ev);
	exit(0);
}


/* called when a task goes down */
_NORETURN_ static void standard_terminate(struct tevent_context *ev, struct loadparm_context *lp_ctx,
					  const char *reason) 
{
	DEBUG(2,("standard_terminate: reason[%s]\n",reason));

	talloc_free(ev);

	/* this reload_charcnv() has the effect of freeing the iconv context memory,
	   which makes leak checking easier */
	reload_charcnv(lp_ctx);

	/* terminate this process */
	exit(0);
}

/* called to set a title of a task or connection */
static void standard_set_title(struct tevent_context *ev, const char *title) 
{
	if (title) {
		setproctitle("%s", title);
	} else {
		setproctitle(NULL);
	}
}

static const struct model_ops standard_ops = {
	.name			= "standard",
	.model_init		= standard_model_init,
	.accept_connection	= standard_accept_connection,
	.new_task               = standard_new_task,
	.terminate              = standard_terminate,
	.set_title              = standard_set_title,
};

/*
  initialise the standard process model, registering ourselves with the process model subsystem
 */
NTSTATUS process_model_standard_init(void)
{
	return register_process_model(&standard_ops);
}
