#include "external-agent.h"
#include "lock-tracking.h"
#include "logging.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include "../common/tdb_private.h"
#include "tap-interface.h"
#include <stdio.h>
#include <stdarg.h>

static struct tdb_context *tdb;

static enum agent_return do_operation(enum operation op, const char *name)
{
	TDB_DATA k;
	enum agent_return ret;
	TDB_DATA data;

	if (op != OPEN && op != OPEN_WITH_CLEAR_IF_FIRST && !tdb) {
		diag("external: No tdb open!");
		return OTHER_FAILURE;
	}

	k.dptr = discard_const_p(uint8_t, name);
	k.dsize = strlen(name);

	locking_would_block = 0;
	switch (op) {
	case OPEN:
		if (tdb) {
			diag("Already have tdb %s open", tdb_name(tdb));
			return OTHER_FAILURE;
		}
		tdb = tdb_open_ex(name, 0, TDB_DEFAULT, O_RDWR, 0,
				  &taplogctx, NULL);
		if (!tdb) {
			if (!locking_would_block)
				diag("Opening tdb gave %s", strerror(errno));
			ret = OTHER_FAILURE;
		} else
			ret = SUCCESS;
		break;
	case OPEN_WITH_CLEAR_IF_FIRST:
		if (tdb)
			return OTHER_FAILURE;
		tdb = tdb_open_ex(name, 0, TDB_CLEAR_IF_FIRST, O_RDWR, 0,
				  &taplogctx, NULL);
		ret = tdb ? SUCCESS : OTHER_FAILURE;
		break;
	case TRANSACTION_START:
		ret = tdb_transaction_start(tdb) == 0 ? SUCCESS : OTHER_FAILURE;
		break;
	case FETCH:
		data = tdb_fetch(tdb, k);
		if (data.dptr == NULL) {
			if (tdb_error(tdb) == TDB_ERR_NOEXIST)
				ret = FAILED;
			else
				ret = OTHER_FAILURE;
		} else if (data.dsize != k.dsize
			   || memcmp(data.dptr, k.dptr, k.dsize) != 0) {
			ret = OTHER_FAILURE;
		} else {
			ret = SUCCESS;
		}
		free(data.dptr);
		break;
	case STORE:
		ret = tdb_store(tdb, k, k, 0) == 0 ? SUCCESS : OTHER_FAILURE;
		break;
	case TRANSACTION_COMMIT:
		ret = tdb_transaction_commit(tdb)==0 ? SUCCESS : OTHER_FAILURE;
		break;
	case CHECK:
		ret = tdb_check(tdb, NULL, NULL) == 0 ? SUCCESS : OTHER_FAILURE;
		break;
	case NEEDS_RECOVERY:
		ret = tdb_needs_recovery(tdb) ? SUCCESS : FAILED;
		break;
	case CLOSE:
		ret = tdb_close(tdb) == 0 ? SUCCESS : OTHER_FAILURE;
		tdb = NULL;
		break;
	case PING:
		ret = SUCCESS;
		break;
	case UNMAP:
		ret = tdb_munmap(tdb) == 0 ? SUCCESS : OTHER_FAILURE;
		if (ret == SUCCESS) {
			tdb->flags |= TDB_NOMMAP;
		}
		break;
	default:
		ret = OTHER_FAILURE;
	}

	if (locking_would_block)
		ret = WOULD_HAVE_BLOCKED;

	return ret;
}

struct agent {
	int cmdfd, responsefd;
	pid_t pid;
};

/* Do this before doing any tdb stuff.  Return handle, or NULL. */
struct agent *prepare_external_agent(void)
{
	int ret;
	int command[2], response[2];
	char name[1+PATH_MAX];
	struct agent *agent = malloc(sizeof(*agent));

	if (pipe(command) != 0 || pipe(response) != 0) {
		fprintf(stderr, "pipe failed: %s\n", strerror(errno));
		exit(1);
	}

	agent->pid = fork();
	if (agent->pid < 0) {
		fprintf(stderr, "fork failed: %s\n", strerror(errno));
		exit(1);
	}

	if (agent->pid != 0) {
		close(command[0]);
		close(response[1]);
		agent->cmdfd = command[1];
		agent->responsefd = response[0];
		return agent;
	}

	close(command[1]);
	close(response[0]);

	/* We want to fail, not block. */
	nonblocking_locks = true;
	log_prefix = "external: ";
	while ((ret = read(command[0], name, sizeof(name))) > 0) {
		enum agent_return result;

		result = do_operation(name[0], name+1);
		if (write(response[1], &result, sizeof(result))
		    != sizeof(result))
			abort();
	}
	exit(0);
}

void shutdown_agent(struct agent *agent)
{
	pid_t p;

	close(agent->cmdfd);
	close(agent->responsefd);
	p = waitpid(agent->pid, NULL, WNOHANG);
	if (p == 0) {
		kill(agent->pid, SIGKILL);
	}
	waitpid(agent->pid, NULL, 0);
	free(agent);
}

/* Ask the external agent to try to do an operation. */
enum agent_return external_agent_operation(struct agent *agent,
					   enum operation op,
					   const char *name)
{
	enum agent_return res;
	unsigned int len;
	char *string;

	if (!name)
		name = "";
	len = 1 + strlen(name) + 1;
	string = malloc(len);

	string[0] = op;
	strncpy(string+1, name, len - 1);
	string[len-1] = '\0';

	if (write(agent->cmdfd, string, len) != len
	    || read(agent->responsefd, &res, sizeof(res)) != sizeof(res))
		res = AGENT_DIED;

	free(string);
	return res;
}

const char *agent_return_name(enum agent_return ret)
{
	return ret == SUCCESS ? "SUCCESS"
		: ret == WOULD_HAVE_BLOCKED ? "WOULD_HAVE_BLOCKED"
		: ret == AGENT_DIED ? "AGENT_DIED"
		: ret == FAILED ? "FAILED"
		: ret == OTHER_FAILURE ? "OTHER_FAILURE"
		: "**INVALID**";
}

const char *operation_name(enum operation op)
{
	switch (op) {
	case OPEN: return "OPEN";
	case OPEN_WITH_CLEAR_IF_FIRST: return "OPEN_WITH_CLEAR_IF_FIRST";
	case TRANSACTION_START: return "TRANSACTION_START";
	case FETCH: return "FETCH";
	case STORE: return "STORE";
	case TRANSACTION_COMMIT: return "TRANSACTION_COMMIT";
	case CHECK: return "CHECK";
	case NEEDS_RECOVERY: return "NEEDS_RECOVERY";
	case CLOSE: return "CLOSE";
	case PING: return "PING";
	case UNMAP: return "UNMAP";
	}
	return "**INVALID**";
}
