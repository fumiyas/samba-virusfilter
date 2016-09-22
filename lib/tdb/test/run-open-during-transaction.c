#include "../common/tdb_private.h"
#include "lock-tracking.h"

static ssize_t pwrite_check(int fd, const void *buf, size_t count, off_t offset);
static ssize_t write_check(int fd, const void *buf, size_t count);
static int ftruncate_check(int fd, off_t length);

#define pwrite pwrite_check
#define write write_check
#define fcntl fcntl_with_lockcheck
#define ftruncate ftruncate_check

#include "../common/io.c"
#include "../common/tdb.c"
#include "../common/lock.c"
#include "../common/freelist.c"
#include "../common/traverse.c"
#include "../common/transaction.c"
#include "../common/error.c"
#include "../common/open.c"
#include "../common/check.c"
#include "../common/hash.c"
#include "../common/mutex.c"
#include "tap-interface.h"
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include "external-agent.h"
#include "logging.h"

static struct agent *agent;
static bool opened;
static int errors = 0;
static bool clear_if_first;
#define TEST_DBNAME "run-open-during-transaction.tdb"

#undef write
#undef pwrite
#undef fcntl
#undef ftruncate

static bool is_same(const char *snapshot, const char *latest, off_t len)
{
	unsigned i;

	for (i = 0; i < len; i++) {
		if (snapshot[i] != latest[i])
			return false;
	}
	return true;
}

static bool compare_file(int fd, const char *snapshot, off_t snapshot_len)
{
	char *contents;
	bool same;

	/* over-length read serves as length check. */
	contents = malloc(snapshot_len+1);
	same = pread(fd, contents, snapshot_len+1, 0) == snapshot_len
		&& is_same(snapshot, contents, snapshot_len);
	free(contents);
	return same;
}

static void check_file_intact(int fd)
{
	enum agent_return ret;
	struct stat st;
	char *contents;

	fstat(fd, &st);
	contents = malloc(st.st_size);
	if (pread(fd, contents, st.st_size, 0) != st.st_size) {
		diag("Read fail");
		errors++;
		free(contents);
		return;
	}

	/* Ask agent to open file. */
	ret = external_agent_operation(agent, clear_if_first ?
				       OPEN_WITH_CLEAR_IF_FIRST :
				       OPEN,
				       TEST_DBNAME);

	/* It's OK to open it, but it must not have changed! */
	if (!compare_file(fd, contents, st.st_size)) {
		diag("Agent changed file after opening %s",
		     agent_return_name(ret));
		errors++;
	}

	if (ret == SUCCESS) {
		ret = external_agent_operation(agent, CLOSE, NULL);
		if (ret != SUCCESS) {
			diag("Agent failed to close tdb: %s",
			     agent_return_name(ret));
			errors++;
		}
	} else if (ret != WOULD_HAVE_BLOCKED) {
		diag("Agent opening file gave %s",
		     agent_return_name(ret));
		errors++;
	}

	free(contents);
}

static void after_unlock(int fd)
{
	if (opened)
		check_file_intact(fd);
}

static ssize_t pwrite_check(int fd,
			    const void *buf, size_t count, off_t offset)
{
	if (opened)
		check_file_intact(fd);

	return pwrite(fd, buf, count, offset);
}

static ssize_t write_check(int fd, const void *buf, size_t count)
{
	if (opened)
		check_file_intact(fd);

	return write(fd, buf, count);
}

static int ftruncate_check(int fd, off_t length)
{
	if (opened)
		check_file_intact(fd);

	return ftruncate(fd, length);

}

int main(int argc, char *argv[])
{
	const int flags[] = { TDB_DEFAULT,
			      TDB_CLEAR_IF_FIRST,
			      TDB_NOMMAP,
			      TDB_CLEAR_IF_FIRST | TDB_NOMMAP };
	int i;
	struct tdb_context *tdb;
	TDB_DATA key, data;

	plan_tests(20);
	agent = prepare_external_agent();

	unlock_callback = after_unlock;
	for (i = 0; i < sizeof(flags)/sizeof(flags[0]); i++) {
		clear_if_first = (flags[i] & TDB_CLEAR_IF_FIRST);
		diag("Test with %s and %s",
		     clear_if_first ? "CLEAR" : "DEFAULT",
		     (flags[i] & TDB_NOMMAP) ? "no mmap" : "mmap");
		unlink(TEST_DBNAME);
		tdb = tdb_open_ex(TEST_DBNAME, 1024, flags[i],
				  O_CREAT|O_TRUNC|O_RDWR, 0600,
				  &taplogctx, NULL);
		ok1(tdb);

		opened = true;
		ok1(tdb_transaction_start(tdb) == 0);
		key.dsize = strlen("hi");
		key.dptr = discard_const_p(uint8_t, "hi");
		data.dptr = discard_const_p(uint8_t, "world");
		data.dsize = strlen("world");

		ok1(tdb_store(tdb, key, data, TDB_INSERT) == 0);
		ok1(tdb_transaction_commit(tdb) == 0);
		ok(!errors, "We had %u open errors", errors);

		opened = false;
		tdb_close(tdb);
	}

	return exit_status();
}
