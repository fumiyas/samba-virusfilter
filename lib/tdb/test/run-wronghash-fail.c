#include "../common/tdb_private.h"
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

static void log_fn(struct tdb_context *tdb, enum tdb_debug_level level, const char *fmt, ...)
{
	unsigned int *count = tdb_get_logging_private(tdb);
	if (strstr(fmt, "hash"))
		(*count)++;
}

int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	unsigned int log_count;
	TDB_DATA d;
	struct tdb_logging_context log_ctx = { log_fn, &log_count };

	plan_tests(28);

	/* Create with default hash. */
	log_count = 0;
	tdb = tdb_open_ex("run-wronghash-fail.tdb", 0, 0,
			  O_CREAT|O_RDWR|O_TRUNC, 0600, &log_ctx, NULL);
	ok1(tdb);
	ok1(log_count == 0);
	d.dptr = discard_const_p(uint8_t, "Hello");
	d.dsize = 5;
	ok1(tdb_store(tdb, d, d, TDB_INSERT) == 0);
	tdb_close(tdb);

	/* Fail to open with different hash. */
	tdb = tdb_open_ex("run-wronghash-fail.tdb", 0, 0, O_RDWR, 0,
			  &log_ctx, tdb_jenkins_hash);
	ok1(!tdb);
	ok1(log_count == 1);

	/* Create with different hash. */
	log_count = 0;
	tdb = tdb_open_ex("run-wronghash-fail.tdb", 0, 0,
			  O_CREAT|O_RDWR|O_TRUNC,
			  0600, &log_ctx, tdb_jenkins_hash);
	ok1(tdb);
	ok1(log_count == 0);
	tdb_close(tdb);

	/* Endian should be no problem. */
	log_count = 0;
	tdb = tdb_open_ex("test/jenkins-le-hash.tdb", 0, 0, O_RDWR, 0,
			  &log_ctx, tdb_old_hash);
	ok1(!tdb);
	ok1(log_count == 1);

	log_count = 0;
	tdb = tdb_open_ex("test/jenkins-be-hash.tdb", 0, 0, O_RDWR, 0,
			  &log_ctx, tdb_old_hash);
	ok1(!tdb);
	ok1(log_count == 1);

	log_count = 0;
	/* Fail to open with old default hash. */
	tdb = tdb_open_ex("run-wronghash-fail.tdb", 0, 0, O_RDWR, 0,
			  &log_ctx, tdb_old_hash);
	ok1(!tdb);
	ok1(log_count == 1);

	log_count = 0;
	tdb = tdb_open_ex("test/jenkins-le-hash.tdb", 0, 0, O_RDONLY,
			  0, &log_ctx, tdb_jenkins_hash);
	ok1(tdb);
	ok1(log_count == 0);
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);

	log_count = 0;
	tdb = tdb_open_ex("test/jenkins-be-hash.tdb", 0, 0, O_RDONLY,
			  0, &log_ctx, tdb_jenkins_hash);
	ok1(tdb);
	ok1(log_count == 0);
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);

	/* It should open with jenkins hash if we don't specify. */
	log_count = 0;
	tdb = tdb_open_ex("test/jenkins-le-hash.tdb", 0, 0, O_RDWR, 0,
			  &log_ctx, NULL);
	ok1(tdb);
	ok1(log_count == 0);
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);

	log_count = 0;
	tdb = tdb_open_ex("test/jenkins-be-hash.tdb", 0, 0, O_RDWR, 0,
			  &log_ctx, NULL);
	ok1(tdb);
	ok1(log_count == 0);
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);

	log_count = 0;
	tdb = tdb_open_ex("run-wronghash-fail.tdb", 0, 0, O_RDONLY,
			  0, &log_ctx, NULL);
	ok1(tdb);
	ok1(log_count == 0);
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);


	return exit_status();
}
