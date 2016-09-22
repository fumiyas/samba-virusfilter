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

static unsigned int tdb_dumb_hash(TDB_DATA *key)
{
	return key->dsize;
}

static void log_fn(struct tdb_context *tdb, enum tdb_debug_level level, const char *fmt, ...)
{
	unsigned int *count = tdb_get_logging_private(tdb);
	if (strstr(fmt, "hash"))
		(*count)++;
}

static unsigned int hdr_rwlocks(const char *fname)
{
	struct tdb_header hdr;
	ssize_t nread;

	int fd = open(fname, O_RDONLY);
	if (fd == -1)
		return -1;

	nread = read(fd, &hdr, sizeof(hdr));
	close(fd);
	if (nread != sizeof(hdr)) {
		return -1;
	}
	return hdr.rwlocks;
}

int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	unsigned int log_count, flags;
	TDB_DATA d, r;
	struct tdb_logging_context log_ctx = { log_fn, &log_count };

	plan_tests(38 * 2);

	for (flags = 0; flags <= TDB_CONVERT; flags += TDB_CONVERT) {
		unsigned int rwmagic = TDB_HASH_RWLOCK_MAGIC;

		if (flags & TDB_CONVERT)
			tdb_convert(&rwmagic, sizeof(rwmagic));

		/* Create an old-style hash. */
		log_count = 0;
		tdb = tdb_open_ex("run-incompatible.tdb", 0, flags,
				  O_CREAT|O_RDWR|O_TRUNC, 0600, &log_ctx,
				  NULL);
		ok1(tdb);
		ok1(log_count == 0);
		d.dptr = discard_const_p(uint8_t, "Hello");
		d.dsize = 5;
		ok1(tdb_store(tdb, d, d, TDB_INSERT) == 0);
		tdb_close(tdb);

		/* Should not have marked rwlocks field. */
		ok1(hdr_rwlocks("run-incompatible.tdb") == 0);

		/* We can still open any old-style with incompat flag. */
		log_count = 0;
		tdb = tdb_open_ex("run-incompatible.tdb", 0,
				  TDB_INCOMPATIBLE_HASH,
				  O_RDWR, 0600, &log_ctx, NULL);
		ok1(tdb);
		ok1(log_count == 0);
		r = tdb_fetch(tdb, d);
		ok1(r.dsize == 5);
		free(r.dptr);
		ok1(tdb_check(tdb, NULL, NULL) == 0);
		tdb_close(tdb);

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

		/* OK, now create with incompatible flag, default hash. */
		log_count = 0;
		tdb = tdb_open_ex("run-incompatible.tdb", 0,
				  flags|TDB_INCOMPATIBLE_HASH,
				  O_CREAT|O_RDWR|O_TRUNC, 0600, &log_ctx,
				  NULL);
		ok1(tdb);
		ok1(log_count == 0);
		d.dptr = discard_const_p(uint8_t, "Hello");
		d.dsize = 5;
		ok1(tdb_store(tdb, d, d, TDB_INSERT) == 0);
		tdb_close(tdb);

		/* Should have marked rwlocks field. */
		ok1(hdr_rwlocks("run-incompatible.tdb") == rwmagic);

		/* Cannot open with old hash. */
		log_count = 0;
		tdb = tdb_open_ex("run-incompatible.tdb", 0, 0,
				  O_RDWR, 0600, &log_ctx, tdb_old_hash);
		ok1(!tdb);
		ok1(log_count == 1);

		/* Can open with jenkins hash. */
		log_count = 0;
		tdb = tdb_open_ex("run-incompatible.tdb", 0, 0,
				  O_RDWR, 0600, &log_ctx, tdb_jenkins_hash);
		ok1(tdb);
		ok1(log_count == 0);
		r = tdb_fetch(tdb, d);
		ok1(r.dsize == 5);
		free(r.dptr);
		ok1(tdb_check(tdb, NULL, NULL) == 0);
		tdb_close(tdb);

		/* Can open by letting it figure it out itself. */
		log_count = 0;
		tdb = tdb_open_ex("run-incompatible.tdb", 0, 0,
				  O_RDWR, 0600, &log_ctx, NULL);
		ok1(tdb);
		ok1(log_count == 0);
		r = tdb_fetch(tdb, d);
		ok1(r.dsize == 5);
		free(r.dptr);
		ok1(tdb_check(tdb, NULL, NULL) == 0);
		tdb_close(tdb);

		/* We can also use incompatible hash with other hashes. */
		log_count = 0;
		tdb = tdb_open_ex("run-incompatible.tdb", 0,
				  flags|TDB_INCOMPATIBLE_HASH,
				  O_CREAT|O_RDWR|O_TRUNC, 0600, &log_ctx,
				  tdb_dumb_hash);
		ok1(tdb);
		ok1(log_count == 0);
		d.dptr = discard_const_p(uint8_t, "Hello");
		d.dsize = 5;
		ok1(tdb_store(tdb, d, d, TDB_INSERT) == 0);
		tdb_close(tdb);

		/* Should have marked rwlocks field. */
		ok1(hdr_rwlocks("run-incompatible.tdb") == rwmagic);

		/* It should not open if we don't specify. */
		log_count = 0;
		tdb = tdb_open_ex("run-incompatible.tdb", 0, 0, O_RDWR, 0,
				  &log_ctx, NULL);
		ok1(!tdb);
		ok1(log_count == 1);

		/* Should reopen with correct hash. */
		log_count = 0;
		tdb = tdb_open_ex("run-incompatible.tdb", 0, 0, O_RDWR, 0,
				  &log_ctx, tdb_dumb_hash);
		ok1(tdb);
		ok1(log_count == 0);
		r = tdb_fetch(tdb, d);
		ok1(r.dsize == 5);
		free(r.dptr);
		ok1(tdb_check(tdb, NULL, NULL) == 0);
		tdb_close(tdb);
	}

	return exit_status();
}
