#include "../common/tdb_private.h"
#include "lock-tracking.h"

#define fcntl fcntl_with_lockcheck

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
#include "logging.h"

#undef fcntl

#define NUM_ENTRIES 10

static bool prepare_entries(struct tdb_context *tdb)
{
	unsigned int i;
	TDB_DATA key, data;

	for (i = 0; i < NUM_ENTRIES; i++) {
		key.dsize = sizeof(i);
		key.dptr = (void *)&i;
		data.dsize = strlen("world");
		data.dptr = discard_const_p(uint8_t, "world");

		if (tdb_store(tdb, key, data, 0) != 0)
			return false;
	}
	return true;
}

static void delete_entries(struct tdb_context *tdb)
{
	unsigned int i;
	TDB_DATA key;

	for (i = 0; i < NUM_ENTRIES; i++) {
		key.dsize = sizeof(i);
		key.dptr = (void *)&i;

		ok1(tdb_delete(tdb, key) == 0);
	}
}

/* We don't know how many times this will run. */
static int delete_other(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data,
			void *private_data)
{
	unsigned int i;
	memcpy(&i, key.dptr, 4);
	i = (i + 1) % NUM_ENTRIES;
	key.dptr = (void *)&i;
	if (tdb_delete(tdb, key) != 0)
		(*(int *)private_data)++;
	return 0;
}

static int delete_self(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data,
			void *private_data)
{
	ok1(tdb_delete(tdb, key) == 0);
	return 0;
}

int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	int errors = 0;

	plan_tests(41);
	tdb = tdb_open_ex("run-no-lock-during-traverse.tdb",
			  1024, TDB_CLEAR_IF_FIRST, O_CREAT|O_TRUNC|O_RDWR,
			  0600, &taplogctx, NULL);

	ok1(tdb);
	ok1(prepare_entries(tdb));
	ok1(locking_errors == 0);
	ok1(tdb_lockall(tdb) == 0);
	ok1(locking_errors == 0);
	tdb_traverse(tdb, delete_other, &errors);
	ok1(errors == 0);
	ok1(locking_errors == 0);
	ok1(tdb_unlockall(tdb) == 0);

	ok1(prepare_entries(tdb));
	ok1(locking_errors == 0);
	ok1(tdb_lockall(tdb) == 0);
	ok1(locking_errors == 0);
	tdb_traverse(tdb, delete_self, NULL);
	ok1(locking_errors == 0);
	ok1(tdb_unlockall(tdb) == 0);

	ok1(prepare_entries(tdb));
	ok1(locking_errors == 0);
	ok1(tdb_lockall(tdb) == 0);
	ok1(locking_errors == 0);
	delete_entries(tdb);
	ok1(locking_errors == 0);
	ok1(tdb_unlockall(tdb) == 0);

	ok1(tdb_close(tdb) == 0);

	return exit_status();
}
