/*
   Unix SMB/CIFS implementation.
   simple tdb dump util
   Copyright (C) Andrew Tridgell              2001

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

#include "replace.h"
#include "system/locale.h"
#include "system/time.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "tdb.h"

static void print_data(TDB_DATA d)
{
	unsigned char *p = (unsigned char *)d.dptr;
	int len = d.dsize;
	while (len--) {
		if (isprint(*p) && !strchr("\"\\", *p)) {
			fputc(*p, stdout);
		} else {
			printf("\\%02X", *p);
		}
		p++;
	}
}

static int traverse_fn(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	printf("{\n");
	printf("key(%d) = \"", (int)key.dsize);
	print_data(key);
	printf("\"\n");
	printf("data(%d) = \"", (int)dbuf.dsize);
	print_data(dbuf);
	printf("\"\n");
	printf("}\n");
	return 0;
}

static void log_stderr(struct tdb_context *tdb, enum tdb_debug_level level,
		       const char *fmt, ...) PRINTF_ATTRIBUTE(3,4);

static void log_stderr(struct tdb_context *tdb, enum tdb_debug_level level,
		       const char *fmt, ...)
{
	va_list ap;
	const char *name = tdb_name(tdb);
	const char *prefix = "";

	if (!name)
		name = "unnamed";

	switch (level) {
	case TDB_DEBUG_ERROR:
		prefix = "ERROR: ";
		break;
	case TDB_DEBUG_WARNING:
		prefix = "WARNING: ";
		break;
	case TDB_DEBUG_TRACE:
		return;

	default:
	case TDB_DEBUG_FATAL:
		prefix = "FATAL: ";
		break;
	}

	va_start(ap, fmt);
	fprintf(stderr, "tdb(%s): %s", name, prefix);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void emergency_walk(TDB_DATA key, TDB_DATA dbuf, void *keyname)
{
	if (keyname) {
		if (key.dsize != strlen(keyname))
			return;
		if (memcmp(key.dptr, keyname, key.dsize) != 0)
			return;
	}
	traverse_fn(NULL, key, dbuf, NULL);
}

static int dump_tdb(const char *fname, const char *keyname, bool emergency)
{
	TDB_CONTEXT *tdb;
	TDB_DATA key, value;
	struct tdb_logging_context logfn = { log_stderr };
	int tdb_flags = TDB_DEFAULT;

	/*
	 * Note: that O_RDONLY implies TDB_NOLOCK, but we want to make it
	 * explicit as it's important when working on databases which were
	 * created with mutex locking.
	 */
	tdb_flags |= TDB_NOLOCK;

	tdb = tdb_open_ex(fname, 0, tdb_flags, O_RDONLY, 0, &logfn, NULL);
	if (!tdb) {
		printf("Failed to open %s\n", fname);
		return 1;
	}

	if (emergency) {
		return tdb_rescue(tdb, emergency_walk, discard_const(keyname)) == 0;
	}
	if (!keyname) {
		return tdb_traverse(tdb, traverse_fn, NULL) == -1 ? 1 : 0;
	} else {
		key.dptr = discard_const_p(uint8_t, keyname);
		key.dsize = strlen(keyname);
		value = tdb_fetch(tdb, key);
		if (!value.dptr) {
			return 1;
		} else {
			print_data(value);
			free(value.dptr);
		}
	}

	return 0;
}

static void usage( void)
{
	printf( "Usage: tdbdump [options] <filename>\n\n");
	printf( "   -h          this help message\n");
	printf( "   -k keyname  dumps value of keyname\n");
	printf( "   -e          emergency dump, for corrupt databases\n");
}

 int main(int argc, char *argv[])
{
	char *fname, *keyname=NULL;
	bool emergency = false;
	int c;

	if (argc < 2) {
		printf("Usage: tdbdump <fname>\n");
		exit(1);
	}

	while ((c = getopt( argc, argv, "hk:e")) != -1) {
		switch (c) {
		case 'h':
			usage();
			exit( 0);
		case 'k':
			keyname = optarg;
			break;
		case 'e':
			emergency = true;
			break;
		default:
			usage();
			exit( 1);
		}
	}

	fname = argv[optind];

	return dump_tdb(fname, keyname, emergency);
}
