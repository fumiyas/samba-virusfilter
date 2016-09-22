/*
   Unix SMB/CIFS implementation.
   Database interface wrapper: local open code.

   Copyright (C) Rusty Russell 2012

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
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_tdb.h"
#include "tdb.h"
#include "lib/param/param.h"

struct db_context *dbwrap_local_open(TALLOC_CTX *mem_ctx,
				     struct loadparm_context *lp_ctx,
				     const char *name,
				     int hash_size, int tdb_flags,
				     int open_flags, mode_t mode,
				     enum dbwrap_lock_order lock_order,
				     uint64_t dbwrap_flags)
{
	struct db_context *db = NULL;

	if (hash_size == 0) {
		hash_size = lpcfg_tdb_hash_size(lp_ctx, name);
	}

	db = db_open_tdb(mem_ctx, name, hash_size,
			 lpcfg_tdb_flags(lp_ctx, tdb_flags),
			 open_flags, mode,
			 lock_order, dbwrap_flags);

	return db;
}
