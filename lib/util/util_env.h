/*
   Unix SMB/CIFS implementation.
   environtment variable handle for execle
   Copyright (C) 2010-2016 SATOH Fumiyasu @ OSS Technology Corp., Japan

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

typedef struct {
	char		**env_list;
	size_t		env_size;
	size_t		env_num;
} env_struct;

/* Environment variable handling for execle(2) */
env_struct *env_new(TALLOC_CTX *ctx);
char * const *env_list(env_struct *env_h);
int env_set(env_struct *env_h, const char *name, const char *value);

