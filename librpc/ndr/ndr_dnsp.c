/*
   Unix SMB/CIFS implementation.

   Manually parsed structures found in DNSP

   Copyright (C) Andrew Tridgell 2010

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
#include "librpc/gen_ndr/ndr_dnsp.h"

/*
  print a dnsp_name
*/
_PUBLIC_ void ndr_print_dnsp_name(struct ndr_print *ndr, const char *name,
				  const char *dns_name)
{
	ndr->print(ndr, "%-25s: %s", name, dns_name);
}

/*
  pull a dnsp_name
*/
_PUBLIC_ enum ndr_err_code ndr_pull_dnsp_name(struct ndr_pull *ndr, int ndr_flags, const char **name)
{
	uint8_t len, count, termination;
	int i;
	uint32_t total_len, raw_offset;
	char *ret;

	NDR_CHECK(ndr_pull_uint8(ndr, ndr_flags, &len));
	NDR_CHECK(ndr_pull_uint8(ndr, ndr_flags, &count));

	raw_offset = ndr->offset;

	ret = talloc_strdup(ndr->current_mem_ctx, "");
	if (!ret) {
		return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Failed to pull dnsp_name");
	}
	total_len = 1;

	for (i=0; i<count; i++) {
		uint8_t sublen, newlen;
		NDR_CHECK(ndr_pull_uint8(ndr, ndr_flags, &sublen));
		newlen = total_len + sublen;
		if (i != count-1) {
			newlen++; /* for the '.' */
		}
		ret = talloc_realloc(ndr->current_mem_ctx, ret, char, newlen);
		if (!ret) {
			return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Failed to pull dnsp_name");
		}
		NDR_CHECK(ndr_pull_bytes(ndr, (uint8_t *)&ret[total_len-1], sublen));
		if (i != count-1) {
			ret[newlen-2] = '.';
		}
		ret[newlen-1] = 0;
		total_len = newlen;
	}
	NDR_CHECK(ndr_pull_uint8(ndr, ndr_flags, &termination));
	if (termination != 0) {
		return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Failed to pull dnsp_name - not NUL terminated");
	}
	if (ndr->offset > raw_offset + len) {
		return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Failed to pull dnsp_name - overrun by %u bytes",
				      ndr->offset - (raw_offset + len));
	}
	/* there could be additional pad bytes */
	while (ndr->offset < raw_offset + len) {
		uint8_t pad;
		NDR_CHECK(ndr_pull_uint8(ndr, ndr_flags, &pad));
	}
	(*name) = ret;
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_dnsp_name(struct ndr_push *ndr, int ndr_flags, const char *name)
{
	int count, total_len, i;

	/* count the dots */
	for (count=i=0; name[i]; i++) {
		if (name[i] == '.') count++;
	}
	total_len = strlen(name) + 1;

	/* cope with names ending in '.' */
	if (name[strlen(name)-1] != '.') {
		total_len++;
		count++;
	}
	if (total_len > 255 || count > 255) {
		return ndr_push_error(ndr, NDR_ERR_BUFSIZE,
				      "dns_name of length %d larger than 255", total_len);
	}
	NDR_CHECK(ndr_push_uint8(ndr, ndr_flags, (uint8_t)total_len));
	NDR_CHECK(ndr_push_uint8(ndr, ndr_flags, (uint8_t)count));
	for (i=0; i<count; i++) {
		const char *p = strchr(name, '.');
		size_t sublen = p?(p-name):strlen(name);
		NDR_CHECK(ndr_push_uint8(ndr, ndr_flags, (uint8_t)sublen));
		NDR_CHECK(ndr_push_bytes(ndr, (const uint8_t *)name, sublen));
		name += sublen + 1;
	}
	NDR_CHECK(ndr_push_uint8(ndr, ndr_flags, 0));

	return NDR_ERR_SUCCESS;
}

/*
  print a dnsp_string
*/
_PUBLIC_ void ndr_print_dnsp_string(struct ndr_print *ndr, const char *name,
				    const char *dns_string)
{
	ndr->print(ndr, "%-25s: %s", name, dns_string);
}

/*
  pull a dnsp_string
*/
_PUBLIC_ enum ndr_err_code ndr_pull_dnsp_string(struct ndr_pull *ndr, int ndr_flags, const char **string)
{
	uint8_t len;
	char *ret;

	NDR_CHECK(ndr_pull_uint8(ndr, ndr_flags, &len));

	ret = talloc_zero_array(ndr->current_mem_ctx, char, len + 1);
	if (!ret) {
		return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Failed to pull dnsp_string");
	}
	NDR_CHECK(ndr_pull_bytes(ndr, (uint8_t *)ret, len));

	(*string) = ret;
	NDR_PULL_ALIGN(ndr, 1);
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_dnsp_string(struct ndr_push *ndr, int ndr_flags, const char *string)
{
	int total_len;
	total_len = strlen(string);
	if (total_len > 255) {
		return ndr_push_error(ndr, NDR_ERR_BUFSIZE,
				      "dns_name of length %d larger than 255", total_len);
	}
	NDR_CHECK(ndr_push_uint8(ndr, ndr_flags, (uint8_t)total_len));
	NDR_CHECK(ndr_push_bytes(ndr, (const uint8_t *)string, total_len));

	return NDR_ERR_SUCCESS;
}

/*
 * print a dnsp_string_list
 */
_PUBLIC_ void ndr_print_dnsp_string_list(struct ndr_print *ndr, const char *name,
					 const struct dnsp_string_list *list)
{
	uint32_t i;

	ndr->no_newline = true;
	for (i=0; i<ndr->depth; i++) {
		ndr->print(ndr, "    ");
	}
	ndr->print(ndr, "%-25s:", name);
	for (i=0; i<list->count; i++) {
		ndr->print(ndr, " \"%s\"", list->str[i]);
	}
	ndr->print(ndr, "\n");
	ndr->no_newline = false;
}

/*
 * pull a dnsp_string_list
 */
_PUBLIC_ enum ndr_err_code ndr_pull_dnsp_string_list(struct ndr_pull *ndr, int ndr_flags, struct dnsp_string_list *list)
{
	list->count = 0;
	list->str = talloc_array(ndr->current_mem_ctx, const char *,
				 list->count);
	if (! list->str) {
		return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Failed to pull dnsp_string_list");
	}

	while (ndr->offset < ndr->data_size) {
		list->str = talloc_realloc(ndr->current_mem_ctx, list->str,
					   const char *, list->count+1);
		if (! list->str) {
			return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Failed to pull dnsp_string_list");
		}
		NDR_CHECK(ndr_pull_dnsp_string(ndr, ndr_flags, &list->str[list->count]));
		list->count++;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_dnsp_string_list(struct ndr_push *ndr, int ndr_flags, const struct dnsp_string_list *list)
{
	uint8_t i;

	for (i=0; i<list->count; i++) {
		NDR_CHECK(ndr_push_dnsp_string(ndr, ndr_flags, list->str[i]));
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_dnsp_string_list_copy(TALLOC_CTX *mem_ctx,
					    const struct dnsp_string_list *src,
					    struct dnsp_string_list *dst)
{
	size_t i;

	dst->count = 0;
	dst->str = talloc_zero_array(mem_ctx, const char *, src->count);
	if (dst->str == NULL) {
		return NDR_ERR_ALLOC;
	}

	for (i = 0; i < src->count; i++) {
		dst->str[i] = talloc_strdup(dst->str, src->str[i]);
		if (dst->str[i] == NULL) {
			TALLOC_FREE(dst->str);
			return NDR_ERR_ALLOC;
		}
	}

	dst->count = src->count;
	return NDR_ERR_SUCCESS;
}
