/*
 *  Unix SMB/CIFS implementation.
 *
 *  getpass.c - platform independent getpass function.
 *
 *  Copyright (c) 2010-2012 Andreas Schneider <asn@samba.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#include "system/filesys.h"
#include "system/terminal.h"

#if !defined(SMB_MALLOC)
#undef malloc
#define SMB_MALLOC(s) malloc((s))
#endif

/**
 * @internal
 *
 * @brief Get the password from the console.
 *
 * @param[in]  prompt   The prompt to display.
 *
 * @param[in]  buf      The buffer to fill.
 *
 * @param[in]  len      The length of the buffer.
 *
 * @param[in]  verify   Should the password be verified?
 *
 * @return              1 on success, 0 on error.
 */
static int samba_gets(const char *prompt, char *buf, size_t len, bool verify)
{
	char *tmp;
	char *ptr = NULL;
	int ok = 0;

	tmp = SMB_MALLOC(len);
	if (tmp == NULL) {
		return 0;
	}
	memset(tmp,'\0',len);

	/* read the password */
	while (!ok) {
		if (buf[0] != '\0') {
			fprintf(stdout, "%s[%s] ", prompt, buf);
		} else {
			fprintf(stdout, "%s", prompt);
		}
		fflush(stdout);
		if (fgets(tmp, len, stdin) == NULL) {
			free(tmp);
			return 0;
		}

		if ((ptr = strchr(tmp, '\n'))) {
			*ptr = '\0';
		}
		fprintf(stdout, "\n");

		if (*tmp) {
			strncpy(buf, tmp, len);
		}

		if (verify) {
			char *key_string;

			key_string = SMB_MALLOC(len);
			if (key_string == NULL) {
				break;
			}
			memset(key_string, '\0', len);

			fprintf(stdout, "\nVerifying, please re-enter. %s", prompt);
			fflush(stdout);
			if (! fgets(key_string, len, stdin)) {
				memset(key_string, '\0', len);
				SAFE_FREE(key_string);
				clearerr(stdin);
				continue;
			}
			if ((ptr = strchr(key_string, '\n'))) {
				*ptr = '\0';
			}
			fprintf(stdout, "\n");
			if (strcmp(buf, key_string)) {
				printf("\n\07\07Mismatch - try again\n");
				memset(key_string, '\0', len);
				SAFE_FREE(key_string);
				fflush(stdout);
				continue;
			}
			memset(key_string, '\0', len);
			SAFE_FREE(key_string);
		}
		ok = 1;
	}
	memset(tmp, '\0', len);
	free(tmp);

	return ok;
}

/**
 * @brief Get a password from the console.
 *
 * You should make sure that the buffer is an empty string!
 *
 * You can also use this function to ask for a username. Then you can fill the
 * buffer with the username and it is shows to the users. If the users just
 * presses enter the buffer will be untouched.
 *
 * @code
 *   char username[128];
 *
 *   snprintf(username, sizeof(username), "john");
 *
 *   samba_getpass("Username:", username, sizeof(username), 1, 0);
 * @endcode
 *
 * The prompt will look like this:
 *
 *   Username: [john]
 *
 * If you press enter then john is used as the username, or you can type it in
 * to change it.
 *
 * @param[in]  prompt   The prompt to show to ask for the password.
 *
 * @param[out] buf    The buffer the password should be stored. It NEEDS to be
 *                      empty or filled out.
 *
 * @param[in]  len      The length of the buffer.
 *
 * @param[in]  echo     Should we echo what you type.
 *
 * @param[in]  verify   Should we ask for the password twice.
 *
 * @return              0 on success, -1 on error.
 */
int samba_getpass(const char *prompt,
		  char *buf,
		  size_t len,
		  bool echo,
		  bool verify)
{
	struct termios attr;
	struct termios old_attr;
	int ok = 0;
	int fd = -1;

	/* fgets needs at least len - 1 */
	if (prompt == NULL || buf == NULL || len < 2) {
		return -1;
	}

	if (isatty (STDIN_FILENO)) {

		ZERO_STRUCT(attr);
		ZERO_STRUCT(old_attr);

		/* get local terminal attributes */
		if (tcgetattr(STDIN_FILENO, &attr) < 0) {
			perror("tcgetattr");
			return -1;
		}

		/* save terminal attributes */
		memcpy(&old_attr, &attr, sizeof(attr));
		if((fd = fcntl(0, F_GETFL, 0)) < 0) {
			perror("fcntl");
			return -1;
		}

		/* disable echo */
		if (!echo) {
			attr.c_lflag &= ~(ECHO);
		}

		/* write attributes to terminal */
		if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &attr) < 0) {
			perror("tcsetattr");
			return -1;
		}
	}

	/* disable nonblocking I/O */
	if (fd & O_NDELAY) {
		fcntl(0, F_SETFL, fd & ~O_NDELAY);
	}

	ok = samba_gets(prompt, buf, len, verify);

	if (isatty (STDIN_FILENO)) {

		/* reset terminal */
		tcsetattr(STDIN_FILENO, TCSANOW, &old_attr);
	}

	/* close fd */
	if (fd & O_NDELAY) {
		fcntl(0, F_SETFL, fd);
	}

	if (!ok) {
		memset (buf, '\0', len);
		return -1;
	}

	/* force termination */
	buf[len - 1] = '\0';

	return 0;
}
