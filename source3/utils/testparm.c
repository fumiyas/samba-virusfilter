/* 
   Unix SMB/CIFS implementation.
   Test validity of smb.conf
   Copyright (C) Karl Auer 1993, 1994-1998

   Extensively modified by Andrew Tridgell, 1995
   Converted to popt by Jelmer Vernooij (jelmer@nl.linux.org), 2002
   
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

/*
 * Testbed for loadparm.c/params.c
 *
 * This module simply loads a specified configuration file and
 * if successful, dumps it's contents to stdout. Note that the
 * operation is performed with DEBUGLEVEL at 3.
 *
 * Useful for a quick 'syntax check' of a configuration file.
 *
 */

#include "includes.h"
#include "system/filesys.h"
#include "popt_common.h"
#include "lib/param/loadparm.h"

/*******************************************************************
 Check if a directory exists.
********************************************************************/

static bool directory_exist_stat(const char *dname,SMB_STRUCT_STAT *st)
{
	SMB_STRUCT_STAT st2;
	bool ret;

	if (!st)
		st = &st2;

	if (sys_stat(dname, st, false) != 0)
		return(False);

	ret = S_ISDIR(st->st_ex_mode);
	if(!ret)
		errno = ENOTDIR;
	return ret;
}

/***********************************************
 Here we do a set of 'hard coded' checks for bad
 configuration settings.
************************************************/

static int do_global_checks(void)
{
	int ret = 0;
	SMB_STRUCT_STAT st;
	const char *socket_options;

	if (lp_security() >= SEC_DOMAIN && !lp_encrypt_passwords()) {
		fprintf(stderr, "ERROR: in 'security=domain' mode the "
				"'encrypt passwords' parameter must always be "
				"set to 'true'.\n\n");
		ret = 1;
	}

	if (lp_we_are_a_wins_server() && lp_wins_server_list()) {
		fprintf(stderr, "ERROR: both 'wins support = true' and "
				"'wins server = <server list>' cannot be set in "
				"the smb.conf file. nmbd will abort with this "
				"setting.\n\n");
		ret = 1;
	}

	if (strequal(lp_workgroup(), lp_netbios_name())) {
		fprintf(stderr, "WARNING: 'workgroup' and 'netbios name' "
				"must differ.\n\n");
	}

	if (strlen(lp_netbios_name()) > 15) {
		fprintf(stderr, "WARNING: The 'netbios name' is too long "
				"(max. 15 chars).\n\n");
	}

	if (!directory_exist_stat(lp_lock_directory(), &st)) {
		fprintf(stderr, "ERROR: lock directory %s does not exist\n\n",
		       lp_lock_directory());
		ret = 1;
	} else if ((st.st_ex_mode & 0777) != 0755) {
		fprintf(stderr, "WARNING: lock directory %s should have "
				"permissions 0755 for browsing to work\n\n",
		       lp_lock_directory());
	}

	if (!directory_exist_stat(lp_state_directory(), &st)) {
		fprintf(stderr, "ERROR: state directory %s does not exist\n\n",
		       lp_state_directory());
		ret = 1;
	} else if ((st.st_ex_mode & 0777) != 0755) {
		fprintf(stderr, "WARNING: state directory %s should have "
				"permissions 0755 for browsing to work\n\n",
		       lp_state_directory());
	}

	if (!directory_exist_stat(lp_cache_directory(), &st)) {
		fprintf(stderr, "ERROR: cache directory %s does not exist\n\n",
		       lp_cache_directory());
		ret = 1;
	} else if ((st.st_ex_mode & 0777) != 0755) {
		fprintf(stderr, "WARNING: cache directory %s should have "
				"permissions 0755 for browsing to work\n\n",
		       lp_cache_directory());
	}

	if (!directory_exist_stat(lp_pid_directory(), &st)) {
		fprintf(stderr, "ERROR: pid directory %s does not exist\n\n",
		       lp_pid_directory());
		ret = 1;
	}

	if (lp_passdb_expand_explicit()) {
		fprintf(stderr, "WARNING: passdb expand explicit = yes is "
				"deprecated\n\n");
	}

	/*
	 * Socket options.
	 */
	socket_options = lp_socket_options();
	if (socket_options != NULL &&
	    (strstr(socket_options, "SO_SNDBUF") ||
	     strstr(socket_options, "SO_RCVBUF") ||
	     strstr(socket_options, "SO_SNDLOWAT") ||
	     strstr(socket_options, "SO_RCVLOWAT")))
	{
		fprintf(stderr,
			"WARNING: socket options = %s\n"
			"This warning is printed because you set one of the\n"
			"following options: SO_SNDBUF, SO_RCVBUF, SO_SNDLOWAT,\n"
			"SO_RCVLOWAT\n"
			"Modern server operating systems are tuned for\n"
			"high network performance in the majority of situations;\n"
			"when you set 'socket options' you are overriding those\n"
			"settings.\n"
			"Linux in particular has an auto-tuning mechanism for\n"
			"buffer sizes (SO_SNDBUF, SO_RCVBUF) that will be\n"
			"disabled if you specify a socket buffer size. This can\n"
			"potentially cripple your TCP/IP stack.\n\n"
			"Getting the 'socket options' correct can make a big\n"
			"difference to your performance, but getting them wrong\n"
			"can degrade it by just as much. As with any other low\n"
			"level setting, if you must make changes to it, make\n "
			"small changes and test the effect before making any\n"
			"large changes.\n\n",
			socket_options);
	}

	/*
	 * Password server sanity checks.
	 */

	if((lp_security() >= SEC_DOMAIN) && !*lp_password_server()) {
		const char *sec_setting;
		if(lp_security() == SEC_DOMAIN)
			sec_setting = "domain";
		else if(lp_security() == SEC_ADS)
			sec_setting = "ads";
		else
			sec_setting = "";

		fprintf(stderr, "ERROR: The setting 'security=%s' requires the "
				"'password server' parameter be set to the "
				"default value * or a valid password server.\n\n",
				sec_setting );
		ret = 1;
	}

	if((lp_security() >= SEC_DOMAIN) && (strcmp(lp_password_server(), "*") != 0)) {
		const char *sec_setting;
		if(lp_security() == SEC_DOMAIN)
			sec_setting = "domain";
		else if(lp_security() == SEC_ADS)
			sec_setting = "ads";
		else
			sec_setting = "";

		fprintf(stderr, "WARNING: The setting 'security=%s' should NOT "
				"be combined with the 'password server' "
				"parameter.\n"
				"(by default Samba will discover the correct DC "
				"to contact automatically).\n\n",
				sec_setting );
	}

	/*
	 * Password chat sanity checks.
	 */

	if(lp_security() == SEC_USER && lp_unix_password_sync()) {

		/*
		 * Check that we have a valid lp_passwd_program() if not using pam.
		 */

#ifdef WITH_PAM
		if (!lp_pam_password_change()) {
#endif

			if((lp_passwd_program(talloc_tos()) == NULL) ||
			   (strlen(lp_passwd_program(talloc_tos())) == 0))
			{
				fprintf(stderr,
					"ERROR: the 'unix password sync' "
					"parameter is set and there is no valid "
					"'passwd program' parameter.\n\n");
				ret = 1;
			} else {
				const char *passwd_prog;
				char *truncated_prog = NULL;
				const char *p;

				passwd_prog = lp_passwd_program(talloc_tos());
				p = passwd_prog;
				next_token_talloc(talloc_tos(),
						&p,
						&truncated_prog, NULL);
				if (truncated_prog && access(truncated_prog, F_OK) == -1) {
					fprintf(stderr,
						"ERROR: the 'unix password sync' "
						"parameter is set and the "
						"'passwd program' (%s) cannot be "
						"executed (error was %s).\n\n",
						truncated_prog,
						strerror(errno));
					ret = 1;
				}
			}

#ifdef WITH_PAM
		}
#endif

		if(lp_passwd_chat(talloc_tos()) == NULL) {
			fprintf(stderr,
				"ERROR: the 'unix password sync' parameter is "
				"set and there is no valid 'passwd chat' "
				"parameter.\n\n");
			ret = 1;
		}

		if ((lp_passwd_program(talloc_tos()) != NULL) &&
		    (strlen(lp_passwd_program(talloc_tos())) > 0))
		{
			/* check if there's a %u parameter present */
			if(strstr_m(lp_passwd_program(talloc_tos()), "%u") == NULL) {
				fprintf(stderr,
					"ERROR: the 'passwd program' (%s) "
					"requires a '%%u' parameter.\n\n",
					lp_passwd_program(talloc_tos()));
				ret = 1;
			}
		}

		/*
		 * Check that we have a valid script and that it hasn't
		 * been written to expect the old password.
		 */

		if(lp_encrypt_passwords()) {
			if(strstr_m( lp_passwd_chat(talloc_tos()), "%o")!=NULL) {
				fprintf(stderr,
					"ERROR: the 'passwd chat' script [%s] "
					"expects to use the old plaintext "
					"password via the %%o substitution. With "
					"encrypted passwords this is not "
					"possible.\n\n",
					lp_passwd_chat(talloc_tos()) );
				ret = 1;
			}
		}
	}

	if (strlen(lp_winbind_separator()) != 1) {
		fprintf(stderr, "ERROR: the 'winbind separator' parameter must "
				"be a single character.\n\n");
		ret = 1;
	}

	if (*lp_winbind_separator() == '+') {
		fprintf(stderr, "'winbind separator = +' might cause problems "
				"with group membership.\n\n");
	}

	if (lp_algorithmic_rid_base() < BASE_RID) {
		/* Try to prevent admin foot-shooting, we can't put algorithmic
		   rids below 1000, that's the 'well known RIDs' on NT */
		fprintf(stderr, "'algorithmic rid base' must be equal to or "
				"above %lu\n\n", BASE_RID);
	}

	if (lp_algorithmic_rid_base() & 1) {
		fprintf(stderr, "'algorithmic rid base' must be even.\n\n");
	}

#ifndef HAVE_DLOPEN
	if (lp_preload_modules()) {
		fprintf(stderr, "WARNING: 'preload modules = ' set while loading "
				"plugins not supported.\n\n");
	}
#endif

	if (!lp_passdb_backend()) {
		fprintf(stderr, "ERROR: passdb backend must have a value or be "
				"left out\n\n");
	}
	
	if (lp_os_level() > 255) {
		fprintf(stderr, "WARNING: Maximum value for 'os level' is "
				"255!\n\n");
	}

	if (strequal(lp_dos_charset(), "UTF8") || strequal(lp_dos_charset(), "UTF-8")) {
		fprintf(stderr, "ERROR: 'dos charset' must not be UTF8\n\n");
		ret = 1;
	}

	return ret;
}   

/**
 * per-share logic tests
 */
static void do_per_share_checks(int s)
{
	const char **deny_list = lp_hosts_deny(s);
	const char **allow_list = lp_hosts_allow(s);
	const char **vfs_objects = NULL;
	int i;
	static bool uses_fruit;
	static bool doesnt_use_fruit;
	static bool fruit_mix_warned;

	if(deny_list) {
		for (i=0; deny_list[i]; i++) {
			char *hasstar = strchr_m(deny_list[i], '*');
			char *hasquery = strchr_m(deny_list[i], '?');
			if(hasstar || hasquery) {
				fprintf(stderr,
					"Invalid character %c in hosts deny list "
					"(%s) for service %s.\n\n",
					hasstar ? *hasstar : *hasquery,
					deny_list[i],
					lp_servicename(talloc_tos(), s));
			}
		}
	}

	if(allow_list) {
		for (i=0; allow_list[i]; i++) {
			char *hasstar = strchr_m(allow_list[i], '*');
			char *hasquery = strchr_m(allow_list[i], '?');
			if(hasstar || hasquery) {
				fprintf(stderr,
					"Invalid character %c in hosts allow "
					"list (%s) for service %s.\n\n",
					hasstar ? *hasstar : *hasquery,
					allow_list[i],
					lp_servicename(talloc_tos(), s));
			}
		}
	}

	if(lp_level2_oplocks(s) && !lp_oplocks(s)) {
		fprintf(stderr, "Invalid combination of parameters for service "
				"%s. Level II oplocks can only be set if oplocks "
				"are also set.\n\n",
				lp_servicename(talloc_tos(), s));
	}

	if (!lp_store_dos_attributes(s) && lp_map_hidden(s)
	    && !(lp_create_mask(s) & S_IXOTH))
	{
		fprintf(stderr,
			"Invalid combination of parameters for service %s. Map "
			"hidden can only work if create mask includes octal "
			"01 (S_IXOTH).\n\n",
			lp_servicename(talloc_tos(), s));
	}
	if (!lp_store_dos_attributes(s) && lp_map_hidden(s)
	    && (lp_force_create_mode(s) & S_IXOTH))
	{
		fprintf(stderr,
			"Invalid combination of parameters for service "
			"%s. Map hidden can only work if force create mode "
			"excludes octal 01 (S_IXOTH).\n\n",
			lp_servicename(talloc_tos(), s));
	}
	if (!lp_store_dos_attributes(s) && lp_map_system(s)
	    && !(lp_create_mask(s) & S_IXGRP))
	{
		fprintf(stderr,
			"Invalid combination of parameters for service "
			"%s. Map system can only work if create mask includes "
			"octal 010 (S_IXGRP).\n\n",
			lp_servicename(talloc_tos(), s));
	}
	if (!lp_store_dos_attributes(s) && lp_map_system(s)
	    && (lp_force_create_mode(s) & S_IXGRP))
	{
		fprintf(stderr,
			"Invalid combination of parameters for service "
			"%s. Map system can only work if force create mode "
			"excludes octal 010 (S_IXGRP).\n\n",
			lp_servicename(talloc_tos(), s));
	}
	if (lp_printing(s) == PRINT_CUPS && *(lp_print_command(talloc_tos(), s)) != '\0') {
		fprintf(stderr,
			"Warning: Service %s defines a print command, but "
			"parameter is ignored when using CUPS libraries.\n\n",
			lp_servicename(talloc_tos(), s));
	}

	vfs_objects = lp_vfs_objects(s);
	if (vfs_objects && str_list_check(vfs_objects, "fruit")) {
		uses_fruit = true;
		if (!lp_ea_support(s) && !lp_ea_support(-1)) {
			fprintf(stderr,
				"ERROR: Service \"%s\" uses vfs_fruit, but "
				"that requires \"ea support = yes\".\n\n",
				lp_servicename(talloc_tos(), s));
		}
	} else {
		doesnt_use_fruit = true;
	}

	if (uses_fruit && doesnt_use_fruit && !fruit_mix_warned) {
		fruit_mix_warned = true;
		fprintf(stderr,
			"WARNING: some services use vfs_fruit, others don't. Mounting them "
			"in conjunction on OS X clients results in undefined behaviour.\n\n");
	}
}

 int main(int argc, const char *argv[])
{
	const char *config_file = get_dyn_CONFIGFILE();
	int s;
	static int silent_mode = False;
	static int show_all_parameters = False;
	int ret = 0;
	poptContext pc;
	static char *parameter_name = NULL;
	static const char *section_name = NULL;
	const char *cname;
	const char *caddr;
	static int show_defaults;
	static int skip_logic_checks = 0;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"suppress-prompt", 's', POPT_ARG_VAL, &silent_mode, 1, "Suppress prompt for enter"},
		{"verbose", 'v', POPT_ARG_NONE, &show_defaults, 1, "Show default options too"},
		{"skip-logic-checks", 'l', POPT_ARG_NONE, &skip_logic_checks, 1, "Skip the global checks"},
		{"show-all-parameters", '\0', POPT_ARG_VAL, &show_all_parameters, True, "Show the parameters, type, possible values" },
		{"parameter-name", '\0', POPT_ARG_STRING, &parameter_name, 0, "Limit testparm to a named parameter" },
		{"section-name", '\0', POPT_ARG_STRING, &section_name, 0, "Limit testparm to a named section" },
		POPT_COMMON_VERSION
		POPT_COMMON_DEBUGLEVEL
		POPT_COMMON_OPTION
		POPT_TABLEEND
	};

	TALLOC_CTX *frame = talloc_stackframe();

	smb_init_locale();
	/*
	 * Set the default debug level to 2.
	 * Allow it to be overridden by the command line,
	 * not by smb.conf.
	 */
	lp_set_cmdline("log level", "2");

	pc = poptGetContext(NULL, argc, argv, long_options, 
			    POPT_CONTEXT_KEEP_FIRST);
	poptSetOtherOptionHelp(pc, "[OPTION...] <config-file> [host-name] [host-ip]");

	while(poptGetNextOpt(pc) != -1);

	if (show_all_parameters) {
		show_parameter_list();
		exit(0);
	}

	setup_logging(poptGetArg(pc), DEBUG_STDERR);

	if (poptPeekArg(pc)) 
		config_file = poptGetArg(pc);

	cname = poptGetArg(pc);
	caddr = poptGetArg(pc);

	poptFreeContext(pc);

	if ( cname && ! caddr ) {
		printf ( "ERROR: You must specify both a machine name and an IP address.\n" );
		ret = 1;
		goto done;
	}

	fprintf(stderr,"Load smb config files from %s\n",config_file);

	if (!lp_load_with_registry_shares(config_file)) {
		fprintf(stderr,"Error loading services.\n");
		ret = 1;
		goto done;
	}

	fprintf(stderr,"Loaded services file OK.\n");

	if (skip_logic_checks == 0) {
		ret = do_global_checks();
	}

	for (s=0;s<1000;s++) {
		if (VALID_SNUM(s))
			if (strlen(lp_servicename(talloc_tos(), s)) > 12) {
				fprintf(stderr, "WARNING: You have some share names that are longer than 12 characters.\n" );
				fprintf(stderr, "These may not be accessible to some older clients.\n" );
				fprintf(stderr, "(Eg. Windows9x, WindowsMe, and smbclient prior to Samba 3.0.)\n" );
				break;
			}
	}

	for (s=0;s<1000;s++) {
		if (VALID_SNUM(s) && (skip_logic_checks == 0)) {
			do_per_share_checks(s);
		}
	}


	if (!section_name && !parameter_name) {
		fprintf(stderr,
			"Server role: %s\n\n",
			server_role_str(lp_server_role()));
	}

	if (!cname) {
		if (!silent_mode) {
			fprintf(stderr,"Press enter to see a dump of your service definitions\n");
			fflush(stdout);
			getc(stdin);
		}
		if (parameter_name || section_name) {
			bool isGlobal = False;
			s = GLOBAL_SECTION_SNUM;

			if (!section_name) {
				section_name = GLOBAL_NAME;
				isGlobal = True;
			} else if ((isGlobal=!strwicmp(section_name, GLOBAL_NAME)) == 0 &&
				 (s=lp_servicenumber(section_name)) == -1) {
					fprintf(stderr,"Unknown section %s\n",
						section_name);
					ret = 1;
					goto done;
			}
			if (parameter_name) {
				if (!dump_a_parameter( s, parameter_name, stdout, isGlobal)) {
					fprintf(stderr,"Parameter %s unknown for section %s\n",
						parameter_name, section_name);
					ret = 1;
					goto done;
				}
			} else {
				if (isGlobal == True)
					lp_dump(stdout, show_defaults, 0);
				else
					lp_dump_one(stdout, show_defaults, s);
			}
			goto done;
		}

		lp_dump(stdout, show_defaults, lp_numservices());
	}

	if(cname && caddr){
		/* this is totally ugly, a real `quick' hack */
		for (s=0;s<1000;s++) {
			if (VALID_SNUM(s)) {
				if (allow_access(lp_hosts_deny(-1), lp_hosts_allow(-1), cname, caddr)
				    && allow_access(lp_hosts_deny(s), lp_hosts_allow(s), cname, caddr)) {
					fprintf(stderr,"Allow connection from %s (%s) to %s\n",
						   cname,caddr,lp_servicename(talloc_tos(), s));
				} else {
					fprintf(stderr,"Deny connection from %s (%s) to %s\n",
						   cname,caddr,lp_servicename(talloc_tos(), s));
				}
			}
		}
	}

done:
	gfree_loadparm();
	TALLOC_FREE(frame);
	return ret;
}

