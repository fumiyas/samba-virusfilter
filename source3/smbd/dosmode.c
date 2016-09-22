/* 
   Unix SMB/CIFS implementation.
   dos mode handling functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) James Peach 2006

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
#include "system/filesys.h"
#include "librpc/gen_ndr/ndr_xattr.h"
#include "librpc/gen_ndr/ioctl.h"
#include "../libcli/security/security.h"
#include "smbd/smbd.h"
#include "lib/param/loadparm.h"

static NTSTATUS get_file_handle_for_metadata(connection_struct *conn,
				const struct smb_filename *smb_fname,
				files_struct **ret_fsp,
				bool *need_close);

static void dos_mode_debug_print(const char *func, uint32_t mode)
{
	fstring modestr;

	if (DEBUGLEVEL < DBGLVL_INFO) {
		return;
	}

	modestr[0] = '\0';

	if (mode & FILE_ATTRIBUTE_HIDDEN) {
		fstrcat(modestr, "h");
	}
	if (mode & FILE_ATTRIBUTE_READONLY) {
		fstrcat(modestr, "r");
	}
	if (mode & FILE_ATTRIBUTE_SYSTEM) {
		fstrcat(modestr, "s");
	}
	if (mode & FILE_ATTRIBUTE_DIRECTORY) {
		fstrcat(modestr, "d");
	}
	if (mode & FILE_ATTRIBUTE_ARCHIVE) {
		fstrcat(modestr, "a");
	}
	if (mode & FILE_ATTRIBUTE_SPARSE) {
		fstrcat(modestr, "[sparse]");
	}
	if (mode & FILE_ATTRIBUTE_OFFLINE) {
		fstrcat(modestr, "[offline]");
	}
	if (mode & FILE_ATTRIBUTE_COMPRESSED) {
		fstrcat(modestr, "[compressed]");
	}

	DBG_INFO("%s returning (0x%x): \"%s\"\n", func, (unsigned)mode,
		 modestr);
}

static uint32_t filter_mode_by_protocol(uint32_t mode)
{
	if (get_Protocol() <= PROTOCOL_LANMAN2) {
		DEBUG(10,("filter_mode_by_protocol: "
			"filtering result 0x%x to 0x%x\n",
			(unsigned int)mode,
			(unsigned int)(mode & 0x3f) ));
		mode &= 0x3f;
	}
	return mode;
}

static int set_link_read_only_flag(const SMB_STRUCT_STAT *const sbuf)
{
#ifdef S_ISLNK
#if LINKS_READ_ONLY
	if (S_ISLNK(sbuf->st_mode) && S_ISDIR(sbuf->st_mode))
		return FILE_ATTRIBUTE_READONLY;
#endif
#endif
	return 0;
}

/****************************************************************************
 Change a dos mode to a unix mode.
    Base permission for files:
         if creating file and inheriting (i.e. parent_dir != NULL)
           apply read/write bits from parent directory.
         else   
           everybody gets read bit set
         dos readonly is represented in unix by removing everyone's write bit
         dos archive is represented in unix by the user's execute bit
         dos system is represented in unix by the group's execute bit
         dos hidden is represented in unix by the other's execute bit
         if !inheriting {
           Then apply create mask,
           then add force bits.
         }
    Base permission for directories:
         dos directory is represented in unix by unix's dir bit and the exec bit
         if !inheriting {
           Then apply create mask,
           then add force bits.
         }
****************************************************************************/

mode_t unix_mode(connection_struct *conn, int dosmode,
		 const struct smb_filename *smb_fname,
		 const char *inherit_from_dir)
{
	mode_t result = (S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH);
	mode_t dir_mode = 0; /* Mode of the inherit_from directory if
			      * inheriting. */

	if (!lp_store_dos_attributes(SNUM(conn)) && IS_DOS_READONLY(dosmode)) {
		result &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
	}

	if ((inherit_from_dir != NULL) && lp_inherit_permissions(SNUM(conn))) {
		struct smb_filename *smb_fname_parent;

		DEBUG(2, ("unix_mode(%s) inheriting from %s\n",
			  smb_fname_str_dbg(smb_fname),
			  inherit_from_dir));

		smb_fname_parent = synthetic_smb_fname(talloc_tos(),
					inherit_from_dir,
					NULL,
					NULL,
					smb_fname->flags);
		if (smb_fname_parent == NULL) {
			DEBUG(1,("unix_mode(%s) failed, [dir %s]: No memory\n",
				 smb_fname_str_dbg(smb_fname),
				 inherit_from_dir));
			return(0);
		}

		if (SMB_VFS_STAT(conn, smb_fname_parent) != 0) {
			DEBUG(4,("unix_mode(%s) failed, [dir %s]: %s\n",
				 smb_fname_str_dbg(smb_fname),
				 inherit_from_dir, strerror(errno)));
			TALLOC_FREE(smb_fname_parent);
			return(0);      /* *** shouldn't happen! *** */
		}

		/* Save for later - but explicitly remove setuid bit for safety. */
		dir_mode = smb_fname_parent->st.st_ex_mode & ~S_ISUID;
		DEBUG(2,("unix_mode(%s) inherit mode %o\n",
			 smb_fname_str_dbg(smb_fname), (int)dir_mode));
		/* Clear "result" */
		result = 0;
		TALLOC_FREE(smb_fname_parent);
	} 

	if (IS_DOS_DIR(dosmode)) {
		/* We never make directories read only for the owner as under DOS a user
		can always create a file in a read-only directory. */
		result |= (S_IFDIR | S_IWUSR);

		if (dir_mode) {
			/* Inherit mode of parent directory. */
			result |= dir_mode;
		} else {
			/* Provisionally add all 'x' bits */
			result |= (S_IXUSR | S_IXGRP | S_IXOTH);                 

			/* Apply directory mask */
			result &= lp_directory_mask(SNUM(conn));
			/* Add in force bits */
			result |= lp_force_directory_mode(SNUM(conn));
		}
	} else { 
		if (lp_map_archive(SNUM(conn)) && IS_DOS_ARCHIVE(dosmode))
			result |= S_IXUSR;

		if (lp_map_system(SNUM(conn)) && IS_DOS_SYSTEM(dosmode))
			result |= S_IXGRP;

		if (lp_map_hidden(SNUM(conn)) && IS_DOS_HIDDEN(dosmode))
			result |= S_IXOTH;  

		if (dir_mode) {
			/* Inherit 666 component of parent directory mode */
			result |= dir_mode & (S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH);
		} else {
			/* Apply mode mask */
			result &= lp_create_mask(SNUM(conn));
			/* Add in force bits */
			result |= lp_force_create_mode(SNUM(conn));
		}
	}

	DBG_INFO("unix_mode(%s) returning 0%o\n",
		 smb_fname_str_dbg(smb_fname), (int)result);

	return(result);
}

/****************************************************************************
 Change a unix mode to a dos mode.
****************************************************************************/

static uint32_t dos_mode_from_sbuf(connection_struct *conn,
				 const struct smb_filename *smb_fname)
{
	int result = 0;
	enum mapreadonly_options ro_opts = (enum mapreadonly_options)lp_map_readonly(SNUM(conn));

#if defined(UF_IMMUTABLE) && defined(SF_IMMUTABLE)
	/* if we can find out if a file is immutable we should report it r/o */
	if (smb_fname->st.st_ex_flags & (UF_IMMUTABLE | SF_IMMUTABLE)) {
		result |= FILE_ATTRIBUTE_READONLY;
	}
#endif
	if (ro_opts == MAP_READONLY_YES) {
		/* Original Samba method - map inverse of user "w" bit. */
		if ((smb_fname->st.st_ex_mode & S_IWUSR) == 0) {
			result |= FILE_ATTRIBUTE_READONLY;
		}
	} else if (ro_opts == MAP_READONLY_PERMISSIONS) {
		/* Check actual permissions for read-only. */
		if (!can_write_to_file(conn, smb_fname)) {
			result |= FILE_ATTRIBUTE_READONLY;
		}
	} /* Else never set the readonly bit. */

	if (MAP_ARCHIVE(conn) && ((smb_fname->st.st_ex_mode & S_IXUSR) != 0))
		result |= FILE_ATTRIBUTE_ARCHIVE;

	if (MAP_SYSTEM(conn) && ((smb_fname->st.st_ex_mode & S_IXGRP) != 0))
		result |= FILE_ATTRIBUTE_SYSTEM;

	if (MAP_HIDDEN(conn) && ((smb_fname->st.st_ex_mode & S_IXOTH) != 0))
		result |= FILE_ATTRIBUTE_HIDDEN;

	if (S_ISDIR(smb_fname->st.st_ex_mode))
		result = FILE_ATTRIBUTE_DIRECTORY | (result & FILE_ATTRIBUTE_READONLY);

	result |= set_link_read_only_flag(&smb_fname->st);

	dos_mode_debug_print(__func__, result);

	return result;
}

/****************************************************************************
 Get DOS attributes from an EA.
 This can also pull the create time into the stat struct inside smb_fname.
****************************************************************************/

NTSTATUS get_ea_dos_attribute(connection_struct *conn,
			      struct smb_filename *smb_fname,
			      uint32_t *pattr)
{
	struct xattr_DOSATTRIB dosattrib;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	ssize_t sizeret;
	fstring attrstr;
	uint32_t dosattr;

	if (!lp_store_dos_attributes(SNUM(conn))) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	/* Don't reset pattr to zero as we may already have filename-based attributes we
	   need to preserve. */

	sizeret = SMB_VFS_GETXATTR(conn, smb_fname->base_name,
				   SAMBA_XATTR_DOS_ATTRIB, attrstr,
				   sizeof(attrstr));
	if (sizeret == -1) {
		DBG_INFO("Cannot get attribute "
			 "from EA on file %s: Error = %s\n",
			 smb_fname_str_dbg(smb_fname), strerror(errno));
		return map_nt_error_from_unix(errno);
	}

	blob.data = (uint8_t *)attrstr;
	blob.length = sizeret;

	ndr_err = ndr_pull_struct_blob(&blob, talloc_tos(), &dosattrib,
			(ndr_pull_flags_fn_t)ndr_pull_xattr_DOSATTRIB);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1,("get_ea_dos_attribute: bad ndr decode "
			 "from EA on file %s: Error = %s\n",
			 smb_fname_str_dbg(smb_fname),
			 ndr_errstr(ndr_err)));
		return ndr_map_error2ntstatus(ndr_err);
	}

	DEBUG(10,("get_ea_dos_attribute: %s attr = %s\n",
		  smb_fname_str_dbg(smb_fname), dosattrib.attrib_hex));

	switch (dosattrib.version) {
		case 0xFFFF:
			dosattr = dosattrib.info.compatinfoFFFF.attrib;
			break;
		case 1:
			dosattr = dosattrib.info.info1.attrib;
			if (!null_nttime(dosattrib.info.info1.create_time)) {
				struct timespec create_time =
					nt_time_to_unix_timespec(
						dosattrib.info.info1.create_time);

				update_stat_ex_create_time(&smb_fname->st,
							create_time);

				DEBUG(10,("get_ea_dos_attribute: file %s case 1 "
					"set btime %s\n",
					smb_fname_str_dbg(smb_fname),
					time_to_asc(convert_timespec_to_time_t(
						create_time)) ));
			}
			break;
		case 2:
			dosattr = dosattrib.info.oldinfo2.attrib;
			/* Don't know what flags to check for this case. */
			break;
		case 3:
			dosattr = dosattrib.info.info3.attrib;
			if ((dosattrib.info.info3.valid_flags & XATTR_DOSINFO_CREATE_TIME) &&
					!null_nttime(dosattrib.info.info3.create_time)) {
				struct timespec create_time =
					nt_time_to_unix_timespec(
						dosattrib.info.info3.create_time);

				update_stat_ex_create_time(&smb_fname->st,
							create_time);

				DEBUG(10,("get_ea_dos_attribute: file %s case 3 "
					"set btime %s\n",
					smb_fname_str_dbg(smb_fname),
					time_to_asc(convert_timespec_to_time_t(
						create_time)) ));
			}
			break;
		default:
			DEBUG(1,("get_ea_dos_attribute: Badly formed DOSATTRIB on "
				 "file %s - %s\n", smb_fname_str_dbg(smb_fname),
				 attrstr));
			/* Should this be INTERNAL_ERROR? */
	                return NT_STATUS_INVALID_PARAMETER;
	}

	if (S_ISDIR(smb_fname->st.st_ex_mode)) {
		dosattr |= FILE_ATTRIBUTE_DIRECTORY;
	}
	/* FILE_ATTRIBUTE_SPARSE is valid on get but not on set. */
	*pattr |= (uint32_t)(dosattr & (SAMBA_ATTRIBUTES_MASK|FILE_ATTRIBUTE_SPARSE));

	dos_mode_debug_print(__func__, *pattr);

	return NT_STATUS_OK;
}

/****************************************************************************
 Set DOS attributes in an EA.
 Also sets the create time.
****************************************************************************/

NTSTATUS set_ea_dos_attribute(connection_struct *conn,
			      const struct smb_filename *smb_fname,
			      uint32_t dosmode)
{
	struct xattr_DOSATTRIB dosattrib;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;

	if (!lp_store_dos_attributes(SNUM(conn))) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	ZERO_STRUCT(dosattrib);
	ZERO_STRUCT(blob);

	dosattrib.version = 3;
	dosattrib.info.info3.valid_flags = XATTR_DOSINFO_ATTRIB|
					XATTR_DOSINFO_CREATE_TIME;
	dosattrib.info.info3.attrib = dosmode;
	dosattrib.info.info3.create_time = unix_timespec_to_nt_time(
				smb_fname->st.st_ex_btime);

	DEBUG(10,("set_ea_dos_attributes: set attribute 0x%x, btime = %s on file %s\n",
		(unsigned int)dosmode,
		time_to_asc(convert_timespec_to_time_t(smb_fname->st.st_ex_btime)),
		smb_fname_str_dbg(smb_fname) ));

	ndr_err = ndr_push_struct_blob(
			&blob, talloc_tos(), &dosattrib,
			(ndr_push_flags_fn_t)ndr_push_xattr_DOSATTRIB);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(5, ("create_acl_blob: ndr_push_xattr_DOSATTRIB failed: %s\n",
			ndr_errstr(ndr_err)));
		return ndr_map_error2ntstatus(ndr_err);
	}

	if (blob.data == NULL || blob.length == 0) {
		/* Should this be INTERNAL_ERROR? */
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (SMB_VFS_SETXATTR(conn, smb_fname->base_name,
			     SAMBA_XATTR_DOS_ATTRIB, blob.data, blob.length,
			     0) == -1) {
		NTSTATUS status = NT_STATUS_OK;
		bool need_close = false;
		files_struct *fsp = NULL;

		if((errno != EPERM) && (errno != EACCES)) {
			DBG_INFO("Cannot set "
				 "attribute EA on file %s: Error = %s\n",
				 smb_fname_str_dbg(smb_fname), strerror(errno));
			return map_nt_error_from_unix(errno);
		}

		/* We want DOS semantics, ie allow non owner with write permission to change the
			bits on a file. Just like file_ntimes below.
		*/

		/* Check if we have write access. */
		if(!CAN_WRITE(conn) || !lp_dos_filemode(SNUM(conn)))
			return NT_STATUS_ACCESS_DENIED;

		if (!can_write_to_file(conn, smb_fname)) {
			return NT_STATUS_ACCESS_DENIED;
		}

		/*
		 * We need to get an open file handle to do the
		 * metadata operation under root.
		 */

		status = get_file_handle_for_metadata(conn,
						smb_fname,
						&fsp,
						&need_close);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		become_root();
		if (SMB_VFS_FSETXATTR(fsp,
				     SAMBA_XATTR_DOS_ATTRIB, blob.data,
				     blob.length, 0) == 0) {
			status = NT_STATUS_OK;
		}
		unbecome_root();
		if (need_close) {
			close_file(NULL, fsp, NORMAL_CLOSE);
		}
		return status;
	}
	DEBUG(10,("set_ea_dos_attribute: set EA 0x%x on file %s\n",
		(unsigned int)dosmode,
		smb_fname_str_dbg(smb_fname)));
	return NT_STATUS_OK;
}

/****************************************************************************
 Change a unix mode to a dos mode for an ms dfs link.
****************************************************************************/

uint32_t dos_mode_msdfs(connection_struct *conn,
		      const struct smb_filename *smb_fname)
{
	uint32_t result = 0;

	DEBUG(8,("dos_mode_msdfs: %s\n", smb_fname_str_dbg(smb_fname)));

	if (!VALID_STAT(smb_fname->st)) {
		return 0;
	}

	/* First do any modifications that depend on the path name. */
	/* hide files with a name starting with a . */
	if (lp_hide_dot_files(SNUM(conn))) {
		const char *p = strrchr_m(smb_fname->base_name, '/');
		if (p) {
			p++;
		} else {
			p = smb_fname->base_name;
		}

		/* Only . and .. are not hidden. */
		if (p[0] == '.' && !((p[1] == '\0') ||
				(p[1] == '.' && p[2] == '\0'))) {
			result |= FILE_ATTRIBUTE_HIDDEN;
		}
	}

	result |= dos_mode_from_sbuf(conn, smb_fname);

	/* Optimization : Only call is_hidden_path if it's not already
	   hidden. */
	if (!(result & FILE_ATTRIBUTE_HIDDEN) &&
	    IS_HIDDEN_PATH(conn, smb_fname->base_name)) {
		result |= FILE_ATTRIBUTE_HIDDEN;
	}

	if (result == 0) {
		result = FILE_ATTRIBUTE_NORMAL;
	}

	result = filter_mode_by_protocol(result);

	/*
	 * Add in that it is a reparse point
	 */
	result |= FILE_ATTRIBUTE_REPARSE_POINT;

	dos_mode_debug_print(__func__, result);

	return(result);
}

/*
 * check whether a file or directory is flagged as compressed.
 */
static NTSTATUS dos_mode_check_compressed(connection_struct *conn,
					  struct smb_filename *smb_fname,
					  bool *is_compressed)
{
	NTSTATUS status;
	uint16_t compression_fmt;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_out;
	}

	status = SMB_VFS_GET_COMPRESSION(conn, tmp_ctx, NULL, smb_fname,
					 &compression_fmt);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_ctx_free;
	}

	if (compression_fmt == COMPRESSION_FORMAT_LZNT1) {
		*is_compressed = true;
	} else {
		*is_compressed = false;
	}
	status = NT_STATUS_OK;

err_ctx_free:
	talloc_free(tmp_ctx);
err_out:
	return status;
}

static uint32_t dos_mode_from_name(connection_struct *conn,
				   const struct smb_filename *smb_fname,
				   uint32_t dosmode)
{
	const char *p = NULL;
	uint32_t result = dosmode;

	if (!(result & FILE_ATTRIBUTE_HIDDEN) &&
	    lp_hide_dot_files(SNUM(conn)))
	{
		p = strrchr_m(smb_fname->base_name, '/');
		if (p) {
			p++;
		} else {
			p = smb_fname->base_name;
		}

		/* Only . and .. are not hidden. */
		if ((p[0] == '.') &&
		    !((p[1] == '\0') || (p[1] == '.' && p[2] == '\0')))
		{
			result |= FILE_ATTRIBUTE_HIDDEN;
		}
	}

	if (!(result & FILE_ATTRIBUTE_HIDDEN) &&
	    IS_HIDDEN_PATH(conn, smb_fname->base_name))
	{
		result |= FILE_ATTRIBUTE_HIDDEN;
	}

	return result;
}

/****************************************************************************
 Change a unix mode to a dos mode.
 May also read the create timespec into the stat struct in smb_fname
 if "store dos attributes" is true.
****************************************************************************/

uint32_t dos_mode(connection_struct *conn, struct smb_filename *smb_fname)
{
	uint32_t result = 0;
	bool offline;
	NTSTATUS status = NT_STATUS_OK;

	DEBUG(8,("dos_mode: %s\n", smb_fname_str_dbg(smb_fname)));

	if (!VALID_STAT(smb_fname->st)) {
		return 0;
	}

	/* Get the DOS attributes via the VFS if we can */
	status = SMB_VFS_GET_DOS_ATTRIBUTES(conn, smb_fname, &result);
	if (!NT_STATUS_IS_OK(status)) {
		result |= dos_mode_from_sbuf(conn, smb_fname);
	}

	offline = SMB_VFS_IS_OFFLINE(conn, smb_fname, &smb_fname->st);
	if (S_ISREG(smb_fname->st.st_ex_mode) && offline) {
		result |= FILE_ATTRIBUTE_OFFLINE;
	}

	if (conn->fs_capabilities & FILE_FILE_COMPRESSION) {
		bool compressed = false;
		status = dos_mode_check_compressed(conn, smb_fname,
						   &compressed);
		if (NT_STATUS_IS_OK(status) && compressed) {
			result |= FILE_ATTRIBUTE_COMPRESSED;
		}
	}

	result |= dos_mode_from_name(conn, smb_fname, result);

	if (result == 0) {
		if (S_ISDIR(smb_fname->st.st_ex_mode)) {
			result = FILE_ATTRIBUTE_DIRECTORY;
		} else {
			result = FILE_ATTRIBUTE_NORMAL;
		}
	}

	result = filter_mode_by_protocol(result);

	dos_mode_debug_print(__func__, result);

	return result;
}

/*******************************************************************
 chmod a file - but preserve some bits.
 If "store dos attributes" is also set it will store the create time
 from the stat struct in smb_fname (in NTTIME format) in the EA
 attribute also.
********************************************************************/

int file_set_dosmode(connection_struct *conn, struct smb_filename *smb_fname,
		     uint32_t dosmode, const char *parent_dir, bool newfile)
{
	int mask=0;
	mode_t tmp;
	mode_t unixmode;
	int ret = -1, lret = -1;
	uint32_t old_mode;
	struct timespec new_create_timespec;
	files_struct *fsp = NULL;
	bool need_close = false;
	NTSTATUS status;

	if (!CAN_WRITE(conn)) {
		errno = EROFS;
		return -1;
	}

	/* We only allow READONLY|HIDDEN|SYSTEM|DIRECTORY|ARCHIVE here. */
	dosmode &= (SAMBA_ATTRIBUTES_MASK | FILE_ATTRIBUTE_OFFLINE);

	DEBUG(10,("file_set_dosmode: setting dos mode 0x%x on file %s\n",
		  dosmode, smb_fname_str_dbg(smb_fname)));

	unixmode = smb_fname->st.st_ex_mode;

	get_acl_group_bits(conn, smb_fname->base_name,
			   &smb_fname->st.st_ex_mode);

	if (S_ISDIR(smb_fname->st.st_ex_mode))
		dosmode |= FILE_ATTRIBUTE_DIRECTORY;
	else
		dosmode &= ~FILE_ATTRIBUTE_DIRECTORY;

	new_create_timespec = smb_fname->st.st_ex_btime;

	old_mode = dos_mode(conn, smb_fname);

	if ((dosmode & FILE_ATTRIBUTE_OFFLINE) &&
	    !(old_mode & FILE_ATTRIBUTE_OFFLINE)) {
		lret = SMB_VFS_SET_OFFLINE(conn, smb_fname);
		if (lret == -1) {
			if (errno == ENOTSUP) {
				DEBUG(10, ("Setting FILE_ATTRIBUTE_OFFLINE for "
					   "%s/%s is not supported.\n",
					   parent_dir,
					   smb_fname_str_dbg(smb_fname)));
			} else {
				DEBUG(0, ("An error occurred while setting "
					  "FILE_ATTRIBUTE_OFFLINE for "
					  "%s/%s: %s", parent_dir,
					  smb_fname_str_dbg(smb_fname),
					  strerror(errno)));
			}
		}
	}

	dosmode  &= ~FILE_ATTRIBUTE_OFFLINE;
	old_mode &= ~FILE_ATTRIBUTE_OFFLINE;

	smb_fname->st.st_ex_btime = new_create_timespec;

	/* Store the DOS attributes in an EA by preference. */
	status = SMB_VFS_SET_DOS_ATTRIBUTES(conn, smb_fname, dosmode);
	if (NT_STATUS_IS_OK(status)) {
		if (!newfile) {
			notify_fname(conn, NOTIFY_ACTION_MODIFIED,
				FILE_NOTIFY_CHANGE_ATTRIBUTES,
				smb_fname->base_name);
		}
		smb_fname->st.st_ex_mode = unixmode;
		return 0;
	} else {
		/*
		 * Only fall back to using UNIX modes if
		 * we get NOT_IMPLEMENTED.
		 */
		if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)) {
			errno = map_errno_from_nt_status(status);
			return -1;
		}
	}

	/* Fall back to UNIX modes. */
	unixmode = unix_mode(conn, dosmode, smb_fname, parent_dir);

	/* preserve the file type bits */
	mask |= S_IFMT;

	/* preserve the s bits */
	mask |= (S_ISUID | S_ISGID);

	/* preserve the t bit */
#ifdef S_ISVTX
	mask |= S_ISVTX;
#endif

	/* possibly preserve the x bits */
	if (!MAP_ARCHIVE(conn))
		mask |= S_IXUSR;
	if (!MAP_SYSTEM(conn))
		mask |= S_IXGRP;
	if (!MAP_HIDDEN(conn))
		mask |= S_IXOTH;

	unixmode |= (smb_fname->st.st_ex_mode & mask);

	/* if we previously had any r bits set then leave them alone */
	if ((tmp = smb_fname->st.st_ex_mode & (S_IRUSR|S_IRGRP|S_IROTH))) {
		unixmode &= ~(S_IRUSR|S_IRGRP|S_IROTH);
		unixmode |= tmp;
	}

	/* if we previously had any w bits set then leave them alone 
		whilst adding in the new w bits, if the new mode is not rdonly */
	if (!IS_DOS_READONLY(dosmode)) {
		unixmode |= (smb_fname->st.st_ex_mode & (S_IWUSR|S_IWGRP|S_IWOTH));
	}

	/*
	 * From the chmod 2 man page:
	 *
	 * "If the calling process is not privileged, and the group of the file
	 * does not match the effective group ID of the process or one of its
	 * supplementary group IDs, the S_ISGID bit will be turned off, but
	 * this will not cause an error to be returned."
	 *
	 * Simply refuse to do the chmod in this case.
	 */

	if (S_ISDIR(smb_fname->st.st_ex_mode) && (unixmode & S_ISGID) &&
			geteuid() != sec_initial_uid() &&
			!current_user_in_group(conn, smb_fname->st.st_ex_gid)) {
		DEBUG(3,("file_set_dosmode: setgid bit cannot be "
			"set for directory %s\n",
			smb_fname_str_dbg(smb_fname)));
		errno = EPERM;
		return -1;
	}

	ret = SMB_VFS_CHMOD(conn, smb_fname, unixmode);
	if (ret == 0) {
		if(!newfile || (lret != -1)) {
			notify_fname(conn, NOTIFY_ACTION_MODIFIED,
				     FILE_NOTIFY_CHANGE_ATTRIBUTES,
				     smb_fname->base_name);
		}
		smb_fname->st.st_ex_mode = unixmode;
		return 0;
	}

	if((errno != EPERM) && (errno != EACCES))
		return -1;

	if(!lp_dos_filemode(SNUM(conn)))
		return -1;

	/* We want DOS semantics, ie allow non owner with write permission to change the
		bits on a file. Just like file_ntimes below.
	*/

	if (!can_write_to_file(conn, smb_fname)) {
		errno = EACCES;
		return -1;
	}

	/*
	 * We need to get an open file handle to do the
	 * metadata operation under root.
	 */

	status = get_file_handle_for_metadata(conn,
					      smb_fname,
					      &fsp,
					      &need_close);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		return -1;
	}

	become_root();
	ret = SMB_VFS_FCHMOD(fsp, unixmode);
	unbecome_root();
	if (need_close) {
		close_file(NULL, fsp, NORMAL_CLOSE);
	}
	if (!newfile) {
		notify_fname(conn, NOTIFY_ACTION_MODIFIED,
			     FILE_NOTIFY_CHANGE_ATTRIBUTES,
			     smb_fname->base_name);
	}
	if (ret == 0) {
		smb_fname->st.st_ex_mode = unixmode;
	}

	return( ret );
}


NTSTATUS file_set_sparse(connection_struct *conn,
			 files_struct *fsp,
			 bool sparse)
{
	uint32_t old_dosmode;
	uint32_t new_dosmode;
	NTSTATUS status;

	if (!CAN_WRITE(conn)) {
		DEBUG(9,("file_set_sparse: fname[%s] set[%u] "
			"on readonly share[%s]\n",
			smb_fname_str_dbg(fsp->fsp_name),
			sparse,
			lp_servicename(talloc_tos(), SNUM(conn))));
		return NT_STATUS_MEDIA_WRITE_PROTECTED;
	}

	/*
	 * Windows Server 2008 & 2012 permit FSCTL_SET_SPARSE if any of the
	 * following access flags are granted.
	 */
	if ((fsp->access_mask & (FILE_WRITE_DATA
				| FILE_WRITE_ATTRIBUTES
				| SEC_FILE_APPEND_DATA)) == 0) {
		DEBUG(9,("file_set_sparse: fname[%s] set[%u] "
			"access_mask[0x%08X] - access denied\n",
			smb_fname_str_dbg(fsp->fsp_name),
			sparse,
			fsp->access_mask));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (fsp->is_directory) {
		DEBUG(9, ("invalid attempt to %s sparse flag on dir %s\n",
			  (sparse ? "set" : "clear"),
			  smb_fname_str_dbg(fsp->fsp_name)));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (IS_IPC(conn) || IS_PRINT(conn)) {
		DEBUG(9, ("attempt to %s sparse flag over invalid conn\n",
			  (sparse ? "set" : "clear")));
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(10,("file_set_sparse: setting sparse bit %u on file %s\n",
		  sparse, smb_fname_str_dbg(fsp->fsp_name)));

	if (!lp_store_dos_attributes(SNUM(conn))) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	old_dosmode = dos_mode(conn, fsp->fsp_name);

	if (sparse && !(old_dosmode & FILE_ATTRIBUTE_SPARSE)) {
		new_dosmode = old_dosmode | FILE_ATTRIBUTE_SPARSE;
	} else if (!sparse && (old_dosmode & FILE_ATTRIBUTE_SPARSE)) {
		new_dosmode = old_dosmode & ~FILE_ATTRIBUTE_SPARSE;
	} else {
		return NT_STATUS_OK;
	}

	/* Store the DOS attributes in an EA. */
	status = SMB_VFS_FSET_DOS_ATTRIBUTES(conn, fsp, new_dosmode);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	notify_fname(conn, NOTIFY_ACTION_MODIFIED,
		     FILE_NOTIFY_CHANGE_ATTRIBUTES,
		     fsp->fsp_name->base_name);

	fsp->is_sparse = sparse;

	return NT_STATUS_OK;
}

/*******************************************************************
 Wrapper around the VFS ntimes that possibly allows DOS semantics rather
 than POSIX.
*******************************************************************/

int file_ntimes(connection_struct *conn, const struct smb_filename *smb_fname,
		struct smb_file_time *ft)
{
	int ret = -1;

	errno = 0;

	DEBUG(6, ("file_ntime: actime: %s",
		  time_to_asc(convert_timespec_to_time_t(ft->atime))));
	DEBUG(6, ("file_ntime: modtime: %s",
		  time_to_asc(convert_timespec_to_time_t(ft->mtime))));
	DEBUG(6, ("file_ntime: ctime: %s",
		  time_to_asc(convert_timespec_to_time_t(ft->ctime))));
	DEBUG(6, ("file_ntime: createtime: %s",
		  time_to_asc(convert_timespec_to_time_t(ft->create_time))));

	/* Don't update the time on read-only shares */
	/* We need this as set_filetime (which can be called on
	   close and other paths) can end up calling this function
	   without the NEED_WRITE protection. Found by : 
	   Leo Weppelman <leo@wau.mis.ah.nl>
	*/

	if (!CAN_WRITE(conn)) {
		return 0;
	}

	if(SMB_VFS_NTIMES(conn, smb_fname, ft) == 0) {
		return 0;
	}

	if((errno != EPERM) && (errno != EACCES)) {
		return -1;
	}

	if(!lp_dos_filetimes(SNUM(conn))) {
		return -1;
	}

	/* We have permission (given by the Samba admin) to
	   break POSIX semantics and allow a user to change
	   the time on a file they don't own but can write to
	   (as DOS does).
	 */

	/* Check if we have write access. */
	if (can_write_to_file(conn, smb_fname)) {
		/* We are allowed to become root and change the filetime. */
		become_root();
		ret = SMB_VFS_NTIMES(conn, smb_fname, ft);
		unbecome_root();
	}

	return ret;
}

/******************************************************************
 Force a "sticky" write time on a pathname. This will always be
 returned on all future write time queries and set on close.
******************************************************************/

bool set_sticky_write_time_path(struct file_id fileid, struct timespec mtime)
{
	if (null_timespec(mtime)) {
		return true;
	}

	if (!set_sticky_write_time(fileid, mtime)) {
		return false;
	}

	return true;
}

/******************************************************************
 Force a "sticky" write time on an fsp. This will always be
 returned on all future write time queries and set on close.
******************************************************************/

bool set_sticky_write_time_fsp(struct files_struct *fsp, struct timespec mtime)
{
	if (null_timespec(mtime)) {
		return true;
	}

	fsp->write_time_forced = true;
	TALLOC_FREE(fsp->update_write_time_event);

	return set_sticky_write_time_path(fsp->file_id, mtime);
}

/******************************************************************
 Set a create time EA.
******************************************************************/

NTSTATUS set_create_timespec_ea(connection_struct *conn,
				const struct smb_filename *psmb_fname,
				struct timespec create_time)
{
	struct smb_filename *smb_fname;
	uint32_t dosmode;
	int ret;

	if (!lp_store_dos_attributes(SNUM(conn))) {
		return NT_STATUS_OK;
	}

	smb_fname = synthetic_smb_fname(talloc_tos(),
					psmb_fname->base_name,
					NULL,
					&psmb_fname->st,
					psmb_fname->flags);

	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	dosmode = dos_mode(conn, smb_fname);

	smb_fname->st.st_ex_btime = create_time;

	ret = file_set_dosmode(conn, smb_fname, dosmode, NULL, false);
	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}

	DEBUG(10,("set_create_timespec_ea: wrote create time EA for file %s\n",
		smb_fname_str_dbg(smb_fname)));

	return NT_STATUS_OK;
}

/******************************************************************
 Return a create time.
******************************************************************/

struct timespec get_create_timespec(connection_struct *conn,
				struct files_struct *fsp,
				const struct smb_filename *smb_fname)
{
	return smb_fname->st.st_ex_btime;
}

/******************************************************************
 Return a change time (may look at EA in future).
******************************************************************/

struct timespec get_change_timespec(connection_struct *conn,
				struct files_struct *fsp,
				const struct smb_filename *smb_fname)
{
	return smb_fname->st.st_ex_mtime;
}

/****************************************************************************
 Get a real open file handle we can do meta-data operations on. As it's
 going to be used under root access only on meta-data we should look for
 any existing open file handle first, and use that in preference (also to
 avoid kernel self-oplock breaks). If not use an INTERNAL_OPEN_ONLY handle.
****************************************************************************/

static NTSTATUS get_file_handle_for_metadata(connection_struct *conn,
				const struct smb_filename *smb_fname,
				files_struct **ret_fsp,
				bool *need_close)
{
	NTSTATUS status;
	files_struct *fsp;
	struct file_id file_id;
	struct smb_filename *smb_fname_cp = NULL;

	*need_close = false;

	if (!VALID_STAT(smb_fname->st)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	file_id = vfs_file_id_from_sbuf(conn, &smb_fname->st);

	for(fsp = file_find_di_first(conn->sconn, file_id);
			fsp;
			fsp = file_find_di_next(fsp)) {
		if (fsp->fh->fd != -1) {
			*ret_fsp = fsp;
			return NT_STATUS_OK;
		}
	}

	smb_fname_cp = cp_smb_filename(talloc_tos(),
					smb_fname);
	if (smb_fname_cp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Opens an INTERNAL_OPEN_ONLY write handle. */
	status = SMB_VFS_CREATE_FILE(
		conn,                                   /* conn */
		NULL,                                   /* req */
		0,                                      /* root_dir_fid */
		smb_fname_cp,				/* fname */
		FILE_WRITE_DATA,                        /* access_mask */
		(FILE_SHARE_READ | FILE_SHARE_WRITE |   /* share_access */
			FILE_SHARE_DELETE),
		FILE_OPEN,                              /* create_disposition*/
		0,                                      /* create_options */
		0,                                      /* file_attributes */
		INTERNAL_OPEN_ONLY,                     /* oplock_request */
		NULL,					/* lease */
                0,                                      /* allocation_size */
		0,                                      /* private_flags */
		NULL,                                   /* sd */
		NULL,                                   /* ea_list */
		ret_fsp,                                /* result */
		NULL,                                   /* pinfo */
		NULL, NULL);				/* create context */

	TALLOC_FREE(smb_fname_cp);

	if (NT_STATUS_IS_OK(status)) {
		*need_close = true;
	}
	return status;
}
