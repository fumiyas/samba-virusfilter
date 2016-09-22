/* 
   Unix SMB/CIFS implementation.
   System QUOTA function wrappers for NFS
   Copyright (C) Michael Adam 2010
   
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_QUOTA

#ifndef HAVE_SYS_QUOTAS
#ifdef HAVE_NFS_QUOTAS
#undef HAVE_NFS_QUOTAS
#endif
#endif

#ifdef HAVE_NFS_QUOTAS

/*
 * nfs quota support
 * This is based on the FreeBSD / SUNOS5 section of quotas.c
 */

#include <rpc/rpc.h>
#include <rpc/types.h>
#include <rpcsvc/rquota.h>
#ifdef HAVE_RPC_NETTYPE_H
#include <rpc/nettype.h>
#endif
#include <rpc/xdr.h>

#ifndef RQ_PATHLEN
#define RQ_PATHLEN 1024
#endif

#ifdef HAVE_GETQUOTA_RSLT_GETQUOTA_RSLT_U
#define GQR_RQUOTA getquota_rslt_u.gqr_rquota
#define GQR_STATUS status
#else
#define GQR_RQUOTA gqr_rquota
#define GQR_STATUS gqr_status
#endif

static int my_xdr_getquota_args(XDR *xdrsp, struct getquota_args *args)
{
	if (!xdr_string(xdrsp, &args->gqa_pathp, RQ_PATHLEN ))
		return(0);
	if (!xdr_int(xdrsp, &args->gqa_uid))
		return(0);
	return (1);
}

static int my_xdr_getquota_rslt(XDR *xdrsp, struct getquota_rslt *gqr)
{
	int quotastat;

	if (!xdr_int(xdrsp, &quotastat)) {
		DEBUG(6,("nfs_quotas: Status bad or zero\n"));
		return 0;
	}
	gqr->GQR_STATUS = quotastat;

	if (!xdr_int(xdrsp, &gqr->GQR_RQUOTA.rq_bsize)) {
		DEBUG(6,("nfs_quotas: Block size bad or zero\n"));
		return 0;
	}
	if (!xdr_bool(xdrsp, &gqr->GQR_RQUOTA.rq_active)) {
		DEBUG(6,("nfs_quotas: Active bad or zero\n"));
		return 0;
	}
	if (!xdr_int(xdrsp, (int *)&gqr->GQR_RQUOTA.rq_bhardlimit)) {
		DEBUG(6,("nfs_quotas: Hardlimit bad or zero\n"));
		return 0;
	}
	if (!xdr_int(xdrsp, (int *)&gqr->GQR_RQUOTA.rq_bsoftlimit)) {
		DEBUG(6,("nfs_quotas: Softlimit bad or zero\n"));
		return 0;
	}
	if (!xdr_int(xdrsp, (int *)&gqr->GQR_RQUOTA.rq_curblocks)) {
		DEBUG(6,("nfs_quotas: Currentblocks bad or zero\n"));
		return 0;
	}
	return (1);
}


int sys_get_nfs_quota(const char *path, const char *bdev,
		      enum SMB_QUOTA_TYPE qtype,
		      unid_t id, SMB_DISK_QUOTA *dp)
{
	CLIENT *clnt = NULL;
	struct getquota_rslt gq_rslt;
	struct getquota_args gq_args;
	const char *mnttype;
	char *cutstr, *host, *testpath;
	int len;
	static struct timeval timeout = {2,0};
	enum clnt_stat clnt_stat;

	int ret = -1;
	uint32_t qflags = 0;

	if (!path || !bdev || !dp) {
		smb_panic("sys_get_nfs_quota: called with NULL pointer");
	}

	DEBUG(10, ("sys_get_nfs_quota: path[%s] bdev[%s] qtype[%d]\n",
		   path, bdev, qtype));

	ZERO_STRUCT(*dp);

	dp->qtype = qtype;

	if (qtype != SMB_USER_QUOTA_TYPE) {
		DEBUG(3, ("sys_get_nfs_quota: got unsupported quota type '%d', "
			  "only supported type is '%d' (SMB_USER_QUOTA_TYPE)\n",
			  qtype, SMB_USER_QUOTA_TYPE));
		errno = ENOSYS;
		return -1;
	}

	mnttype = bdev;
	len = strcspn(mnttype, ":");
	cutstr = (char *) SMB_MALLOC(len+1);
	if (cutstr == NULL) {
		errno = ENOMEM;
		return -1;
	}

	memset(cutstr, '\0', len+1);
	host = strncat(cutstr, mnttype, sizeof(char) * len);
	testpath = strchr_m(mnttype, ':');
	if (testpath == NULL) {
		errno = EINVAL;
		goto out;
	}
	testpath++;
	gq_args.gqa_pathp = testpath;
	gq_args.gqa_uid = id.uid;

	DEBUG(10, ("sys_get_nfs_quotas: Asking for quota of path '%s' on "
		   "host '%s', rpcprog '%i', rpcvers '%i', network '%s'\n",
		   host, testpath+1, (int)RQUOTAPROG, (int)RQUOTAVERS, "udp"));

	clnt = clnt_create(host, RQUOTAPROG, RQUOTAVERS, "udp");
	if (clnt == NULL) {
		ret = -1;
		goto out;
	}

	clnt->cl_auth = authunix_create_default();
	if (clnt->cl_auth == NULL) {
		DEBUG(3, ("sys_get_nfs_quotas: authunix_create_default "
			  "failed\n"));
		ret = -1;
		goto out;
	}

	clnt_stat = clnt_call(clnt,
			      RQUOTAPROC_GETQUOTA,
			      (const xdrproc_t) my_xdr_getquota_args,
			      (caddr_t)&gq_args,
			      (const xdrproc_t) my_xdr_getquota_rslt,
			      (caddr_t)&gq_rslt,
			      timeout);

	if (clnt_stat != RPC_SUCCESS) {
		if (errno == ECONNREFUSED) {
			/* If we cannot connect with rpc.quotad, it may
			 * simply be because there's no quota on the remote
			 * system
			 */
			DBG_INFO("clnt_call failed with ECONNREFUSED - "
				 "assuming no quotas on server\n");
			ret = 0;
		} else {
			int save_errno = errno;
			DBG_NOTICE("clnt_call failed - %s\n", strerror(errno));
			errno = save_errno;
			ret = -1;
		}
		goto out;
	}

	DEBUG(10, ("sys_get_nfs_quotas: getquota_rslt:\n"
		   "status       : '%i'\n"
		   "bsize        : '%i'\n"
		   "active       : '%s'\n"
		   "bhardlimit   : '%u'\n"
		   "bsoftlimit   : '%u'\n"
		   "curblocks    : '%u'\n"
		   "fhardlimit   : '%u'\n"
		   "fsoftlimit   : '%u'\n"
		   "curfiles     : '%u'\n"
		   "btimeleft    : '%u'\n"
		   "ftimeleft    : '%u'\n",
		   gq_rslt.GQR_STATUS,
		   gq_rslt.GQR_RQUOTA.rq_bsize,
		   gq_rslt.GQR_RQUOTA.rq_active?"yes":"no",
		   gq_rslt.GQR_RQUOTA.rq_bhardlimit,
		   gq_rslt.GQR_RQUOTA.rq_bsoftlimit,
		   gq_rslt.GQR_RQUOTA.rq_curblocks,
		   gq_rslt.GQR_RQUOTA.rq_fhardlimit,
		   gq_rslt.GQR_RQUOTA.rq_fsoftlimit,
		   gq_rslt.GQR_RQUOTA.rq_curfiles,
		   gq_rslt.GQR_RQUOTA.rq_btimeleft,
		   gq_rslt.GQR_RQUOTA.rq_ftimeleft));

	/*
	 * gqr.status returns
	 *   1 if quotas exist,
	 *   2 if there is no quota set, and
	 *   3 if no permission to get the quota.
	 */

	switch (gq_rslt.GQR_STATUS) {
	case 1:
		DEBUG(10, ("sys_get_nfs_quotas: Good quota data\n"));
		dp->bsize = (uint64_t)gq_rslt.GQR_RQUOTA.rq_bsize;
		dp->softlimit = gq_rslt.GQR_RQUOTA.rq_bsoftlimit;
		dp->hardlimit = gq_rslt.GQR_RQUOTA.rq_bhardlimit;
		dp->curblocks = gq_rslt.GQR_RQUOTA.rq_curblocks;
		break;

	case 2:
		DEBUG(5, ("sys_get_nfs_quotas: No quota set\n"));
		SMB_QUOTAS_SET_NO_LIMIT(dp);
		break;

	case 3:
		DEBUG(3, ("sys_get_nfs_quotas: no permission to get quota\n"));
		errno = EPERM;
		ret = -1;
		goto out;

	default:
		DEBUG(5, ("sys_get_nfs_quotas: Unknown remote quota status "
			  "code '%i'\n", gq_rslt.GQR_STATUS));
		ret = -1;
		goto out;
		break;
	}

	dp->qflags = qflags;

	ret = 0;

out:
	if (clnt) {
		if (clnt->cl_auth) {
			auth_destroy(clnt->cl_auth);
		}
		clnt_destroy(clnt);
	}

	SAFE_FREE(cutstr);

	DEBUG(10, ("sys_get_nfs_quotas: finished\n" ));
	return ret;
}

int sys_set_nfs_quota(const char *path, const char *bdev,
		      enum SMB_QUOTA_TYPE qtype,
		      unid_t id, SMB_DISK_QUOTA *dp)
{
	DEBUG(1, ("sys_set_nfs_quota : not supported\n"));
	errno = ENOSYS;
	return -1;
}

#else /* HAVE_NFS_QUOTAS */

void dummy_sysquotas_nfs(void);
void dummy_sysquotas_nfs(void) {}

#endif /* HAVE_NFS_QUOTAS */
