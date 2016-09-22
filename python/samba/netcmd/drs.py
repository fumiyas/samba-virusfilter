# implement samba_tool drs commands
#
# Copyright Andrew Tridgell 2010
#
# based on C implementation by Kamen Mazdrashki <kamen.mazdrashki@postpath.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import samba.getopt as options
import ldb
import logging

from samba.auth import system_session
from samba.netcmd import (
    Command,
    CommandError,
    Option,
    SuperCommand,
    )
from samba.samdb import SamDB
from samba import drs_utils, nttime2string, dsdb
from samba.dcerpc import drsuapi, misc
import common
from samba.join import join_clone

def drsuapi_connect(ctx):
    '''make a DRSUAPI connection to the server'''
    try:
        (ctx.drsuapi, ctx.drsuapi_handle, ctx.bind_supported_extensions) = drs_utils.drsuapi_connect(ctx.server, ctx.lp, ctx.creds)
    except Exception, e:
        raise CommandError("DRS connection to %s failed" % ctx.server, e)

def samdb_connect(ctx):
    '''make a ldap connection to the server'''
    try:
        ctx.samdb = SamDB(url="ldap://%s" % ctx.server,
                          session_info=system_session(),
                          credentials=ctx.creds, lp=ctx.lp)
    except Exception, e:
        raise CommandError("LDAP connection to %s failed" % ctx.server, e)

def drs_errmsg(werr):
    '''return "was successful" or an error string'''
    (ecode, estring) = werr
    if ecode == 0:
        return "was successful"
    return "failed, result %u (%s)" % (ecode, estring)



def attr_default(msg, attrname, default):
    '''get an attribute from a ldap msg with a default'''
    if attrname in msg:
        return msg[attrname][0]
    return default



def drs_parse_ntds_dn(ntds_dn):
    '''parse a NTDS DN returning a site and server'''
    a = ntds_dn.split(',')
    if a[0] != "CN=NTDS Settings" or a[2] != "CN=Servers" or a[4] != 'CN=Sites':
        raise RuntimeError("bad NTDS DN %s" % ntds_dn)
    server = a[1].split('=')[1]
    site   = a[3].split('=')[1]
    return (site, server)





class cmd_drs_showrepl(Command):
    """Show replication status."""

    synopsis = "%prog [<DC>] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ["DC?"]

    def print_neighbour(self, n):
        '''print one set of neighbour information'''
        self.message("%s" % n.naming_context_dn)
        try:
            (site, server) = drs_parse_ntds_dn(n.source_dsa_obj_dn)
            self.message("\t%s\%s via RPC" % (site, server))
        except RuntimeError:
            self.message("\tNTDS DN: %s" % n.source_dsa_obj_dn)
        self.message("\t\tDSA object GUID: %s" % n.source_dsa_obj_guid)
        self.message("\t\tLast attempt @ %s %s" % (nttime2string(n.last_attempt),
                                                   drs_errmsg(n.result_last_attempt)))
        self.message("\t\t%u consecutive failure(s)." % n.consecutive_sync_failures)
        self.message("\t\tLast success @ %s" % nttime2string(n.last_success))
        self.message("")

    def drsuapi_ReplicaInfo(ctx, info_type):
        '''call a DsReplicaInfo'''

        req1 = drsuapi.DsReplicaGetInfoRequest1()
        req1.info_type = info_type
        try:
            (info_type, info) = ctx.drsuapi.DsReplicaGetInfo(ctx.drsuapi_handle, 1, req1)
        except Exception, e:
            raise CommandError("DsReplicaGetInfo of type %u failed" % info_type, e)
        return (info_type, info)

    def run(self, DC=None, sambaopts=None,
            credopts=None, versionopts=None, server=None):

        self.lp = sambaopts.get_loadparm()
        if DC is None:
            DC = common.netcmd_dnsname(self.lp)
        self.server = DC
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        drsuapi_connect(self)
        samdb_connect(self)

        # show domain information
        ntds_dn = self.samdb.get_dsServiceName()
        server_dns = self.samdb.search(base="", scope=ldb.SCOPE_BASE, attrs=["dnsHostName"])[0]['dnsHostName'][0]

        (site, server) = drs_parse_ntds_dn(ntds_dn)
        try:
            ntds = self.samdb.search(base=ntds_dn, scope=ldb.SCOPE_BASE, attrs=['options', 'objectGUID', 'invocationId'])
        except Exception, e:
            raise CommandError("Failed to search NTDS DN %s" % ntds_dn)
        conn = self.samdb.search(base=ntds_dn, expression="(objectClass=nTDSConnection)")

        self.message("%s\\%s" % (site, server))
        self.message("DSA Options: 0x%08x" % int(attr_default(ntds[0], "options", 0)))
        self.message("DSA object GUID: %s" % self.samdb.schema_format_value("objectGUID", ntds[0]["objectGUID"][0]))
        self.message("DSA invocationId: %s\n" % self.samdb.schema_format_value("objectGUID", ntds[0]["invocationId"][0]))

        self.message("==== INBOUND NEIGHBORS ====\n")
        (info_type, info) = self.drsuapi_ReplicaInfo(drsuapi.DRSUAPI_DS_REPLICA_INFO_NEIGHBORS)
        for n in info.array:
            self.print_neighbour(n)


        self.message("==== OUTBOUND NEIGHBORS ====\n")
        (info_type, info) = self.drsuapi_ReplicaInfo(drsuapi.DRSUAPI_DS_REPLICA_INFO_REPSTO)
        for n in info.array:
            self.print_neighbour(n)

        reasons = ['NTDSCONN_KCC_GC_TOPOLOGY',
                   'NTDSCONN_KCC_RING_TOPOLOGY',
                   'NTDSCONN_KCC_MINIMIZE_HOPS_TOPOLOGY',
                   'NTDSCONN_KCC_STALE_SERVERS_TOPOLOGY',
                   'NTDSCONN_KCC_OSCILLATING_CONNECTION_TOPOLOGY',
                   'NTDSCONN_KCC_INTERSITE_GC_TOPOLOGY',
                   'NTDSCONN_KCC_INTERSITE_TOPOLOGY',
                   'NTDSCONN_KCC_SERVER_FAILOVER_TOPOLOGY',
                   'NTDSCONN_KCC_SITE_FAILOVER_TOPOLOGY',
                   'NTDSCONN_KCC_REDUNDANT_SERVER_TOPOLOGY']

        self.message("==== KCC CONNECTION OBJECTS ====\n")
        for c in conn:
            self.message("Connection --")

            c_rdn, sep, c_server_dn = c['fromServer'][0].partition(',')
            try:
                c_server_res = self.samdb.search(base=c_server_dn, scope=ldb.SCOPE_BASE, attrs=["dnsHostName"])
                c_server_dns = c_server_res[0]["dnsHostName"][0]
            except ldb.LdbError, (errno, _):
                if errno == ldb.ERR_NO_SUCH_OBJECT:
                    self.message("\tWARNING: Connection to DELETED server!")
                c_server_dns = ""
            except KeyError:
                c_server_dns = ""

            self.message("\tConnection name: %s" % c['name'][0])
            self.message("\tEnabled        : %s" % attr_default(c, 'enabledConnection', 'TRUE'))
            self.message("\tServer DNS name : %s" % c_server_dns)
            self.message("\tServer DN name  : %s" % c['fromServer'][0])
            self.message("\t\tTransportType: RPC")
            self.message("\t\toptions: 0x%08X" % int(attr_default(c, 'options', 0)))
            if not 'mS-DS-ReplicatesNCReason' in c:
                self.message("Warning: No NC replicated for Connection!")
                continue
            for r in c['mS-DS-ReplicatesNCReason']:
                a = str(r).split(':')
                self.message("\t\tReplicatesNC: %s" % a[3])
                self.message("\t\tReason: 0x%08x" % int(a[2]))
                for s in reasons:
                    if getattr(dsdb, s, 0) & int(a[2]):
                        self.message("\t\t\t%s" % s)



class cmd_drs_kcc(Command):
    """Trigger knowledge consistency center run."""

    synopsis = "%prog [<DC>] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ["DC?"]

    def run(self, DC=None, sambaopts=None,
            credopts=None, versionopts=None, server=None):

        self.lp = sambaopts.get_loadparm()
        if DC is None:
            DC = common.netcmd_dnsname(self.lp)
        self.server = DC

        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        drsuapi_connect(self)

        req1 = drsuapi.DsExecuteKCC1()
        try:
            self.drsuapi.DsExecuteKCC(self.drsuapi_handle, 1, req1)
        except Exception, e:
            raise CommandError("DsExecuteKCC failed", e)
        self.message("Consistency check on %s successful." % DC)



def drs_local_replicate(self, SOURCE_DC, NC):
    '''replicate from a source DC to the local SAM'''

    self.server = SOURCE_DC
    drsuapi_connect(self)

    self.local_samdb = SamDB(session_info=system_session(), url=None,
                             credentials=self.creds, lp=self.lp)

    self.samdb = SamDB(url="ldap://%s" % self.server,
                       session_info=system_session(),
                       credentials=self.creds, lp=self.lp)

    # work out the source and destination GUIDs
    res = self.local_samdb.search(base="", scope=ldb.SCOPE_BASE, attrs=["dsServiceName"])
    self.ntds_dn = res[0]["dsServiceName"][0]

    res = self.local_samdb.search(base=self.ntds_dn, scope=ldb.SCOPE_BASE, attrs=["objectGUID"])
    self.ntds_guid = misc.GUID(self.samdb.schema_format_value("objectGUID", res[0]["objectGUID"][0]))


    source_dsa_invocation_id = misc.GUID(self.samdb.get_invocation_id())
    dest_dsa_invocation_id = misc.GUID(self.local_samdb.get_invocation_id())
    destination_dsa_guid = self.ntds_guid

    self.samdb.transaction_start()
    repl = drs_utils.drs_Replicate("ncacn_ip_tcp:%s[seal]" % self.server, self.lp,
                                   self.creds, self.local_samdb, dest_dsa_invocation_id)

    # Work out if we are an RODC, so that a forced local replicate
    # with the admin pw does not sync passwords
    rodc = self.local_samdb.am_rodc()
    try:
        repl.replicate(NC, source_dsa_invocation_id, destination_dsa_guid, rodc=rodc)
    except Exception, e:
        raise CommandError("Error replicating DN %s" % NC, e)
    self.samdb.transaction_commit()

    self.message("Replicate from %s to %s was successful." % (SOURCE_DC, self.local_samdb.url))



class cmd_drs_replicate(Command):
    """Replicate a naming context between two DCs."""

    synopsis = "%prog <destinationDC> <sourceDC> <NC> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ["DEST_DC", "SOURCE_DC", "NC"]

    takes_options = [
        Option("--add-ref", help="use ADD_REF to add to repsTo on source", action="store_true"),
        Option("--sync-forced", help="use SYNC_FORCED to force inbound replication", action="store_true"),
        Option("--sync-all", help="use SYNC_ALL to replicate from all DCs", action="store_true"),
        Option("--full-sync", help="resync all objects", action="store_true"),
        Option("--local", help="pull changes directly into the local database (destination DC is ignored)", action="store_true"),
        Option("--local-online", help="pull changes into the local database (destination DC is ignored) as a normal online replication", action="store_true"),
        Option("--async-op", help="use ASYNC_OP for the replication", action="store_true"),
        ]

    def run(self, DEST_DC, SOURCE_DC, NC,
            add_ref=False, sync_forced=False, sync_all=False, full_sync=False,
            local=False, local_online=False, async_op=False,
            sambaopts=None, credopts=None, versionopts=None, server=None):

        self.server = DEST_DC
        self.lp = sambaopts.get_loadparm()

        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        if local:
            drs_local_replicate(self, SOURCE_DC, NC)
            return

        if local_online:
            server_bind = drsuapi.drsuapi("irpc:dreplsrv", lp_ctx=self.lp)
            server_bind_handle = misc.policy_handle()
        else:
            drsuapi_connect(self)
            server_bind = self.drsuapi
            server_bind_handle = self.drsuapi_handle

        if not async_op:
            # Give the sync replication 5 minutes time
            server_bind.request_timeout = 5 * 60

        samdb_connect(self)

        # we need to find the NTDS GUID of the source DC
        msg = self.samdb.search(base=self.samdb.get_config_basedn(),
                                expression="(&(objectCategory=server)(|(name=%s)(dNSHostName=%s)))" % (
            ldb.binary_encode(SOURCE_DC),
            ldb.binary_encode(SOURCE_DC)),
                                attrs=[])
        if len(msg) == 0:
            raise CommandError("Failed to find source DC %s" % SOURCE_DC)
        server_dn = msg[0]['dn']

        msg = self.samdb.search(base=server_dn, scope=ldb.SCOPE_ONELEVEL,
                                expression="(|(objectCategory=nTDSDSA)(objectCategory=nTDSDSARO))",
                                attrs=['objectGUID', 'options'])
        if len(msg) == 0:
            raise CommandError("Failed to find source NTDS DN %s" % SOURCE_DC)
        source_dsa_guid = msg[0]['objectGUID'][0]
        dsa_options = int(attr_default(msg, 'options', 0))


        req_options = 0
        if not (dsa_options & dsdb.DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL):
            req_options |= drsuapi.DRSUAPI_DRS_WRIT_REP
        if add_ref:
            req_options |= drsuapi.DRSUAPI_DRS_ADD_REF
        if sync_forced:
            req_options |= drsuapi.DRSUAPI_DRS_SYNC_FORCED
        if sync_all:
            req_options |= drsuapi.DRSUAPI_DRS_SYNC_ALL
        if full_sync:
            req_options |= drsuapi.DRSUAPI_DRS_FULL_SYNC_NOW
        if async_op:
            req_options |= drsuapi.DRSUAPI_DRS_ASYNC_OP

        try:
            drs_utils.sendDsReplicaSync(server_bind, server_bind_handle, source_dsa_guid, NC, req_options)
        except drs_utils.drsException, estr:
            raise CommandError("DsReplicaSync failed", estr)
        if async_op:
            self.message("Replicate from %s to %s was started." % (SOURCE_DC, DEST_DC))
        else:
            self.message("Replicate from %s to %s was successful." % (SOURCE_DC, DEST_DC))



class cmd_drs_bind(Command):
    """Show DRS capabilities of a server."""

    synopsis = "%prog [<DC>] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ["DC?"]

    def run(self, DC=None, sambaopts=None,
            credopts=None, versionopts=None, server=None):

        self.lp = sambaopts.get_loadparm()
        if DC is None:
            DC = common.netcmd_dnsname(self.lp)
        self.server = DC
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        drsuapi_connect(self)

        bind_info = drsuapi.DsBindInfoCtr()
        bind_info.length = 28
        bind_info.info = drsuapi.DsBindInfo28()
        (info, handle) = self.drsuapi.DsBind(misc.GUID(drsuapi.DRSUAPI_DS_BIND_GUID), bind_info)

        optmap = [
            ("DRSUAPI_SUPPORTED_EXTENSION_BASE",     "DRS_EXT_BASE"),
            ("DRSUAPI_SUPPORTED_EXTENSION_ASYNC_REPLICATION",   "DRS_EXT_ASYNCREPL"),
            ("DRSUAPI_SUPPORTED_EXTENSION_REMOVEAPI",    "DRS_EXT_REMOVEAPI"),
            ("DRSUAPI_SUPPORTED_EXTENSION_MOVEREQ_V2",   "DRS_EXT_MOVEREQ_V2"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHG_COMPRESS",   "DRS_EXT_GETCHG_DEFLATE"),
            ("DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V1",    "DRS_EXT_DCINFO_V1"),
            ("DRSUAPI_SUPPORTED_EXTENSION_RESTORE_USN_OPTIMIZATION",   "DRS_EXT_RESTORE_USN_OPTIMIZATION"),
            ("DRSUAPI_SUPPORTED_EXTENSION_ADDENTRY",    "DRS_EXT_ADDENTRY"),
            ("DRSUAPI_SUPPORTED_EXTENSION_KCC_EXECUTE",   "DRS_EXT_KCC_EXECUTE"),
            ("DRSUAPI_SUPPORTED_EXTENSION_ADDENTRY_V2",   "DRS_EXT_ADDENTRY_V2"),
            ("DRSUAPI_SUPPORTED_EXTENSION_LINKED_VALUE_REPLICATION",   "DRS_EXT_LINKED_VALUE_REPLICATION"),
            ("DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V2",    "DRS_EXT_DCINFO_V2"),
            ("DRSUAPI_SUPPORTED_EXTENSION_INSTANCE_TYPE_NOT_REQ_ON_MOD","DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD"),
            ("DRSUAPI_SUPPORTED_EXTENSION_CRYPTO_BIND",   "DRS_EXT_CRYPTO_BIND"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GET_REPL_INFO",   "DRS_EXT_GET_REPL_INFO"),
            ("DRSUAPI_SUPPORTED_EXTENSION_STRONG_ENCRYPTION",   "DRS_EXT_STRONG_ENCRYPTION"),
            ("DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V01",   "DRS_EXT_DCINFO_VFFFFFFFF"),
            ("DRSUAPI_SUPPORTED_EXTENSION_TRANSITIVE_MEMBERSHIP",  "DRS_EXT_TRANSITIVE_MEMBERSHIP"),
            ("DRSUAPI_SUPPORTED_EXTENSION_ADD_SID_HISTORY",   "DRS_EXT_ADD_SID_HISTORY"),
            ("DRSUAPI_SUPPORTED_EXTENSION_POST_BETA3",   "DRS_EXT_POST_BETA3"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V5",   "DRS_EXT_GETCHGREQ_V5"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GET_MEMBERSHIPS2",   "DRS_EXT_GETMEMBERSHIPS2"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V6",   "DRS_EXT_GETCHGREQ_V6"),
            ("DRSUAPI_SUPPORTED_EXTENSION_NONDOMAIN_NCS",   "DRS_EXT_NONDOMAIN_NCS"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V8",   "DRS_EXT_GETCHGREQ_V8"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V5",   "DRS_EXT_GETCHGREPLY_V5"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V6",   "DRS_EXT_GETCHGREPLY_V6"),
            ("DRSUAPI_SUPPORTED_EXTENSION_ADDENTRYREPLY_V3",   "DRS_EXT_WHISTLER_BETA3"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V7",   "DRS_EXT_WHISTLER_BETA3"),
            ("DRSUAPI_SUPPORTED_EXTENSION_VERIFY_OBJECT",   "DRS_EXT_WHISTLER_BETA3"),
            ("DRSUAPI_SUPPORTED_EXTENSION_XPRESS_COMPRESS",   "DRS_EXT_W2K3_DEFLATE"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V10",   "DRS_EXT_GETCHGREQ_V10"),
            ("DRSUAPI_SUPPORTED_EXTENSION_RESERVED_PART2",   "DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART2"),
            ("DRSUAPI_SUPPORTED_EXTENSION_RESERVED_PART3", "DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART3")
            ]

        optmap_ext = [
            ("DRSUAPI_SUPPORTED_EXTENSION_ADAM", "DRS_EXT_ADAM"),
            ("DRSUAPI_SUPPORTED_EXTENSION_LH_BETA2", "DRS_EXT_LH_BETA2"),
            ("DRSUAPI_SUPPORTED_EXTENSION_RECYCLE_BIN", "DRS_EXT_RECYCLE_BIN")]

        self.message("Bind to %s succeeded." % DC)
        self.message("Extensions supported:")
        for (opt, str) in optmap:
            optval = getattr(drsuapi, opt, 0)
            if info.info.supported_extensions & optval:
                yesno = "Yes"
            else:
                yesno = "No "
            self.message("  %-60s: %s (%s)" % (opt, yesno, str))

        if isinstance(info.info, drsuapi.DsBindInfo48):
            self.message("\nExtended Extensions supported:")
            for (opt, str) in optmap_ext:
                optval = getattr(drsuapi, opt, 0)
                if info.info.supported_extensions_ext & optval:
                    yesno = "Yes"
                else:
                    yesno = "No "
                self.message("  %-60s: %s (%s)" % (opt, yesno, str))

        self.message("\nSite GUID: %s" % info.info.site_guid)
        self.message("Repl epoch: %u" % info.info.repl_epoch)
        if isinstance(info.info, drsuapi.DsBindInfo48):
            self.message("Forest GUID: %s" % info.info.config_dn_guid)



class cmd_drs_options(Command):
    """Query or change 'options' for NTDS Settings object of a Domain Controller."""

    synopsis = "%prog [<DC>] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ["DC?"]

    takes_options = [
        Option("--dsa-option", help="DSA option to enable/disable", type="str",
               metavar="{+|-}IS_GC | {+|-}DISABLE_INBOUND_REPL | {+|-}DISABLE_OUTBOUND_REPL | {+|-}DISABLE_NTDSCONN_XLATE" ),
        ]

    option_map = {"IS_GC": 0x00000001,
                  "DISABLE_INBOUND_REPL": 0x00000002,
                  "DISABLE_OUTBOUND_REPL": 0x00000004,
                  "DISABLE_NTDSCONN_XLATE": 0x00000008}

    def run(self, DC=None, dsa_option=None,
            sambaopts=None, credopts=None, versionopts=None):

        self.lp = sambaopts.get_loadparm()
        if DC is None:
            DC = common.netcmd_dnsname(self.lp)
        self.server = DC
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        samdb_connect(self)

        ntds_dn = self.samdb.get_dsServiceName()
        res = self.samdb.search(base=ntds_dn, scope=ldb.SCOPE_BASE, attrs=["options"])
        dsa_opts = int(res[0]["options"][0])

        # print out current DSA options
        cur_opts = [x for x in self.option_map if self.option_map[x] & dsa_opts]
        self.message("Current DSA options: " + ", ".join(cur_opts))

        # modify options
        if dsa_option:
            if dsa_option[:1] not in ("+", "-"):
                raise CommandError("Unknown option %s" % dsa_option)
            flag = dsa_option[1:]
            if flag not in self.option_map.keys():
                raise CommandError("Unknown option %s" % dsa_option)
            if dsa_option[:1] == "+":
                dsa_opts |= self.option_map[flag]
            else:
                dsa_opts &= ~self.option_map[flag]
            #save new options
            m = ldb.Message()
            m.dn = ldb.Dn(self.samdb, ntds_dn)
            m["options"]= ldb.MessageElement(str(dsa_opts), ldb.FLAG_MOD_REPLACE, "options")
            self.samdb.modify(m)
            # print out new DSA options
            cur_opts = [x for x in self.option_map if self.option_map[x] & dsa_opts]
            self.message("New DSA options: " + ", ".join(cur_opts))


class cmd_drs_clone_dc_database(Command):
    """Replicate an initial clone of domain, but DO NOT JOIN it."""

    synopsis = "%prog <dnsdomain> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("--server", help="DC to join", type=str),
        Option("--targetdir", help="where to store provision (required)", type=str),
        Option("--quiet", help="Be quiet", action="store_true"),
        Option("--include-secrets", help="Also replicate secret values", action="store_true"),
        Option("--verbose", help="Be verbose", action="store_true")
       ]

    takes_args = ["domain"]

    def run(self, domain, sambaopts=None, credopts=None,
            versionopts=None, server=None, targetdir=None,
            quiet=False, verbose=False, include_secrets=False):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        logger = self.get_logger()
        if verbose:
            logger.setLevel(logging.DEBUG)
        elif quiet:
            logger.setLevel(logging.WARNING)
        else:
            logger.setLevel(logging.INFO)

        if targetdir is None:
            raise CommandError("--targetdir option must be specified")


        join_clone(logger=logger, server=server, creds=creds, lp=lp, domain=domain,
                   targetdir=targetdir, include_secrets=include_secrets)


class cmd_drs(SuperCommand):
    """Directory Replication Services (DRS) management."""

    subcommands = {}
    subcommands["bind"] = cmd_drs_bind()
    subcommands["kcc"] = cmd_drs_kcc()
    subcommands["replicate"] = cmd_drs_replicate()
    subcommands["showrepl"] = cmd_drs_showrepl()
    subcommands["options"] = cmd_drs_options()
    subcommands["clone-dc-database"] = cmd_drs_clone_dc_database()
