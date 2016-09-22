#!/usr/bin/python
# This script generates a list of testsuites that should be run as part of
# the Samba 3 test suite.

# The output of this script is parsed by selftest.pl, which then decides
# which of the tests to actually run. It will, for example, skip all tests
# listed in selftest/skip or only run a subset during "make quicktest".

# The idea is that this script outputs all of the tests of Samba 3, not
# just those that are known to pass, and list those that should be skipped
# or are known to fail in selftest/skip or selftest/samba3-knownfail. This makes it
# very easy to see what functionality is still missing in Samba 3 and makes
# it possible to run the testsuite against other servers, such as Samba 4 or
# Windows that have a different set of features.

# The syntax for a testsuite is "-- TEST --" on a single line, followed
# by the name of the test, the environment it needs and the command to run, all
# three separated by newlines. All other lines in the output are considered
# comments.

import os, sys
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), "../../selftest")))
import selftesthelpers
from selftesthelpers import *
smbtorture4_options.extend([
   '--option=torture:sharedelay=100000',
   '--option=torture:writetimeupdatedelay=500000',
   ])

def plansmbtorture4testsuite(name, env, options, description=''):
    if description == '':
        modname = "samba3.%s" % (name, )
    else:
        modname = "samba3.%s %s" % (name, description)

    selftesthelpers.plansmbtorture4testsuite(
        name, env, options, target='samba3', modname=modname)


plantestsuite("samba3.blackbox.success", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/test_success.sh")])
plantestsuite("samba3.blackbox.failure", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/test_failure.sh")])

plantestsuite("samba3.local_s3", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/test_local_s3.sh")])

plantestsuite("samba3.blackbox.registry.upgrade", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/test_registry_upgrade.sh"), net, dbwrap_tool])

tests = ["FDPASS", "LOCK1", "LOCK2", "LOCK3", "LOCK4", "LOCK5", "LOCK6", "LOCK7", "LOCK9",
        "UNLINK", "BROWSE", "ATTR", "TRANS2", "TORTURE",
        "OPLOCK1", "OPLOCK2", "OPLOCK4", "STREAMERROR",
        "DIR", "DIR1", "DIR-CREATETIME", "TCON", "TCONDEV", "RW1", "RW2", "RW3", "LARGE_READX", "RW-SIGNING",
        "OPEN", "XCOPY", "RENAME", "DELETE", "DELETE-LN", "WILDDELETE", "PROPERTIES", "W2K",
        "TCON2", "IOCTL", "CHKPATH", "FDSESS", "CHAIN1", "CHAIN2",
        "CHAIN3", "PIDHIGH",
        "GETADDRINFO", "UID-REGRESSION-TEST", "SHORTNAME-TEST",
        "CASE-INSENSITIVE-CREATE", "SMB2-BASIC", "NTTRANS-FSCTL", "SMB2-NEGPROT",
        "SMB2-SESSION-REAUTH", "SMB2-SESSION-RECONNECT",
        "CLEANUP1",
        "CLEANUP2",
        "CLEANUP4",
        "BAD-NBT-SESSION"]

for t in tests:
    plantestsuite("samba3.smbtorture_s3.plain(nt4_dc).%s" % t, "nt4_dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmp', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])
    plantestsuite("samba3.smbtorture_s3.crypt_client(nt4_dc).%s" % t, "nt4_dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmp', '$USERNAME', '$PASSWORD', smbtorture3, "-e", "-l $LOCAL_PATH"])
    if t == "TORTURE":
        # this is a negative test to verify that the server rejects
        # access without encryption
        plantestsuite("samba3.smbtorture_s3.crypt_server(nt4_dc).%s" % t, "nt4_dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmpenc', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])
    plantestsuite("samba3.smbtorture_s3.plain(ad_dc_ntvfs).%s" % t, "ad_dc_ntvfs", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmp', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])

# non-crypt only

tests = ["OPLOCK-CANCEL"]
for t in tests:
    plantestsuite("samba3.smbtorture_s3.plain(nt4_dc).%s" % t, "nt4_dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmp', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])

tests = ["RW1", "RW2", "RW3"]
for t in tests:
    plantestsuite("samba3.smbtorture_s3.vfs_aio_fork(simpleserver).%s" % t, "simpleserver", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/vfs_aio_fork', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])

posix_tests = ["POSIX", "POSIX-APPEND", "POSIX-SYMLINK-ACL", "POSIX-SYMLINK-EA", "POSIX-OFD-LOCK",
              "POSIX-STREAM-DELETE" ]

for t in posix_tests:
    plantestsuite("samba3.smbtorture_s3.plain(nt4_dc).%s" % t, "nt4_dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/posix_share', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])
    plantestsuite("samba3.smbtorture_s3.crypt(nt4_dc).%s" % t, "nt4_dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/posix_share', '$USERNAME', '$PASSWORD', smbtorture3, "-e", "-l $LOCAL_PATH"])
    plantestsuite("samba3.smbtorture_s3.plain(ad_dc_ntvfs).%s" % t, "ad_dc_ntvfs", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/posix_share', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])

env = "nt4_dc:local"
t = "CLEANUP3"
plantestsuite("samba3.smbtorture_s3.plain(%s).%s" % (env, t), env, [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmp', '$USERNAME', '$PASSWORD', binpath('smbtorture3'), "", "-l $LOCAL_PATH"])

local_tests = [
    "LOCAL-SUBSTITUTE",
    "LOCAL-GENCACHE",
    "LOCAL-TALLOC-DICT",
    "LOCAL-BASE64",
    "LOCAL-RBTREE",
    "LOCAL-MEMCACHE",
    "LOCAL-STREAM-NAME",
    "LOCAL-string_to_sid",
    "LOCAL-sid_to_string",
    "LOCAL-binary_to_sid",
    "LOCAL-DBTRANS",
    "LOCAL-TEVENT-SELECT",
    "LOCAL-CONVERT-STRING",
    "LOCAL-CONV-AUTH-INFO",
    "LOCAL-IDMAP-TDB-COMMON",
    "LOCAL-MESSAGING-READ1",
    "LOCAL-MESSAGING-READ2",
    "LOCAL-MESSAGING-READ3",
    "LOCAL-MESSAGING-READ4",
    "LOCAL-MESSAGING-FDPASS1",
    "LOCAL-MESSAGING-FDPASS2",
    "LOCAL-MESSAGING-FDPASS2a",
    "LOCAL-MESSAGING-FDPASS2b",
    "LOCAL-PTHREADPOOL-TEVENT",
    "LOCAL-hex_encode_buf",
    "LOCAL-remove_duplicate_addrs2"]

for t in local_tests:
    plantestsuite("samba3.smbtorture_s3.%s" % t, "none", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//foo/bar', '""', '""', smbtorture3, ""])

plantestsuite("samba.vfstest.stream_depot", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/stream-depot/run.sh"), binpath("vfstest"), "$PREFIX", configuration])
plantestsuite("samba.vfstest.xattr-tdb-1", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/xattr-tdb-1/run.sh"), binpath("vfstest"), "$PREFIX", configuration])
plantestsuite("samba.vfstest.acl", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/vfstest-acl/run.sh"), binpath("vfstest"), "$PREFIX", configuration])
plantestsuite("samba.vfstest.catia", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/vfstest-catia/run.sh"), binpath("vfstest"), "$PREFIX", configuration])

for options in ["", "--option=clientntlmv2auth=no", "--option=clientusespnego=no", "--option=clientusespnego=no --option=clientntlmv2auth=no", "--option=clientntlmv2auth=no --option=clientlanmanauth=yes --max-protocol=LANMAN2", "--option=clientntlmv2auth=no --option=clientlanmanauth=yes --option=clientmaxprotocol=NT1"]:
    env = "nt4_dc"
    plantestsuite("samba3.blackbox.smbclient_auth.plain (%s) %s" % (env, options), env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME', '$DC_PASSWORD', smbclient3, configuration, options])

for env in ["nt4_dc", "nt4_member", "ad_member", "ad_dc", "ad_dc_ntvfs", "s4member", "fl2000dc"]:
    plantestsuite("samba3.blackbox.smbclient_machine_auth.plain (%s:local)" % env, "%s:local" % env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_machine_auth.sh"), '$SERVER', smbclient3, configuration])
    plantestsuite("samba3.blackbox.smbclient_ntlm.plain (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_ntlm.sh"), '$SERVER', '$DC_USERNAME', '$DC_PASSWORD', "never", smbclient3, configuration])

for options in ["--option=clientntlmv2auth=no", "--option=clientusespnego=no --option=clientntlmv2auth=no", ""]:
    for env in ["nt4_member", "ad_member"]:
        plantestsuite("samba3.blackbox.smbclient_auth.plain (%s) %s" % (env, options), env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME', '$DC_PASSWORD', smbclient3, configuration, options])
        plantestsuite("samba3.blackbox.smbclient_auth.plain (%s) %s member creds" % (env, options), env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '$SERVER/$USERNAME', '$PASSWORD', smbclient3, configuration, options])

env="nt4_dc"
plantestsuite("samba3.blackbox.smbclient_auth.plain (%s) ipv6" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IPV6', '$SERVER/$USERNAME', '$PASSWORD', smbclient3, configuration])

for env in ["nt4_member", "ad_member"]:
    plantestsuite("samba3.blackbox.net_cred_change.(%s:local)" % env, "%s:local" % env, [os.path.join(samba3srcdir, "script/tests/test_net_cred_change.sh"), configuration])

env = "ad_member"
t = "--krb5auth=$DOMAIN/$DC_USERNAME%$DC_PASSWORD"
plantestsuite("samba3.wbinfo_simple.(%s:local).%s" % (env, t), "%s:local" % env, [os.path.join(srcdir(), "nsswitch/tests/test_wbinfo_simple.sh"), t])
t = "WBCLIENT-MULTI-PING"
plantestsuite("samba3.smbtorture_s3.%s" % t, env, [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//foo/bar', '""', '""', smbtorture3, ""])


plantestsuite("samba3.ntlm_auth.krb5(ktest:local) old ccache", "ktest:local", [os.path.join(samba3srcdir, "script/tests/test_ntlm_auth_krb5.sh"), valgrindify(python), samba3srcdir, ntlm_auth3, '$PREFIX/ktest/krb5_ccache-2', '$SERVER', configuration])

plantestsuite("samba3.ntlm_auth.krb5(ktest:local)", "ktest:local", [os.path.join(samba3srcdir, "script/tests/test_ntlm_auth_krb5.sh"), valgrindify(python), samba3srcdir, ntlm_auth3, '$PREFIX/ktest/krb5_ccache-3', '$SERVER', configuration])


for env in ["maptoguest", "simpleserver"]:
    plantestsuite("samba3.blackbox.smbclient_auth.plain (%s) local creds" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', smbclient3, configuration + " --option=clientntlmv2auth=no --option=clientlanmanauth=yes"])

env = "maptoguest"
plantestsuite("samba3.blackbox.smbclient_auth.plain (%s) bad username" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', 'notmy$USERNAME', '$PASSWORD', smbclient3, configuration + " --option=clientntlmv2auth=no --option=clientlanmanauth=yes"])
plantestsuite("samba3.blackbox.smbclient_ntlm.plain (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_ntlm.sh"), '$SERVER', '$USERNAME', '$PASSWORD', "baduser", smbclient3, configuration])

# plain
for env in ["nt4_dc"]:
    plantestsuite("samba3.blackbox.smbclient_s3.plain (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$DC_USERNAME', '$DC_PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration])

for env in ["nt4_member", "ad_member"]:
    plantestsuite("samba3.blackbox.smbclient_s3.plain (%s) member creds" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$SERVER', '$SERVER/$USERNAME', '$PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration])

for env in ["nt4_dc"]:
    plantestsuite("samba3.blackbox.smbclient_s3.sign (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$DC_USERNAME', '$DC_PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "--signing=required"])

for env in ["nt4_member", "ad_member"]:
    plantestsuite("samba3.blackbox.smbclient_s3.sign (%s) member creds" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$SERVER', '$SERVER/$USERNAME', '$PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "--signing=required"])

for env in ["nt4_dc"]:
    # encrypted
    plantestsuite("samba3.blackbox.smbclient_s3.crypt (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$USERNAME', '$PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "-e"])

for env in ["fileserver"]:
    plantestsuite("samba3.blackbox.preserve_case (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_preserve_case.sh"), '$SERVER', '$DOMAIN', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3])
    plantestsuite("samba3.blackbox.dfree_command (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_dfree_command.sh"), '$SERVER', '$DOMAIN', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3])
    plantestsuite("samba3.blackbox.dfree_quota (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_dfree_quota.sh"), '$SERVER', '$DOMAIN', '$USERNAME', '$PASSWORD', '$LOCAL_PATH', smbclient3, smbcquotas, smbcacls])
    plantestsuite("samba3.blackbox.valid_users (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_valid_users.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3])
    plantestsuite("samba3.blackbox.offline (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_offline.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/offline', smbclient3])
    plantestsuite("samba3.blackbox.shadow_copy2 NT1 (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_shadow_copy.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/shadow', smbclient3, '-m', 'NT1'])
    plantestsuite("samba3.blackbox.shadow_copy2 SMB3 (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_shadow_copy.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/shadow', smbclient3, '-m', 'SMB3'])
    plantestsuite("samba3.blackbox.smbclient.forceuser_validusers (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_forceuser_validusers.sh"), '$SERVER', '$DOMAIN', '$USERNAME', '$PASSWORD', '$LOCAL_PATH', smbclient3])
    plantestsuite("samba3.blackbox.smbget (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbget.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', 'smbget_user', '$PASSWORD', '$LOCAL_PATH/smbget', smbget])
    plantestsuite("samba3.blackbox.netshareenum (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_shareenum.sh"), '$SERVER', '$USERNAME', '$PASSWORD', rpcclient])
    plantestsuite("samba3.blackbox.acl_xattr (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_acl_xattr.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, smbcacls])
    plantestsuite("samba3.blackbox.smb2.not_casesensitive (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smb2_not_casesensitive.sh"), '//$SERVER/tmp', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH', smbclient3])
    plantestsuite("samba3.blackbox.inherit_owner.default(%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_inherit_owner.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, smbcacls, 'tmp', '0', '0', '-m', 'NT1'])
    plantestsuite("samba3.blackbox.inherit_owner.full (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_inherit_owner.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, smbcacls, 'inherit_owner', '1', '1', '-m', 'NT1'])
    plantestsuite("samba3.blackbox.inherit_owner.unix (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_inherit_owner.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, smbcacls, 'inherit_owner_u', '0', '1', '-m', 'NT1'])

    #
    # tar command tests
    #

    # find config.h
    try:
        config_h = os.environ["CONFIG_H"]
    except KeyError:
        samba4bindir = bindir()
        config_h = os.path.join(samba4bindir, "default/include/config.h")

    # see if libarchive is supported
    f = open(config_h, 'r')
    try:
        have_libarchive = ("HAVE_LIBARCHIVE 1" in f.read())
    finally:
        f.close()

    # tar command enabled only if built with libarchive
    if have_libarchive:
        # Test smbclient/tarmode
        plantestsuite("samba3.blackbox.smbclient_tarmode (%s)" % env, env,
                      [os.path.join(samba3srcdir, "script/tests/test_smbclient_tarmode.sh"),
                       '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD',
                       '$LOCAL_PATH', '$PREFIX', smbclient3, configuration])

        # Test suite for new smbclient/tar with libarchive (GSoC 13)
        plantestsuite("samba3.blackbox.smbclient_tar (%s)" % env, env,
                      [os.path.join(samba3srcdir, "script/tests/test_smbclient_tarmode.pl"),
                       '-n', '$SERVER', '-i', '$SERVER_IP', '-s', 'tmp',
                       '-u', '$USERNAME', '-p', '$PASSWORD', '-l', '$LOCAL_PATH',
                       '-d', '$PREFIX', '-b', smbclient3,
                       '--subunit', '--', configuration])

#TODO encrypted against member, with member creds, and with DC creds
plantestsuite("samba3.blackbox.net.misc", "nt4_dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_misc.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration])
plantestsuite("samba3.blackbox.net.local.registry", "nt4_dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_registry.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration])
plantestsuite("samba3.blackbox.net.registry.check", "nt4_dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_registry_check.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration, dbwrap_tool])
plantestsuite("samba3.blackbox.net.rpc.registry", "nt4_dc",
              [os.path.join(samba3srcdir, "script/tests/test_net_registry.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration, 'rpc'])

plantestsuite("samba3.blackbox.net.local.registry.roundtrip", "nt4_dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_registry_roundtrip.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration])
plantestsuite("samba3.blackbox.net.rpc.registry.roundtrip", "nt4_dc",
              [os.path.join(samba3srcdir, "script/tests/test_net_registry_roundtrip.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration, 'rpc'])

plantestsuite("samba3.blackbox.net.local.conf", "nt4_dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_conf.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration])
plantestsuite("samba3.blackbox.net.rpc.conf", "nt4_dc",
              [os.path.join(samba3srcdir, "script/tests/test_net_conf.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration, 'rpc'])


plantestsuite("samba3.blackbox.testparm", "nt4_dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_testparm_s3.sh"),
               "$LOCAL_PATH"])

plantestsuite(
    "samba3.pthreadpool", "nt4_dc",
    [os.path.join(samba3srcdir, "script/tests/test_pthreadpool.sh")])

plantestsuite("samba3.async_req", "nt4_dc",
              [os.path.join(samba3srcdir, "script/tests/test_async_req.sh")])

#smbtorture4 tests

base = ["base.attr", "base.charset", "base.chkpath", "base.defer_open", "base.delaywrite", "base.delete",
        "base.deny1", "base.deny2", "base.deny3", "base.denydos", "base.dir1", "base.dir2",
        "base.disconnect", "base.fdpass", "base.lock",
        "base.mangle", "base.negnowait", "base.ntdeny1",
        "base.ntdeny2", "base.open", "base.openattr", "base.properties", "base.rename", "base.rw1",
        "base.secleak", "base.tcon", "base.tcondev", "base.trans2", "base.unlink", "base.vuid",
        "base.xcopy", "base.samba3error"]

raw = ["raw.acls", "raw.chkpath", "raw.close", "raw.composite", "raw.context", "raw.eas",
       "raw.ioctl", "raw.lock", "raw.mkdir", "raw.mux", "raw.notify", "raw.open", "raw.oplock",
       "raw.qfileinfo", "raw.qfsinfo", "raw.read", "raw.rename", "raw.search", "raw.seek",
       "raw.sfileinfo.base", "raw.sfileinfo.bug", "raw.streams", "raw.unlink", "raw.write",
       "raw.samba3hide", "raw.samba3badpath", "raw.sfileinfo.rename", "raw.session",
       "raw.samba3caseinsensitive", "raw.samba3posixtimedlock",
       "raw.samba3rootdirfid", "raw.sfileinfo.end-of-file",
       "raw.bench-oplock", "raw.bench-lock", "raw.bench-open", "raw.bench-tcon",
       "raw.samba3checkfsp", "raw.samba3closeerr", "raw.samba3oplocklogoff", "raw.samba3badnameblob"]

smb2 = smbtorture4_testsuites("smb2.")

rpc = ["rpc.authcontext", "rpc.samba3.bind", "rpc.samba3.srvsvc", "rpc.samba3.sharesec",
       "rpc.samba3.spoolss", "rpc.samba3.wkssvc", "rpc.samba3.winreg",
       "rpc.samba3.getaliasmembership-0",
       "rpc.samba3.netlogon", "rpc.samba3.sessionkey", "rpc.samba3.getusername",
       "rpc.samba3.smb1-pipe-name", "rpc.samba3.smb2-pipe-name",
       "rpc.samba3.smb-reauth1", "rpc.samba3.smb-reauth2",
       "rpc.svcctl", "rpc.ntsvcs", "rpc.winreg", "rpc.eventlog",
       "rpc.spoolss.printserver", "rpc.spoolss.win", "rpc.spoolss.notify", "rpc.spoolss.printer",
       "rpc.spoolss.driver",
       "rpc.lsa", "rpc.lsa-getuser", "rpc.lsa.lookupsids", "rpc.lsa.lookupnames",
       "rpc.lsa.privileges", "rpc.lsa.secrets",
       "rpc.samr", "rpc.samr.users", "rpc.samr.users.privileges", "rpc.samr.passwords",
       "rpc.samr.passwords.pwdlastset", "rpc.samr.passwords.lockout", "rpc.samr.passwords.badpwdcount", "rpc.samr.large-dc", "rpc.samr.machine.auth",
       "rpc.samr.priv", "rpc.samr.passwords.validate",
       "rpc.netlogon.admin",
       "rpc.schannel", "rpc.schannel2", "rpc.bench-schannel1", "rpc.schannel_anon_setpw", "rpc.join", "rpc.bind"]

local = ["local.nss"]

idmap = ["idmap.rfc2307", "idmap.alloc"]

rap = ["rap.basic", "rap.rpc", "rap.printing", "rap.sam"]

unix = ["unix.info2", "unix.whoami"]

nbt = ["nbt.dgram" ]

libsmbclient = ["libsmbclient"]

vfs = ["vfs.fruit", "vfs.acl_xattr"]

tests= base + raw + smb2 + rpc + unix + local + rap + nbt + libsmbclient + idmap + vfs

for t in tests:
    if t == "base.delaywrite":
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD -k yes --maximum-runtime=900')
    elif t == "rap.sam":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD --option=doscharset=ISO-8859-1')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD --option=doscharset=ISO-8859-1')
    elif t == "winbind.pac":
        plansmbtorture4testsuite(t, "ad_member:local", '//$SERVER/tmp --realm=$REALM --machine-pass --option=torture:addc=$DC_SERVER', description="machine account")
    elif t == "unix.whoami":
        plansmbtorture4testsuite(t, "nt4_member:local", '//$SERVER/tmp --machine-pass', description="machine account")
        plansmbtorture4testsuite(t, "ad_member:local", '//$SERVER/tmp --machine-pass --option=torture:addc=$DC_SERVER', description="machine account")
        for env in ["nt4_dc", "nt4_member"]:
            plansmbtorture4testsuite(t, env, '//$SERVER/tmp -U$DC_USERNAME%$DC_PASSWORD')
            plansmbtorture4testsuite(t, env, '//$SERVER/tmpguest -U%', description='anonymous connection')
        for env in ["ad_dc", "ad_member"]:
            plansmbtorture4testsuite(t, env, '//$SERVER/tmp -U$DC_USERNAME@$REALM%$DC_PASSWORD --option=torture:addc=$DC_SERVER')
            plansmbtorture4testsuite(t, env, '//$SERVER/tmp -k yes -U$DC_USERNAME@$REALM%$DC_PASSWORD --option=torture:addc=$DC_SERVER', description='kerberos connection')
            plansmbtorture4testsuite(t, env, '//$SERVER/tmpguest -U% --option=torture:addc=$DC_SERVER', description='anonymous connection')
    elif t == "raw.samba3posixtimedlock":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmpguest -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/nt4_dc/share')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER_IP/tmpguest -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/ad_dc/share')
    elif t == "raw.chkpath":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmpcase -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER_IP/tmpcase -U$USERNAME%$PASSWORD')
    elif t == "raw.samba3hide" or t == "raw.samba3checkfsp" or t ==  "raw.samba3closeerr":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "simpleserver", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "raw.session" or t == "smb2.session":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD', 'plain')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmpenc -U$USERNAME%$PASSWORD', 'enc')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -k no -U$USERNAME%$PASSWORD', 'ntlm')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -k yes -U$USERNAME%$PASSWORD', 'krb5')
    elif t == "rpc.lsa":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD', 'over ncacn_np ')
        plansmbtorture4testsuite(t, "nt4_dc", 'ncacn_ip_tcp:$SERVER_IP -U$USERNAME%$PASSWORD', 'over ncacn_ip_tcp ')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD', 'over ncacn_np ')
        plansmbtorture4testsuite(t, "ad_dc", 'ncacn_ip_tcp:$SERVER_IP -U$USERNAME%$PASSWORD', 'over ncacn_ip_tcp ')
    elif t == "rpc.samr.passwords.validate":
        plansmbtorture4testsuite(t, "nt4_dc", 'ncacn_ip_tcp:$SERVER_IP[seal] -U$USERNAME%$PASSWORD', 'over ncacn_ip_tcp ')
        plansmbtorture4testsuite(t, "ad_dc", 'ncacn_ip_tcp:$SERVER_IP[seal] -U$USERNAME%$PASSWORD', 'over ncacn_ip_tcp ')
    elif t == "smb2.durable-open" or t == "smb2.durable-v2-open" or t == "smb2.replay":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/durable -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER_IP/durable -U$USERNAME%$PASSWORD')
    elif t == "base.rw1":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/valid-users-tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/write-list-tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "idmap.rfc2307":
        plantestsuite(t, "ad_member_rfc2307", [os.path.join(samba3srcdir, "../nsswitch/tests/test_idmap_rfc2307.sh"), '$DOMAIN', 'Administrator', '2000000', 'Guest', '2000001', '"Domain Users"', '2000002', 'DnsAdmins', '2000003', 'ou=idmap,dc=samba,dc=example,dc=com', '$DC_SERVER', '$DC_USERNAME', '$DC_PASSWORD'])
    elif t == "idmap.alloc":
        plantestsuite(t, "ad_member_rfc2307", [os.path.join(samba3srcdir, "../nsswitch/tests/test_idmap_nss.sh"), '$DOMAIN'])
    elif t == "raw.acls":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/nfs4acl_simple -U$USERNAME%$PASSWORD', description='nfs4acl_xattr-simple')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/nfs4acl_special -U$USERNAME%$PASSWORD', description='nfs4acl_xattr-special')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER_IP/tmpcase -U$USERNAME%$PASSWORD')
    elif t == "smb2.ioctl":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/fs_specific -U$USERNAME%$PASSWORD', 'fs_specific')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "smb2.lock":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/aio -U$USERNAME%$PASSWORD', 'aio')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "raw.read":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/aio -U$USERNAME%$PASSWORD', 'aio')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "raw.search":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
# test the dirsort module.
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmpsort -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "vfs.fruit":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/vfs_fruit -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/nt4_dc/share')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER_IP/vfs_fruit -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/ad_dc/share')
    elif t == "rpc.schannel_anon_setpw":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$%', description="anonymous password set")
        plansmbtorture4testsuite(t, "nt4_dc_schannel", '//$SERVER_IP/tmp -U$%', description="anonymous password set (schannel enforced server-side)")
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$%', description="anonymous password set")
    elif t == "local.nss":
        for env in ["nt4_dc:local", "ad_member:local", "nt4_member:local", "ad_dc:local"]:
            plansmbtorture4testsuite(t, env, '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "smb2.change_notify_disabled":
        plansmbtorture4testsuite(t, "simpleserver", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "smb2.notify":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD --signing=required')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD --signing=required')
    elif t == "smb2.dosmode":
        plansmbtorture4testsuite(t, "simpleserver", '//$SERVER/dosmode -U$USERNAME%$PASSWORD')
    elif t == "vfs.acl_xattr":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
    else:
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')


test = 'rpc.lsa.lookupsids'
auth_options = ["", "ntlm", "spnego", "spnego,ntlm" ]
signseal_options = ["", ",connect", ",sign", ",seal"]
endianness_options = ["", ",bigendian"]
for s in signseal_options:
    for e in endianness_options:
        for a in auth_options:
            binding_string = "ncacn_np:$SERVER[%s%s%s]" % (a, s, e)
            options = binding_string + " -U$USERNAME%$PASSWORD"
            plansmbtorture4testsuite(test, "nt4_dc", options, 'over ncacn_np with [%s%s%s] ' % (a, s, e))
            plantestsuite("samba3.blackbox.rpcclient over ncacn_np with [%s%s%s] " % (a, s, e), "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/test_rpcclient.sh"),
                                                             "none", options, configuration])

    # We should try more combinations in future, but this is all
    # the pre-calculated credentials cache supports at the moment
    e = ""
    a = ""
    binding_string = "ncacn_np:$SERVER[%s%s%s]" % (a, s, e)
    options = binding_string + " -k yes --krb5-ccache=$PREFIX/ktest/krb5_ccache-2"
    plansmbtorture4testsuite(test, "ktest", options, 'krb5 with old ccache ncacn_np with [%s%s%s] ' % (a, s, e))

    options = binding_string + " -k yes --krb5-ccache=$PREFIX/ktest/krb5_ccache-3"
    plansmbtorture4testsuite(test, "ktest", options, 'krb5 ncacn_np with [%s%s%s] ' % (a, s, e))

    auth_options2 = ["krb5", "spnego,krb5"]
    for a in auth_options2:
        binding_string = "ncacn_np:$SERVER[%s%s%s]" % (a, s, e)

        plantestsuite("samba3.blackbox.rpcclient krb5 ncacn_np with [%s%s%s] " % (a, s, e), "ktest:local", [os.path.join(samba3srcdir, "script/tests/test_rpcclient.sh"),
                                                                                                                              "$PREFIX/ktest/krb5_ccache-3", binding_string, "-k", configuration])

plantestsuite("samba3.blackbox.rpcclient_samlogon", "ad_member:local", [os.path.join(samba3srcdir, "script/tests/test_rpcclient_samlogon.sh"),
								       "$DC_USERNAME", "$DC_PASSWORD", "ncacn_np:$DC_SERVER", configuration])
plantestsuite("samba3.blackbox.sharesec", "simpleserver:local",
              [os.path.join(samba3srcdir, "script/tests/test_sharesec.sh"),
               configuration, os.path.join(bindir(), "sharesec"), "tmp"])

plantestsuite("samba3.blackbox.net_dom_join_fail_dc", "nt4_dc",
              [os.path.join(samba3srcdir, "script/tests/test_net_dom_join_fail_dc.sh"),
               "$USERNAME", "$PASSWORD", "$SERVER", "$PREFIX/net_dom_join_fail_dc",
               configuration])
plantestsuite("samba3.blackbox.net_rpc_join", "nt4_dc",
              [os.path.join(samba3srcdir, "script/tests/test_net_rpc_join.sh"),
               "$USERNAME", "$PASSWORD", "$SERVER", "$PREFIX/net_rpc_join",
               configuration])

plantestsuite("samba3.blackbox.rpcclient_srvsvc", "simpleserver",
              [os.path.join(samba3srcdir, "script/tests/test_rpcclientsrvsvc.sh"),
               "$USERNAME", "$PASSWORD", "$SERVER",
               os.path.join(bindir(), "rpcclient"), "tmp"])

plantestsuite("samba3.blackbox.rpcclient.pw-nt-hash", "simpleserver",
              [os.path.join(samba3srcdir, "script/tests/test_rpcclient_pw_nt_hash.sh"),
               "$USERNAME", "$PASSWORD", "$SERVER",
               os.path.join(bindir(), "rpcclient")])

options_list = ["", "-e"]
for options in options_list:
    plantestsuite("samba3.blackbox.smbclient_krb5 old ccache %s" % options, "ktest:local",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_krb5.sh"),
                   "$PREFIX/ktest/krb5_ccache-2",
                   smbclient3, "$SERVER", options, configuration])

    plantestsuite("samba3.blackbox.smbclient_krb5 old ccache %s" % options, "ktest:local",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_krb5.sh"),
                   "$PREFIX/ktest/krb5_ccache-2",
                   smbclient3, "$SERVER", options, configuration])

    plantestsuite("samba3.blackbox.smbclient_large_file %s" % options, "ktest:local",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_posix_large.sh"),
                   "$PREFIX/ktest/krb5_ccache-3",
                   smbclient3, "$SERVER", "$PREFIX", options, "-k " + configuration])

    plantestsuite("samba3.blackbox.smbclient_posix_large %s krb5" % options, "ktest:local",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_posix_large.sh"),
                   "$PREFIX/ktest/krb5_ccache-3",
                   smbclient3, "$SERVER", "$PREFIX", options, "-k " + configuration])

    plantestsuite("samba3.blackbox.smbclient_posix_large %s NTLM" % options, "nt4_dc:local",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_posix_large.sh"),
                   "none",
                   smbclient3, "$SERVER", "$PREFIX", options, "-U$USERNAME%$PASSWORD " + configuration])

for alias in ["foo", "bar"]:
    plantestsuite("samba3.blackbox.smbclient_netbios_aliases [%s]" % alias, "ad_member:local",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_netbios_aliases.sh"),
                   smbclient3, alias, "$DC_USERNAME", "$DC_PASSWORD", "$PREFIX", options, configuration])

for e in endianness_options:
    for a in auth_options:
        for s in signseal_options:
            binding_string = "ncacn_ip_tcp:$SERVER_IP[%s%s%s]" % (a, s, e)
            options = binding_string + " -U$USERNAME%$PASSWORD"
            plansmbtorture4testsuite(test, "nt4_dc", options, 'over ncacn_ip_tcp with [%s%s%s] ' % (a, s, e))

plansmbtorture4testsuite('rpc.epmapper', 'nt4_dc:local', 'ncalrpc: -U$USERNAME%$PASSWORD', 'over ncalrpc')
plansmbtorture4testsuite('rpc.fsrvp', 'nt4_dc:local', 'ncacn_np:$SERVER_IP[/pipe/FssagentRpc] -U$USERNAME%$PASSWORD', 'over ncacn_np')
