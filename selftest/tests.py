#!/usr/bin/python
# This script generates a list of testsuites that should be run as part of
# the Samba test suite.

# The output of this script is parsed by selftest.pl, which then decides
# which of the tests to actually run. It will, for example, skip all tests
# listed in selftest/skip or only run a subset during "make quicktest".

# The idea is that this script outputs all of the tests of Samba, not
# just those that are known to pass, and list those that should be skipped
# or are known to fail in selftest/skip or selftest/knownfail. This makes it
# very easy to see what functionality is still missing in Samba and makes
# it possible to run the testsuite against other servers, such as
# Windows that have a different set of features.

# The syntax for a testsuite is "-- TEST --" on a single line, followed
# by the name of the test, the environment it needs and the command to run, all
# three separated by newlines. All other lines in the output are considered
# comments.

from selftesthelpers import *

try:
    config_h = os.environ["CONFIG_H"]
except KeyError:
    samba4bindir = bindir()
    config_h = os.path.join(samba4bindir, "default/include/config.h")

# define here var to check what we support
f = open(config_h, 'r')
try:
    have_man_pages_support = ("XSLTPROC_MANPAGES 1" in f.read())
finally:
    f.close()

planpythontestsuite("none", "samba.tests.source")
if have_man_pages_support:
    planpythontestsuite("none", "samba.tests.docs")

try:
    import testscenarios
except ImportError:
    skiptestsuite("subunit", "testscenarios not available")
else:
    planpythontestsuite("none", "subunit.tests.test_suite")
planpythontestsuite("none", "samba.tests.blackbox.ndrdump")
planpythontestsuite("none", "api", name="ldb.python", extra_path=['lib/ldb/tests/python'])
planpythontestsuite("none", "samba.tests.credentials")
planpythontestsuite("none", "samba.tests.registry")
planpythontestsuite("none", "samba.tests.auth")
planpythontestsuite("none", "samba.tests.get_opt")
planpythontestsuite("none", "samba.tests.security")
planpythontestsuite("none", "samba.tests.dcerpc.misc")
planpythontestsuite("none", "samba.tests.dcerpc.integer")
planpythontestsuite("none", "samba.tests.param")
planpythontestsuite("none", "samba.tests.upgrade")
planpythontestsuite("none", "samba.tests.core")
planpythontestsuite("none", "samba.tests.provision")
planpythontestsuite("none", "samba.tests.samba3")
planpythontestsuite("none", "samba.tests.strings")
planpythontestsuite("none", "samba.tests.netcmd")
planpythontestsuite("none", "samba.tests.dcerpc.rpc_talloc")
planpythontestsuite("none", "samba.tests.dcerpc.array")
planpythontestsuite("none", "samba.tests.dcerpc.string")
planpythontestsuite("none", "samba.tests.hostconfig")
planpythontestsuite("ad_dc_ntvfs:local", "samba.tests.messaging")
planpythontestsuite("none", "samba.tests.samba3sam")
planpythontestsuite(
    "none", "wafsamba.tests.test_suite",
    extra_path=[os.path.join(samba4srcdir, "..", "buildtools"),
                os.path.join(samba4srcdir, "..", "third_party", "waf", "wafadmin")])
plantestsuite(
    "samba4.blackbox.demote-saveddb", "none",
    ["PYTHON=%s" % python, os.path.join(bbdir, "demote-saveddb.sh"),
     '$PREFIX_ABS/demote', configuration])
plantestsuite(
    "samba4.blackbox.dbcheck.alpha13", "none",
    ["PYTHON=%s" % python, os.path.join(bbdir, "dbcheck-oldrelease.sh"),
     '$PREFIX_ABS/provision', 'alpha13', configuration])
plantestsuite(
    "samba4.blackbox.dbcheck.release-4-0-0", "none",
    ["PYTHON=%s" % python, os.path.join(bbdir, "dbcheck-oldrelease.sh"),
     '$PREFIX_ABS/provision', 'release-4-0-0', configuration])
plantestsuite(
    "samba4.blackbox.dbcheck.release-4-1-0rc3", "none",
    ["PYTHON=%s" % python, os.path.join(bbdir, "dbcheck-oldrelease.sh"),
     '$PREFIX_ABS/provision', 'release-4-1-0rc3', configuration])
plantestsuite(
    "samba4.blackbox.dbcheck.release-4-1-6-partial-object", "none",
    ["PYTHON=%s" % python, os.path.join(bbdir, "dbcheck-oldrelease.sh"),
     '$PREFIX_ABS/provision', 'release-4-1-6-partial-object', configuration])
plantestsuite(
    "samba4.blackbox.dbcheck.release-4-5-0-pre1", "none",
    ["PYTHON=%s" % python,
     os.path.join(bbdir, "dbcheck-oldrelease.sh"),
     '$PREFIX_ABS/provision', 'release-4-5-0-pre1', configuration])
plantestsuite(
    "samba4.blackbox.upgradeprovision.alpha13", "none",
    ["PYTHON=%s" % python,
     os.path.join(bbdir, "upgradeprovision-oldrelease.sh"),
     '$PREFIX_ABS/provision', 'alpha13', configuration])
plantestsuite(
    "samba4.blackbox.upgradeprovision.release-4-0-0", "none",
    ["PYTHON=%s" % python,
     os.path.join(bbdir, "upgradeprovision-oldrelease.sh"),
     '$PREFIX_ABS/provision', 'release-4-0-0', configuration])
plantestsuite(
    "samba4.blackbox.tombstones-expunge.release-4-5-0-pre1", "none",
    ["PYTHON=%s" % python,
     os.path.join(bbdir, "tombstones-expunge.sh"),
     '$PREFIX_ABS/provision', 'release-4-5-0-pre1', configuration])
planpythontestsuite("none", "samba.tests.upgradeprovision")
planpythontestsuite("none", "samba.tests.xattr")
planpythontestsuite("none", "samba.tests.ntacls")
planpythontestsuite("none", "samba.tests.policy")
planpythontestsuite("none", "samba.tests.kcc.graph")
planpythontestsuite("none", "samba.tests.kcc.graph_utils")
planpythontestsuite("none", "samba.tests.kcc.kcc_utils")
planpythontestsuite("none", "samba.tests.kcc.ldif_import_export")
plantestsuite("wafsamba.duplicate_symbols", "none", [os.path.join(srcdir(), "buildtools/wafsamba/test_duplicate_symbol.sh")])
