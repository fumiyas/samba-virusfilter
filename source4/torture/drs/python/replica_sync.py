#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Tests various schema replication scenarios
#
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2011
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

#
# Usage:
#  export DC1=dc1_dns_name
#  export DC2=dc2_dns_name
#  export SUBUNITRUN=$samba4srcdir/scripting/bin/subunitrun
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" $SUBUNITRUN replica_sync -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

import drs_base
import samba.tests
import time

from ldb import (
    SCOPE_BASE, LdbError, ERR_NO_SUCH_OBJECT)

class DrsReplicaSyncTestCase(drs_base.DrsBaseTestCase):
    """Intended as a black box test case for DsReplicaSync
       implementation. It should test the behavior of this
       case in cases when inbound replication is disabled"""

    def setUp(self):
        super(DrsReplicaSyncTestCase, self).setUp()
        self.ou1 = None
        self.ou2 = None

    def tearDown(self):
        # re-enable replication
        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        if self.ldb_dc2 is not None:
            if self.ou1 is not None:
                try:
                    self.ldb_dc2.delete('<GUID=%s>' % self.ou1, ["tree_delete:1"])
                except LdbError, (num, _):
                    self.assertEquals(num, ERR_NO_SUCH_OBJECT)
            if self.ou2 is not None:
                try:
                    self.ldb_dc2.delete('<GUID=%s>' % self.ou2, ["tree_delete:1"])
                except LdbError, (num, _):
                    self.assertEquals(num, ERR_NO_SUCH_OBJECT)

        super(DrsReplicaSyncTestCase, self).tearDown()

    def test_ReplEnabled(self):
        """Tests we can replicate when replication is enabled"""
        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=False)

    def test_ReplDisabled(self):
        """Tests we cann't replicate when replication is disabled"""
        self._disable_inbound_repl(self.dnsname_dc1)
        try:
            self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=False)
        except samba.tests.BlackboxProcessError, e:
            self.assertTrue('WERR_DS_DRA_SINK_DISABLED' in e.stderr)
        else:
            self.fail("'drs replicate' command should have failed!")

    def test_ReplDisabledForced(self):
        """Tests we can force replicate when replication is disabled"""
        self._disable_inbound_repl(self.dnsname_dc1)
        out = self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)

    def test_ReplLocal(self):
        """Tests we can replicate direct to the local db"""
        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=False, local=True, full_sync=True)

    def _create_ou(self, samdb, name):
        ldif = """
dn: %s,%s
objectClass: organizationalUnit
""" % (name, self.domain_dn)
        samdb.add_ldif(ldif)
        res = samdb.search(base="%s,%s" % (name, self.domain_dn),
                           scope=SCOPE_BASE, attrs=["objectGUID"])
        return self._GUID_string(res[0]["objectGUID"][0])

    def _check_deleted(self, sam_ldb, guid):
        # search the user by guid as it may be deleted
        res = sam_ldb.search(base='<GUID=%s>' % guid,
                             controls=["show_deleted:1"],
                             attrs=["isDeleted", "objectCategory", "ou"])
        self.assertEquals(len(res), 1)
        ou_cur = res[0]
        # Deleted Object base DN
        dodn = self._deleted_objects_dn(sam_ldb)
        # now check properties of the user
        name_cur  = ou_cur["ou"][0]
        self.assertEquals(ou_cur["isDeleted"][0],"TRUE")
        self.assertTrue(not("objectCategory" in ou_cur))
        self.assertTrue(dodn in str(ou_cur["dn"]),
                        "OU %s is deleted but it is not located under %s!" % (name_cur, dodn))

    def test_ReplConflictsFullSync(self):
        """Tests that objects created in conflict become conflict DNs (honour full sync override)"""

        # First confirm local replication (so when we test against windows, this fails fast without creating objects)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, local=True, forced=True, full_sync=True)

        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Create conflicting objects on DC1 and DC2, with DC1 object created first
        self.ou1 = self._create_ou(self.ldb_dc1, "OU=Test Full Sync")
        # We have to sleep to ensure that the two objects have different timestamps
        time.sleep(1)
        self.ou2 = self._create_ou(self.ldb_dc2, "OU=Test Full Sync")

        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, local=True, forced=True, full_sync=True)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Check that DC2 got the DC1 object, and OU1 was make into conflict
        res1 = self.ldb_dc2.search(base="<GUID=%s>" % self.ou1,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc2.search(base="<GUID=%s>" % self.ou2,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0]["name"][0]
        print res2[0]["name"][0]
        self.assertFalse('CNF:%s' % self.ou2 in str(res2[0]["name"][0]))
        self.assertTrue('CNF:%s' % self.ou1 in str(res1[0]["name"][0]))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc2, self.domain_dn) not in str(res1[0].dn))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc2, self.domain_dn) not in str(res2[0].dn))
        self.assertEqual(str(res1[0]["name"][0]), res1[0].dn.get_rdn_value())
        self.assertEqual(str(res2[0]["name"][0]), res2[0].dn.get_rdn_value())

        # Delete both objects by GUID on DC2

        self.ldb_dc2.delete('<GUID=%s>' % self.ou1)
        self.ldb_dc2.delete('<GUID=%s>' % self.ou2)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=True)

        self._check_deleted(self.ldb_dc1, self.ou1)
        self._check_deleted(self.ldb_dc1, self.ou2)
        # Check deleted on DC2
        self._check_deleted(self.ldb_dc2, self.ou1)
        self._check_deleted(self.ldb_dc2, self.ou2)

    def test_ReplConflictsRemoteWin(self):
        """Tests that objects created in conflict become conflict DNs"""
        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Create conflicting objects on DC1 and DC2, with DC1 object created first
        self.ou1 = self._create_ou(self.ldb_dc1, "OU=Test Remote Conflict")
        # We have to sleep to ensure that the two objects have different timestamps
        time.sleep(1)
        self.ou2 = self._create_ou(self.ldb_dc2, "OU=Test Remote Conflict")

        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Check that DC2 got the DC1 object, and OU1 was make into conflict
        res1 = self.ldb_dc1.search(base="<GUID=%s>" % self.ou1,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc1.search(base="<GUID=%s>" % self.ou2,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0]["name"][0]
        print res2[0]["name"][0]
        self.assertTrue('CNF:%s' % self.ou1 in str(res1[0]["name"][0]))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res1[0].dn))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res2[0].dn))
        self.assertEqual(str(res1[0]["name"][0]), res1[0].dn.get_rdn_value())
        self.assertEqual(str(res2[0]["name"][0]), res2[0].dn.get_rdn_value())

        # Delete both objects by GUID on DC1

        self.ldb_dc1.delete('<GUID=%s>' % self.ou1)
        self.ldb_dc1.delete('<GUID=%s>' % self.ou2)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True, full_sync=False)

        self._check_deleted(self.ldb_dc1, self.ou1)
        self._check_deleted(self.ldb_dc1, self.ou2)
        # Check deleted on DC2
        self._check_deleted(self.ldb_dc2, self.ou1)
        self._check_deleted(self.ldb_dc2, self.ou2)

    def test_ReplConflictsLocalWin(self):
        """Tests that objects created in conflict become conflict DNs"""
        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Create conflicting objects on DC1 and DC2, with DC2 object created first
        self.ou2 = self._create_ou(self.ldb_dc2, "OU=Test Local Conflict")
        # We have to sleep to ensure that the two objects have different timestamps
        time.sleep(1)
        self.ou1 = self._create_ou(self.ldb_dc1, "OU=Test Local Conflict")

        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Check that DC2 got the DC1 object, and OU2 was make into conflict
        res1 = self.ldb_dc1.search(base="<GUID=%s>" % self.ou1,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc1.search(base="<GUID=%s>" % self.ou2,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0]["name"][0]
        print res2[0]["name"][0]
        self.assertTrue('CNF:%s' % self.ou2 in str(res2[0]["name"][0]), "Got %s for %s" % (str(res2[0]["name"][0]), self.ou2))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res1[0].dn))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res2[0].dn))
        self.assertEqual(str(res1[0]["name"][0]), res1[0].dn.get_rdn_value())
        self.assertEqual(str(res2[0]["name"][0]), res2[0].dn.get_rdn_value())

        # Delete both objects by GUID on DC1

        self.ldb_dc1.delete('<GUID=%s>' % self.ou1)
        self.ldb_dc1.delete('<GUID=%s>' % self.ou2)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True, full_sync=False)

        self._check_deleted(self.ldb_dc1, self.ou1)
        self._check_deleted(self.ldb_dc1, self.ou2)
        # Check deleted on DC2
        self._check_deleted(self.ldb_dc2, self.ou1)
        self._check_deleted(self.ldb_dc2, self.ou2)

    def test_ReplConflictsRemoteWin_with_child(self):
        """Tests that objects created in conflict become conflict DNs"""
        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Create conflicting objects on DC1 and DC2, with DC1 object created first
        self.ou1 = self._create_ou(self.ldb_dc1, "OU=Test Parent Remote Conflict")
        # We have to sleep to ensure that the two objects have different timestamps
        time.sleep(1)
        self.ou2 = self._create_ou(self.ldb_dc2, "OU=Test Parent Remote Conflict")
        # Create children on DC2
        ou1_child = self._create_ou(self.ldb_dc1, "OU=Test Child,OU=Test Parent Remote Conflict")
        ou2_child = self._create_ou(self.ldb_dc2, "OU=Test Child,OU=Test Parent Remote Conflict")

        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Check that DC2 got the DC1 object, and SELF.OU1 was make into conflict
        res1 = self.ldb_dc1.search(base="<GUID=%s>" % self.ou1,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc1.search(base="<GUID=%s>" % self.ou2,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0]["name"][0]
        print res2[0]["name"][0]
        self.assertTrue('CNF:%s' % self.ou1 in str(res1[0]["name"][0]))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res1[0].dn))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res2[0].dn))
        self.assertEqual(str(res1[0]["name"][0]), res1[0].dn.get_rdn_value())
        self.assertEqual(str(res2[0]["name"][0]), res2[0].dn.get_rdn_value())

        # Delete both objects by GUID on DC1

        self.ldb_dc1.delete('<GUID=%s>' % self.ou1, ["tree_delete:1"])
        self.ldb_dc1.delete('<GUID=%s>' % self.ou2, ["tree_delete:1"])

        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True, full_sync=False)

        self._check_deleted(self.ldb_dc1, self.ou1)
        self._check_deleted(self.ldb_dc1, self.ou2)
        # Check deleted on DC2
        self._check_deleted(self.ldb_dc2, self.ou1)
        self._check_deleted(self.ldb_dc2, self.ou2)

        self._check_deleted(self.ldb_dc1, ou1_child)
        self._check_deleted(self.ldb_dc1, ou2_child)
        # Check deleted on DC2
        self._check_deleted(self.ldb_dc2, ou1_child)
        self._check_deleted(self.ldb_dc2, ou2_child)


    def test_ReplConflictsRenameRemoteWin(self):
        """Tests that objects created in conflict become conflict DNs"""
        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Create conflicting objects on DC1 and DC2, with DC1 object created first
        self.ou1 = self._create_ou(self.ldb_dc1, "OU=Test Remote Rename Conflict")
        self.ou2 = self._create_ou(self.ldb_dc2, "OU=Test Remote Rename Conflict 2")

        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        self.ldb_dc1.rename("<GUID=%s>" % self.ou1, "OU=Test Remote Rename Conflict 3,%s" % self.domain_dn)
        # We have to sleep to ensure that the two objects have different timestamps
        time.sleep(1)
        self.ldb_dc2.rename("<GUID=%s>" % self.ou2, "OU=Test Remote Rename Conflict 3,%s" % self.domain_dn)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Check that DC2 got the DC1 object, and SELF.OU1 was make into conflict
        res1 = self.ldb_dc1.search(base="<GUID=%s>" % self.ou1,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc1.search(base="<GUID=%s>" % self.ou2,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0]["name"][0]
        print res2[0]["name"][0]
        self.assertTrue('CNF:%s' % self.ou1 in str(res1[0]["name"][0]))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res1[0].dn))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res2[0].dn))
        self.assertEqual(str(res1[0]["name"][0]), res1[0].dn.get_rdn_value())
        self.assertEqual(str(res2[0]["name"][0]), res2[0].dn.get_rdn_value())

        # Delete both objects by GUID on DC1

        self.ldb_dc1.delete('<GUID=%s>' % self.ou1)
        self.ldb_dc1.delete('<GUID=%s>' % self.ou2)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True, full_sync=False)

        self._check_deleted(self.ldb_dc1, self.ou1)
        self._check_deleted(self.ldb_dc1, self.ou2)
        # Check deleted on DC2
        self._check_deleted(self.ldb_dc2, self.ou1)
        self._check_deleted(self.ldb_dc2, self.ou2)


    def test_ReplConflictsRenameRemoteWin_with_child(self):
        """Tests that objects created in conflict become conflict DNs"""
        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Create conflicting objects on DC1 and DC2, with DC1 object created first
        self.ou1 = self._create_ou(self.ldb_dc1, "OU=Test Parent Remote Rename Conflict")
        self.ou2 = self._create_ou(self.ldb_dc2, "OU=Test Parent Remote Rename Conflict 2")
        # Create children on DC2
        ou1_child = self._create_ou(self.ldb_dc1, "OU=Test Child,OU=Test Parent Remote Rename Conflict")
        ou2_child = self._create_ou(self.ldb_dc2, "OU=Test Child,OU=Test Parent Remote Rename Conflict 2")

        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        self.ldb_dc1.rename("<GUID=%s>" % self.ou1, "OU=Test Parent Remote Rename Conflict 3,%s" % self.domain_dn)
        # We have to sleep to ensure that the two objects have different timestamps
        time.sleep(1)
        self.ldb_dc2.rename("<GUID=%s>" % self.ou2, "OU=Test Parent Remote Rename Conflict 3,%s" % self.domain_dn)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Check that DC2 got the DC1 object, and SELF.OU1 was make into conflict
        res1 = self.ldb_dc1.search(base="<GUID=%s>" % self.ou1,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc1.search(base="<GUID=%s>" % self.ou2,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0]["name"][0]
        print res2[0]["name"][0]
        self.assertTrue('CNF:%s' % self.ou1 in str(res1[0]["name"][0]))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res1[0].dn))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res2[0].dn))
        self.assertEqual(str(res1[0]["name"][0]), res1[0].dn.get_rdn_value())
        self.assertEqual(str(res2[0]["name"][0]), res2[0].dn.get_rdn_value())

        # Delete both objects by GUID on DC1

        self.ldb_dc1.delete('<GUID=%s>' % self.ou1, ["tree_delete:1"])
        self.ldb_dc1.delete('<GUID=%s>' % self.ou2, ["tree_delete:1"])

        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True, full_sync=False)

        self._check_deleted(self.ldb_dc1, self.ou1)
        self._check_deleted(self.ldb_dc1, self.ou2)
        # Check deleted on DC2
        self._check_deleted(self.ldb_dc2, self.ou1)
        self._check_deleted(self.ldb_dc2, self.ou2)

        self._check_deleted(self.ldb_dc1, ou1_child)
        self._check_deleted(self.ldb_dc1, ou2_child)
        # Check deleted on DC2
        self._check_deleted(self.ldb_dc2, ou1_child)
        self._check_deleted(self.ldb_dc2, ou2_child)


    def test_ReplConflictsRenameLocalWin(self):
        """Tests that objects created in conflict become conflict DNs"""
        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Create conflicting objects on DC1 and DC2, with DC1 object created first
        self.ou1 = self._create_ou(self.ldb_dc1, "OU=Test Rename Local Conflict")
        self.ou2 = self._create_ou(self.ldb_dc2, "OU=Test Rename Local Conflict 2")

        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        self.ldb_dc2.rename("<GUID=%s>" % self.ou2, "OU=Test Rename Local Conflict 3,%s" % self.domain_dn)
        # We have to sleep to ensure that the two objects have different timestamps
        time.sleep(1)
        self.ldb_dc1.rename("<GUID=%s>" % self.ou1, "OU=Test Rename Local Conflict 3,%s" % self.domain_dn)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Check that DC2 got the DC1 object, and OU2 was make into conflict
        res1 = self.ldb_dc1.search(base="<GUID=%s>" % self.ou1,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc1.search(base="<GUID=%s>" % self.ou2,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0]["name"][0]
        print res2[0]["name"][0]
        self.assertTrue('CNF:%s' % self.ou2 in str(res2[0]["name"][0]))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res1[0].dn))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) not in str(res2[0].dn))
        self.assertEqual(str(res1[0]["name"][0]), res1[0].dn.get_rdn_value())
        self.assertEqual(str(res2[0]["name"][0]), res2[0].dn.get_rdn_value())

        # Delete both objects by GUID on DC1

        self.ldb_dc1.delete('<GUID=%s>' % self.ou1)
        self.ldb_dc1.delete('<GUID=%s>' % self.ou2)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True, full_sync=False)

        self._check_deleted(self.ldb_dc1, self.ou1)
        self._check_deleted(self.ldb_dc1, self.ou2)
        # Check deleted on DC2
        self._check_deleted(self.ldb_dc2, self.ou1)
        self._check_deleted(self.ldb_dc2, self.ou2)

    def test_ReplLostAndFound(self):
        """Tests that objects created under a OU deleted eleswhere end up in lostAndFound"""
        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Create two OUs on DC2
        self.ou1 = self._create_ou(self.ldb_dc2, "OU=Deleted parent")
        self.ou2 = self._create_ou(self.ldb_dc2, "OU=Deleted parent 2")

        # replicate them from DC2 to DC1
        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Delete both objects by GUID on DC1

        self.ldb_dc1.delete('<GUID=%s>' % self.ou1)
        self.ldb_dc1.delete('<GUID=%s>' % self.ou2)

        # Create children on DC2
        ou1_child = self._create_ou(self.ldb_dc2, "OU=Test Child,OU=Deleted parent")
        ou2_child = self._create_ou(self.ldb_dc2, "OU=Test Child,OU=Deleted parent 2")

        # Replicate from DC2
        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Check the sub-OUs are now in lostAndFound and the first one is a conflict DN

        # Check that DC2 got the DC1 object, and one or other object was make into conflict
        res1 = self.ldb_dc1.search(base="<GUID=%s>" % ou1_child,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc1.search(base="<GUID=%s>" % ou2_child,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0]["name"][0]
        print res2[0]["name"][0]
        self.assertTrue('CNF:%s' % ou1_child in str(res1[0]["name"][0]) or 'CNF:%s' % ou2_child in str(res2[0]["name"][0]))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) in str(res1[0].dn))
        self.assertTrue(self._lost_and_found_dn(self.ldb_dc1, self.domain_dn) in str(res2[0].dn))
        self.assertEqual(str(res1[0]["name"][0]), res1[0].dn.get_rdn_value())
        self.assertEqual(str(res2[0]["name"][0]), res2[0].dn.get_rdn_value())

        # Delete all objects by GUID on DC1

        self.ldb_dc1.delete('<GUID=%s>' % ou1_child)
        self.ldb_dc1.delete('<GUID=%s>' % ou2_child)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True, full_sync=False)


        # Check all deleted on DC1
        self._check_deleted(self.ldb_dc1, self.ou1)
        self._check_deleted(self.ldb_dc1, self.ou2)
        self._check_deleted(self.ldb_dc1, ou1_child)
        self._check_deleted(self.ldb_dc1, ou2_child)
        # Check all deleted on DC2
        self._check_deleted(self.ldb_dc2, self.ou1)
        self._check_deleted(self.ldb_dc2, self.ou2)
        self._check_deleted(self.ldb_dc2, ou1_child)
        self._check_deleted(self.ldb_dc2, ou2_child)

    def test_ReplRenames(self):
        """Tests that objects created under a OU deleted eleswhere end up in lostAndFound"""
        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Create two OUs on DC2
        self.ou1 = self._create_ou(self.ldb_dc2, "OU=Original parent")
        self.ou2 = self._create_ou(self.ldb_dc2, "OU=Original parent 2")

        # replicate them from DC2 to DC1
        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Create children on DC1
        ou1_child = self._create_ou(self.ldb_dc1, "OU=Test Child,OU=Original parent")
        ou2_child = self._create_ou(self.ldb_dc1, "OU=Test Child 2,OU=Original parent")
        ou3_child = self._create_ou(self.ldb_dc1, "OU=Test Case Child,OU=Original parent")

        # replicate them from DC1 to DC2
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc2)

        self.ldb_dc1.rename("<GUID=%s>" % ou2_child, "OU=Test Child 3,OU=Original parent 2,%s" % self.domain_dn)
        self.ldb_dc1.rename("<GUID=%s>" % ou1_child, "OU=Test Child 2,OU=Original parent 2,%s" % self.domain_dn)
        self.ldb_dc1.rename("<GUID=%s>" % ou2_child, "OU=Test Child,OU=Original parent 2,%s" % self.domain_dn)
        self.ldb_dc1.rename("<GUID=%s>" % ou3_child, "OU=Test CASE Child,OU=Original parent,%s" % self.domain_dn)
        self.ldb_dc2.rename("<GUID=%s>" % self.ou2, "OU=Original parent 3,%s" % self.domain_dn)
        self.ldb_dc2.rename("<GUID=%s>" % self.ou1, "OU=Original parent 2,%s" % self.domain_dn)

        # replicate them from DC1 to DC2
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc2)

        # Check the sub-OUs are now under Original Parent 3 (original
        # parent 2 for Test CASE Child), and both have the right names

        # Check that DC2 got the DC1 object, and the renames are all correct
        res1 = self.ldb_dc2.search(base="<GUID=%s>" % ou1_child,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc2.search(base="<GUID=%s>" % ou2_child,
                                  scope=SCOPE_BASE, attrs=["name"])
        res3 = self.ldb_dc2.search(base="<GUID=%s>" % ou3_child,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0].dn
        print res2[0].dn
        print res3[0].dn
        self.assertEqual('Test Child 2', res1[0]["name"][0])
        self.assertEqual('Test Child', res2[0]["name"][0])
        self.assertEqual('Test CASE Child', res3[0]["name"][0])
        self.assertEqual(str(res1[0].dn), "OU=Test Child 2,OU=Original parent 3,%s" % self.domain_dn)
        self.assertEqual(str(res2[0].dn), "OU=Test Child,OU=Original parent 3,%s" % self.domain_dn)
        self.assertEqual(str(res3[0].dn), "OU=Test CASE Child,OU=Original parent 2,%s" % self.domain_dn)

        # replicate them from DC2 to DC1
        self._enable_inbound_repl(self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True, full_sync=False)
        self._disable_inbound_repl(self.dnsname_dc1)

        # Check that DC1 got the DC2 object, and the renames are all correct
        res1 = self.ldb_dc1.search(base="<GUID=%s>" % ou1_child,
                                  scope=SCOPE_BASE, attrs=["name"])
        res2 = self.ldb_dc1.search(base="<GUID=%s>" % ou2_child,
                                  scope=SCOPE_BASE, attrs=["name"])
        res3 = self.ldb_dc1.search(base="<GUID=%s>" % ou3_child,
                                  scope=SCOPE_BASE, attrs=["name"])
        print res1[0].dn
        print res2[0].dn
        print res3[0].dn
        self.assertEqual('Test Child 2', res1[0]["name"][0])
        self.assertEqual('Test Child', res2[0]["name"][0])
        self.assertEqual('Test CASE Child', res3[0]["name"][0])
        self.assertEqual(str(res1[0].dn), "OU=Test Child 2,OU=Original parent 3,%s" % self.domain_dn)
        self.assertEqual(str(res2[0].dn), "OU=Test Child,OU=Original parent 3,%s" % self.domain_dn)
        self.assertEqual(str(res3[0].dn), "OU=Test CASE Child,OU=Original parent 2,%s" % self.domain_dn)

        # Delete all objects by GUID on DC1

        self.ldb_dc1.delete('<GUID=%s>' % ou1_child)
        self.ldb_dc1.delete('<GUID=%s>' % ou2_child)
        self.ldb_dc1.delete('<GUID=%s>' % ou3_child)
        self.ldb_dc1.delete('<GUID=%s>' % self.ou1)
        self.ldb_dc1.delete('<GUID=%s>' % self.ou2)

        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True, full_sync=False)


        # Check all deleted on DC1
        self._check_deleted(self.ldb_dc1, self.ou1)
        self._check_deleted(self.ldb_dc1, self.ou2)
        self._check_deleted(self.ldb_dc1, ou1_child)
        self._check_deleted(self.ldb_dc1, ou2_child)
        self._check_deleted(self.ldb_dc1, ou3_child)
        # Check all deleted on DC2
        self._check_deleted(self.ldb_dc2, self.ou1)
        self._check_deleted(self.ldb_dc2, self.ou2)
        self._check_deleted(self.ldb_dc2, ou1_child)
        self._check_deleted(self.ldb_dc2, ou2_child)
        self._check_deleted(self.ldb_dc2, ou3_child)
