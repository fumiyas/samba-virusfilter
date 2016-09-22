#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Tests various schema replication scenarios
#
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2011
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2016
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
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" $SUBUNITRUN getnc_exop -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

import drs_base
import samba.tests

import ldb
from ldb import SCOPE_BASE

from samba.dcerpc import drsuapi, misc, drsblobs
from samba.drs_utils import drs_DsBind
from samba.ndr import ndr_unpack, ndr_pack

def _linked_attribute_compare(la1, la2):
    """See CompareLinks() in MS-DRSR section 4.1.10.5.17"""
    la1, la1_target = la1
    la2, la2_target = la2

    # Ascending host object GUID
    c = cmp(ndr_pack(la1.identifier.guid), ndr_pack(la2.identifier.guid))
    if c != 0:
        return c

    # Ascending attribute ID
    if la1.attid != la2.attid:
        return -1 if la1.attid < la2.attid else 1

    la1_active = la1.flags & drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE
    la2_active = la2.flags & drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE

    # Ascending 'is present'
    if la1_active != la2_active:
        return 1 if la1_active else -1

    # Ascending target object GUID
    return cmp(ndr_pack(la1_target), ndr_pack(la2_target))

class AbstractLink:
    def __init__(self, attid, flags, identifier, targetGUID):
        self.attid = attid
        self.flags = flags
        self.identifier = identifier
        self.targetGUID = targetGUID

    def __eq__(self, other):
        return isinstance(other, AbstractLink) and \
            ((self.attid, self.flags, self.identifier, self.targetGUID) ==
             (other.attid, other.flags, other.identifier, other.targetGUID))

    def __hash__(self):
        return hash((self.attid, self.flags, self.identifier, self.targetGUID))

class ExopBaseTest:
    def _exop_req8(self, dest_dsa, invocation_id, nc_dn_str, exop,
                   replica_flags=0, max_objects=0, partial_attribute_set=None,
                   partial_attribute_set_ex=None, mapping_ctr=None):
        req8 = drsuapi.DsGetNCChangesRequest8()

        req8.destination_dsa_guid = misc.GUID(dest_dsa) if dest_dsa else misc.GUID()
        req8.source_dsa_invocation_id = misc.GUID(invocation_id)
        req8.naming_context = drsuapi.DsReplicaObjectIdentifier()
        req8.naming_context.dn = unicode(nc_dn_str)
        req8.highwatermark = drsuapi.DsReplicaHighWaterMark()
        req8.highwatermark.tmp_highest_usn = 0
        req8.highwatermark.reserved_usn = 0
        req8.highwatermark.highest_usn = 0
        req8.uptodateness_vector = None
        req8.replica_flags = replica_flags
        req8.max_object_count = max_objects
        req8.max_ndr_size = 402116
        req8.extended_op = exop
        req8.fsmo_info = 0
        req8.partial_attribute_set = partial_attribute_set
        req8.partial_attribute_set_ex = partial_attribute_set_ex
        if mapping_ctr:
            req8.mapping_ctr = mapping_ctr
        else:
            req8.mapping_ctr.num_mappings = 0
            req8.mapping_ctr.mappings = None

        return req8

    def _ds_bind(self, server_name):
        binding_str = "ncacn_ip_tcp:%s[seal]" % server_name

        drs = drsuapi.drsuapi(binding_str, self.get_loadparm(), self.get_credentials())
        (drs_handle, supported_extensions) = drs_DsBind(drs)
        return (drs, drs_handle)


class DrsReplicaSyncTestCase(drs_base.DrsBaseTestCase, ExopBaseTest):
    """Intended as a semi-black box test case for DsGetNCChanges
       implementation for extended operations. It should be testing
       how DsGetNCChanges handles different input params (mostly invalid).
       Final goal is to make DsGetNCChanges as binary compatible to
       Windows implementation as possible"""

    def setUp(self):
        super(DrsReplicaSyncTestCase, self).setUp()

    def tearDown(self):
        super(DrsReplicaSyncTestCase, self).tearDown()

    def _determine_fSMORoleOwner(self, fsmo_obj_dn):
        """Returns (owner, not_owner) pair where:
             owner: dns name for FSMO owner
             not_owner: dns name for DC not owning the FSMO"""
        # collect info to return later
        fsmo_info_1 = {"dns_name": self.dnsname_dc1,
                       "invocation_id": self.ldb_dc1.get_invocation_id(),
                       "ntds_guid": self.ldb_dc1.get_ntds_GUID(),
                       "server_dn": self.ldb_dc1.get_serverName()}
        fsmo_info_2 = {"dns_name": self.dnsname_dc2,
                       "invocation_id": self.ldb_dc2.get_invocation_id(),
                       "ntds_guid": self.ldb_dc2.get_ntds_GUID(),
                       "server_dn": self.ldb_dc2.get_serverName()}

        msgs = self.ldb_dc1.search(scope=ldb.SCOPE_BASE, base=fsmo_info_1["server_dn"], attrs=["serverReference"])
        fsmo_info_1["server_acct_dn"] = ldb.Dn(self.ldb_dc1, msgs[0]["serverReference"][0])
        fsmo_info_1["rid_set_dn"] = ldb.Dn(self.ldb_dc1, "CN=RID Set") + fsmo_info_1["server_acct_dn"]

        msgs = self.ldb_dc2.search(scope=ldb.SCOPE_BASE, base=fsmo_info_2["server_dn"], attrs=["serverReference"])
        fsmo_info_2["server_acct_dn"] = ldb.Dn(self.ldb_dc2, msgs[0]["serverReference"][0])
        fsmo_info_2["rid_set_dn"] = ldb.Dn(self.ldb_dc2, "CN=RID Set") + fsmo_info_2["server_acct_dn"]

        # determine the owner dc
        res = self.ldb_dc1.search(fsmo_obj_dn,
                                  scope=SCOPE_BASE, attrs=["fSMORoleOwner"])
        assert len(res) == 1, "Only one fSMORoleOwner value expected for %s!"%fsmo_obj_dn
        fsmo_owner = res[0]["fSMORoleOwner"][0]
        if fsmo_owner == self.info_dc1["dsServiceName"][0]:
            return (fsmo_info_1, fsmo_info_2)
        return (fsmo_info_2, fsmo_info_1)

    def _check_exop_failed(self, ctr6, expected_failure):
        self.assertEqual(ctr6.extended_ret, expected_failure)
        #self.assertEqual(ctr6.object_count, 0)
        #self.assertEqual(ctr6.first_object, None)
        self.assertEqual(ctr6.more_data, False)
        self.assertEqual(ctr6.nc_object_count, 0)
        self.assertEqual(ctr6.nc_linked_attributes_count, 0)
        self.assertEqual(ctr6.linked_attributes_count, 0)
        self.assertEqual(ctr6.linked_attributes, [])
        self.assertEqual(ctr6.drs_error[0], 0)

    def test_FSMONotOwner(self):
        """Test role transfer with against DC not owner of the role"""
        fsmo_dn = self.ldb_dc1.get_schema_basedn()
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        req8 = self._exop_req8(dest_dsa=fsmo_owner["ntds_guid"],
                               invocation_id=fsmo_not_owner["invocation_id"],
                               nc_dn_str=fsmo_dn,
                               exop=drsuapi.DRSUAPI_EXOP_FSMO_REQ_ROLE)

        (drs, drs_handle) = self._ds_bind(fsmo_not_owner["dns_name"])
        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
        self.assertEqual(level, 6, "Expected level 6 response!")
        self._check_exop_failed(ctr, drsuapi.DRSUAPI_EXOP_ERR_FSMO_NOT_OWNER)
        self.assertEqual(ctr.source_dsa_guid, misc.GUID(fsmo_not_owner["ntds_guid"]))
        self.assertEqual(ctr.source_dsa_invocation_id, misc.GUID(fsmo_not_owner["invocation_id"]))

    def test_InvalidDestDSA(self):
        """Test role transfer with invalid destination DSA guid"""
        fsmo_dn = self.ldb_dc1.get_schema_basedn()
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        req8 = self._exop_req8(dest_dsa="9c637462-5b8c-4467-aef2-bdb1f57bc4ef",
                               invocation_id=fsmo_owner["invocation_id"],
                               nc_dn_str=fsmo_dn,
                               exop=drsuapi.DRSUAPI_EXOP_FSMO_REQ_ROLE)

        (drs, drs_handle) = self._ds_bind(fsmo_owner["dns_name"])
        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
        self.assertEqual(level, 6, "Expected level 6 response!")
        self._check_exop_failed(ctr, drsuapi.DRSUAPI_EXOP_ERR_UNKNOWN_CALLER)
        self.assertEqual(ctr.source_dsa_guid, misc.GUID(fsmo_owner["ntds_guid"]))
        self.assertEqual(ctr.source_dsa_invocation_id, misc.GUID(fsmo_owner["invocation_id"]))

    def test_InvalidDestDSA_ridalloc(self):
        """Test RID allocation with invalid destination DSA guid"""
        fsmo_dn = ldb.Dn(self.ldb_dc1, "CN=RID Manager$,CN=System," + self.ldb_dc1.domain_dn())
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        req8 = self._exop_req8(dest_dsa="9c637462-5b8c-4467-aef2-bdb1f57bc4ef",
                               invocation_id=fsmo_owner["invocation_id"],
                               nc_dn_str=fsmo_dn,
                               exop=drsuapi.DRSUAPI_EXOP_FSMO_RID_ALLOC)

        (drs, drs_handle) = self._ds_bind(fsmo_owner["dns_name"])
        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
        self.assertEqual(level, 6, "Expected level 6 response!")
        self._check_exop_failed(ctr, drsuapi.DRSUAPI_EXOP_ERR_UNKNOWN_CALLER)
        self.assertEqual(ctr.source_dsa_guid, misc.GUID(fsmo_owner["ntds_guid"]))
        self.assertEqual(ctr.source_dsa_invocation_id, misc.GUID(fsmo_owner["invocation_id"]))

    def test_do_ridalloc(self):
        """Test doing a RID allocation with a valid destination DSA guid"""
        fsmo_dn = ldb.Dn(self.ldb_dc1, "CN=RID Manager$,CN=System," + self.ldb_dc1.domain_dn())
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        req8 = self._exop_req8(dest_dsa=fsmo_not_owner["ntds_guid"],
                               invocation_id=fsmo_owner["invocation_id"],
                               nc_dn_str=fsmo_dn,
                               exop=drsuapi.DRSUAPI_EXOP_FSMO_RID_ALLOC)

        (drs, drs_handle) = self._ds_bind(fsmo_owner["dns_name"])
        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
        self.assertEqual(level, 6, "Expected level 6 response!")
        self.assertEqual(ctr.source_dsa_guid, misc.GUID(fsmo_owner["ntds_guid"]))
        self.assertEqual(ctr.source_dsa_invocation_id, misc.GUID(fsmo_owner["invocation_id"]))
        ctr6 = ctr
        self.assertEqual(ctr6.extended_ret, drsuapi.DRSUAPI_EXOP_ERR_SUCCESS)
        self.assertEqual(ctr6.object_count, 3)
        self.assertNotEqual(ctr6.first_object, None)
        self.assertEqual(ldb.Dn(self.ldb_dc1, ctr6.first_object.object.identifier.dn), fsmo_dn)
        self.assertNotEqual(ctr6.first_object.next_object, None)
        self.assertNotEqual(ctr6.first_object.next_object.next_object, None)
        second_object = ctr6.first_object.next_object.object
        self.assertEqual(ldb.Dn(self.ldb_dc1, second_object.identifier.dn), fsmo_not_owner["rid_set_dn"])
        third_object = ctr6.first_object.next_object.next_object.object
        self.assertEqual(ldb.Dn(self.ldb_dc1, third_object.identifier.dn), fsmo_not_owner["server_acct_dn"])

        self.assertEqual(ctr6.more_data, False)
        self.assertEqual(ctr6.nc_object_count, 0)
        self.assertEqual(ctr6.nc_linked_attributes_count, 0)
        self.assertEqual(ctr6.drs_error[0], 0)
        # We don't check the linked_attributes_count as if the domain
        # has an RODC, it can gain links on the server account object

    def test_do_ridalloc_get_anc(self):
        """Test doing a RID allocation with a valid destination DSA guid and """
        fsmo_dn = ldb.Dn(self.ldb_dc1, "CN=RID Manager$,CN=System," + self.ldb_dc1.domain_dn())
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        req8 = self._exop_req8(dest_dsa=fsmo_not_owner["ntds_guid"],
                               invocation_id=fsmo_owner["invocation_id"],
                               nc_dn_str=fsmo_dn,
                               exop=drsuapi.DRSUAPI_EXOP_FSMO_RID_ALLOC,
                               replica_flags=drsuapi.DRSUAPI_DRS_GET_ANC)

        (drs, drs_handle) = self._ds_bind(fsmo_owner["dns_name"])
        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
        self.assertEqual(level, 6, "Expected level 6 response!")
        self.assertEqual(ctr.source_dsa_guid, misc.GUID(fsmo_owner["ntds_guid"]))
        self.assertEqual(ctr.source_dsa_invocation_id, misc.GUID(fsmo_owner["invocation_id"]))
        ctr6 = ctr
        self.assertEqual(ctr6.extended_ret, drsuapi.DRSUAPI_EXOP_ERR_SUCCESS)
        self.assertEqual(ctr6.object_count, 3)
        self.assertNotEqual(ctr6.first_object, None)
        self.assertEqual(ldb.Dn(self.ldb_dc1, ctr6.first_object.object.identifier.dn), fsmo_dn)
        self.assertNotEqual(ctr6.first_object.next_object, None)
        self.assertNotEqual(ctr6.first_object.next_object.next_object, None)
        second_object = ctr6.first_object.next_object.object
        self.assertEqual(ldb.Dn(self.ldb_dc1, second_object.identifier.dn), fsmo_not_owner["rid_set_dn"])
        third_object = ctr6.first_object.next_object.next_object.object
        self.assertEqual(ldb.Dn(self.ldb_dc1, third_object.identifier.dn), fsmo_not_owner["server_acct_dn"])
        self.assertEqual(ctr6.more_data, False)
        self.assertEqual(ctr6.nc_object_count, 0)
        self.assertEqual(ctr6.nc_linked_attributes_count, 0)
        self.assertEqual(ctr6.drs_error[0], 0)
        # We don't check the linked_attributes_count as if the domain
        # has an RODC, it can gain links on the server account object

class DrsReplicaPrefixMapTestCase(drs_base.DrsBaseTestCase, ExopBaseTest):
    def setUp(self):
        super(DrsReplicaPrefixMapTestCase, self).setUp()
        self.base_dn = self.ldb_dc1.get_default_basedn()
        self.ou = "ou=pfm_exop,%s" % self.base_dn
        self.ldb_dc1.add({
            "dn": self.ou,
            "objectclass": "organizationalUnit"})
        self.user = "cn=testuser,%s" % self.ou
        self.ldb_dc1.add({
            "dn": self.user,
            "objectclass": "user"})

    def tearDown(self):
        super(DrsReplicaPrefixMapTestCase, self).tearDown()
        try:
            self.ldb_dc1.delete(self.ou, ["tree_delete:1"])
        except ldb.LdbError as (enum, string):
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                pass

    def get_partial_attribute_set(self, attids=[drsuapi.DRSUAPI_ATTID_objectClass]):
        partial_attribute_set = drsuapi.DsPartialAttributeSet()
        partial_attribute_set.attids = attids
        partial_attribute_set.num_attids = len(attids)
        return partial_attribute_set

    def test_missing_prefix_map_dsa(self):
        partial_attribute_set = self.get_partial_attribute_set()

        dc_guid_1 = self.ldb_dc1.get_invocation_id()

        drs, drs_handle = self._ds_bind(self.dnsname_dc1)

        req8 = self._exop_req8(dest_dsa=None,
                               invocation_id=dc_guid_1,
                               nc_dn_str=self.user,
                               exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                               partial_attribute_set=partial_attribute_set)

        try:
            (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
            self.assertEqual(ctr.extended_ret, drsuapi.DRSUAPI_EXOP_ERR_SUCCESS)
        except RuntimeError:
            self.fail("Missing prefixmap shouldn't have triggered an error")

    def test_invalid_prefix_map_attid(self):
        # Request for invalid attid
        partial_attribute_set = self.get_partial_attribute_set([99999])

        dc_guid_1 = self.ldb_dc1.get_invocation_id()
        drs, drs_handle = self._ds_bind(self.dnsname_dc1)

        try:
            pfm = self._samdb_fetch_pfm_and_schi()
        except KeyError:
            # On Windows, prefixMap isn't available over LDAP
            req8 = self._exop_req8(dest_dsa=None,
                                   invocation_id=dc_guid_1,
                                   nc_dn_str=self.user,
                                   exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ)
            (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
            pfm = ctr.mapping_ctr

        req8 = self._exop_req8(dest_dsa=None,
                               invocation_id=dc_guid_1,
                               nc_dn_str=self.user,
                               exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                               partial_attribute_set=partial_attribute_set,
                               mapping_ctr=pfm)

        try:
            (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
            self.fail("Invalid attid (99999) should have triggered an error")
        except RuntimeError as (ecode, emsg):
            self.assertEqual(ecode, 0x000020E2, "Error code should have been "
                             "WERR_DS_DRA_SCHEMA_MISMATCH")

    def test_secret_prefix_map_attid(self):
        # Request for a secret attid
        partial_attribute_set = self.get_partial_attribute_set([drsuapi.DRSUAPI_ATTID_unicodePwd])

        dc_guid_1 = self.ldb_dc1.get_invocation_id()
        drs, drs_handle = self._ds_bind(self.dnsname_dc1)

        try:
            pfm = self._samdb_fetch_pfm_and_schi()
        except KeyError:
            # On Windows, prefixMap isn't available over LDAP
            req8 = self._exop_req8(dest_dsa=None,
                                   invocation_id=dc_guid_1,
                                   nc_dn_str=self.user,
                                   exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ)
            (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
            pfm = ctr.mapping_ctr


        req8 = self._exop_req8(dest_dsa=None,
                               invocation_id=dc_guid_1,
                               nc_dn_str=self.user,
                               exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                               partial_attribute_set=partial_attribute_set,
                               mapping_ctr=pfm)

        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)

        found = False
        for attr in ctr.first_object.object.attribute_ctr.attributes:
            if attr.attid == drsuapi.DRSUAPI_ATTID_unicodePwd:
                found = True
                break

        self.assertTrue(found, "Ensure we get the unicodePwd attribute back")

        for i, mapping in enumerate(pfm.mappings):
            # OID: 2.5.4.*
            # objectClass: 2.5.4.0
            if mapping.oid.binary_oid == [85, 4]:
                idx1 = i
            # OID: 1.2.840.113556.1.4.*
            # unicodePwd: 1.2.840.113556.1.4.90
            elif mapping.oid.binary_oid == [42, 134, 72, 134, 247, 20, 1, 4]:
                idx2 = i

        (pfm.mappings[idx1].id_prefix,
         pfm.mappings[idx2].id_prefix) = (pfm.mappings[idx2].id_prefix,
                                          pfm.mappings[idx1].id_prefix)

        tmp = pfm.mappings
        tmp[idx1], tmp[idx2] = tmp[idx2], tmp[idx1]
        pfm.mappings = tmp

        # 90 for unicodePwd (with new prefix = 0)
        # 589824, 589827 for objectClass and CN
        # Use of three ensures sorting is correct
        partial_attribute_set = self.get_partial_attribute_set([90, 589824, 589827])
        req8 = self._exop_req8(dest_dsa=None,
                               invocation_id=dc_guid_1,
                               nc_dn_str=self.user,
                               exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                               partial_attribute_set=partial_attribute_set,
                               mapping_ctr=pfm)

        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)

        found = False
        for attr in ctr.first_object.object.attribute_ctr.attributes:
            if attr.attid == drsuapi.DRSUAPI_ATTID_unicodePwd:
                found = True
                break

        self.assertTrue(found, "Ensure we get the unicodePwd attribute back")

    def test_regular_prefix_map_attid(self):
        # Request for a regular (non-secret) attid
        partial_attribute_set = self.get_partial_attribute_set([drsuapi.DRSUAPI_ATTID_name])

        dc_guid_1 = self.ldb_dc1.get_invocation_id()
        drs, drs_handle = self._ds_bind(self.dnsname_dc1)

        try:
            pfm = self._samdb_fetch_pfm_and_schi()
        except KeyError:
            # On Windows, prefixMap isn't available over LDAP
            req8 = self._exop_req8(dest_dsa=None,
                                   invocation_id=dc_guid_1,
                                   nc_dn_str=self.user,
                                   exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ)
            (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
            pfm = ctr.mapping_ctr


        req8 = self._exop_req8(dest_dsa=None,
                               invocation_id=dc_guid_1,
                               nc_dn_str=self.user,
                               exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                               partial_attribute_set=partial_attribute_set,
                               mapping_ctr=pfm)

        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)

        found = False
        for attr in ctr.first_object.object.attribute_ctr.attributes:
            if attr.attid == drsuapi.DRSUAPI_ATTID_name:
                found = True
                break

        self.assertTrue(found, "Ensure we get the name attribute back")

        for i, mapping in enumerate(pfm.mappings):
            # OID: 2.5.4.*
            # objectClass: 2.5.4.0
            if mapping.oid.binary_oid == [85, 4]:
                idx1 = i
            # OID: 1.2.840.113556.1.4.*
            # name: 1.2.840.113556.1.4.1
            elif mapping.oid.binary_oid == [42, 134, 72, 134, 247, 20, 1, 4]:
                idx2 = i

        (pfm.mappings[idx1].id_prefix,
         pfm.mappings[idx2].id_prefix) = (pfm.mappings[idx2].id_prefix,
                                          pfm.mappings[idx1].id_prefix)

        tmp = pfm.mappings
        tmp[idx1], tmp[idx2] = tmp[idx2], tmp[idx1]
        pfm.mappings = tmp

        # 1 for name (with new prefix = 0)
        partial_attribute_set = self.get_partial_attribute_set([1])
        req8 = self._exop_req8(dest_dsa=None,
                               invocation_id=dc_guid_1,
                               nc_dn_str=self.user,
                               exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                               partial_attribute_set=partial_attribute_set,
                               mapping_ctr=pfm)

        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)

        found = False
        for attr in ctr.first_object.object.attribute_ctr.attributes:
            if attr.attid == drsuapi.DRSUAPI_ATTID_name:
                found = True
                break

        self.assertTrue(found, "Ensure we get the name attribute back")

    def test_regular_prefix_map_ex_attid(self):
        # Request for a regular (non-secret) attid
        partial_attribute_set = self.get_partial_attribute_set([drsuapi.DRSUAPI_ATTID_name])
        partial_attribute_set_ex = self.get_partial_attribute_set([drsuapi.DRSUAPI_ATTID_unicodePwd])

        dc_guid_1 = self.ldb_dc1.get_invocation_id()
        drs, drs_handle = self._ds_bind(self.dnsname_dc1)

        try:
            pfm = self._samdb_fetch_pfm_and_schi()
        except KeyError:
            # On Windows, prefixMap isn't available over LDAP
            req8 = self._exop_req8(dest_dsa=None,
                                   invocation_id=dc_guid_1,
                                   nc_dn_str=self.user,
                                   exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ)
            (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
            pfm = ctr.mapping_ctr


        req8 = self._exop_req8(dest_dsa=None,
                               invocation_id=dc_guid_1,
                               nc_dn_str=self.user,
                               exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                               partial_attribute_set=partial_attribute_set,
                               partial_attribute_set_ex=partial_attribute_set_ex,
                               mapping_ctr=pfm)

        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)

        found = False
        for attr in ctr.first_object.object.attribute_ctr.attributes:
            if attr.attid == drsuapi.DRSUAPI_ATTID_name:
                found = True
                break

        self.assertTrue(found, "Ensure we get the name attribute back")

        found = False
        for attr in ctr.first_object.object.attribute_ctr.attributes:
            if attr.attid == drsuapi.DRSUAPI_ATTID_unicodePwd:
                found = True
                break

        self.assertTrue(found, "Ensure we get the unicodePwd attribute back")

        for i, mapping in enumerate(pfm.mappings):
            # OID: 2.5.4.*
            # objectClass: 2.5.4.0
            if mapping.oid.binary_oid == [85, 4]:
                idx1 = i
            # OID: 1.2.840.113556.1.4.*
            # name: 1.2.840.113556.1.4.1
            # unicodePwd: 1.2.840.113556.1.4.90
            elif mapping.oid.binary_oid == [42, 134, 72, 134, 247, 20, 1, 4]:
                idx2 = i

        (pfm.mappings[idx1].id_prefix,
         pfm.mappings[idx2].id_prefix) = (pfm.mappings[idx2].id_prefix,
                                          pfm.mappings[idx1].id_prefix)

        tmp = pfm.mappings
        tmp[idx1], tmp[idx2] = tmp[idx2], tmp[idx1]
        pfm.mappings = tmp

        # 1 for name (with new prefix = 0)
        partial_attribute_set = self.get_partial_attribute_set([1])
        # 90 for unicodePwd (with new prefix = 0)
        # HOWEVER: Windows doesn't seem to respect incoming maps for PartialAttrSetEx
        partial_attribute_set_ex = self.get_partial_attribute_set([drsuapi.DRSUAPI_ATTID_unicodePwd])
        req8 = self._exop_req8(dest_dsa=None,
                               invocation_id=dc_guid_1,
                               nc_dn_str=self.user,
                               exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                               partial_attribute_set=partial_attribute_set,
                               partial_attribute_set_ex=partial_attribute_set_ex,
                               mapping_ctr=pfm)

        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)

        found = False
        for attr in ctr.first_object.object.attribute_ctr.attributes:
            if attr.attid == drsuapi.DRSUAPI_ATTID_name:
                found = True
                break

        self.assertTrue(found, "Ensure we get the name attribute back")

        found = False
        for attr in ctr.first_object.object.attribute_ctr.attributes:
            if attr.attid == drsuapi.DRSUAPI_ATTID_unicodePwd:
                found = True
                break

        self.assertTrue(found, "Ensure we get the unicodePwd attribute back")

    def _samdb_fetch_pfm_and_schi(self):
        """Fetch prefixMap and schemaInfo stored in SamDB using LDB connection"""
        samdb = self.ldb_dc1
        res = samdb.search(base=samdb.get_schema_basedn(), scope=SCOPE_BASE,
                           attrs=["prefixMap", "schemaInfo"])

        pfm = ndr_unpack(drsblobs.prefixMapBlob,
                         str(res[0]['prefixMap']))

        schi = drsuapi.DsReplicaOIDMapping()
        schi.id_prefix = 0

        if 'schemaInfo' in res[0]:
            schi.oid.length = len(map(ord, str(res[0]['schemaInfo'])))
            schi.oid.binary_oid = map(ord, str(res[0]['schemaInfo']))
        else:
            schema_info = drsblobs.schemaInfoBlob()
            schema_info.revision = 0
            schema_info.marker = 0xFF
            schema_info.invocation_id = misc.GUID(samdb.get_invocation_id())
            schi.oid.length = len(map(ord, ndr_pack(schema_info)))
            schi.oid.binary_oid = map(ord, ndr_pack(schema_info))

        pfm.ctr.mappings = pfm.ctr.mappings + [schi]
        pfm.ctr.num_mappings += 1
        return pfm.ctr

class DrsReplicaSyncSortTestCase(drs_base.DrsBaseTestCase, ExopBaseTest):
    def setUp(self):
        super(DrsReplicaSyncSortTestCase, self).setUp()
        self.base_dn = self.ldb_dc1.get_default_basedn()
        self.ou = "ou=sort_exop,%s" % self.base_dn
        self.ldb_dc1.add({
            "dn": self.ou,
            "objectclass": "organizationalUnit"})

    def tearDown(self):
        super(DrsReplicaSyncSortTestCase, self).tearDown()
        # tidyup groups and users
        try:
            self.ldb_dc1.delete(self.ou, ["tree_delete:1"])
        except ldb.LdbError as (enum, string):
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                pass

    def add_linked_attribute(self, src, dest, attr='member'):
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb_dc1, src)
        m[attr] = ldb.MessageElement(dest, ldb.FLAG_MOD_ADD, attr)
        self.ldb_dc1.modify(m)

    def remove_linked_attribute(self, src, dest, attr='member'):
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb_dc1, src)
        m[attr] = ldb.MessageElement(dest, ldb.FLAG_MOD_DELETE, attr)
        self.ldb_dc1.modify(m)

    def test_sort_behaviour_single_object(self):
        """Testing sorting behaviour on single objects"""

        user1_dn = "cn=test_user1,%s" % self.ou
        user2_dn = "cn=test_user2,%s" % self.ou
        user3_dn = "cn=test_user3,%s" % self.ou
        group_dn = "cn=test_group,%s" % self.ou

        self.ldb_dc1.add({"dn": user1_dn, "objectclass": "user"})
        self.ldb_dc1.add({"dn": user2_dn, "objectclass": "user"})
        self.ldb_dc1.add({"dn": user3_dn, "objectclass": "user"})
        self.ldb_dc1.add({"dn": group_dn, "objectclass": "group"})

        u1_guid = str(misc.GUID(self.ldb_dc1.search(base=user1_dn,
                      attrs=["objectGUID"])[0]['objectGUID'][0]))
        u2_guid = str(misc.GUID(self.ldb_dc1.search(base=user2_dn,
                      attrs=["objectGUID"])[0]['objectGUID'][0]))
        u3_guid = str(misc.GUID(self.ldb_dc1.search(base=user3_dn,
                      attrs=["objectGUID"])[0]['objectGUID'][0]))
        g_guid = str(misc.GUID(self.ldb_dc1.search(base=group_dn,
                     attrs=["objectGUID"])[0]['objectGUID'][0]))

        self.add_linked_attribute(group_dn, user1_dn,
                                  attr='member')
        self.add_linked_attribute(group_dn, user2_dn,
                                  attr='member')
        self.add_linked_attribute(group_dn, user3_dn,
                                  attr='member')
        self.add_linked_attribute(group_dn, user1_dn,
                                  attr='managedby')
        self.add_linked_attribute(group_dn, user2_dn,
                                  attr='nonSecurityMember')
        self.add_linked_attribute(group_dn, user3_dn,
                                  attr='nonSecurityMember')

        set_inactive = AbstractLink(drsuapi.DRSUAPI_ATTID_nonSecurityMember,
                                    drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE,
                                    g_guid, u3_guid)

        expected_links = set([set_inactive,
        AbstractLink(drsuapi.DRSUAPI_ATTID_member,
                     drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE,
                     g_guid,
                     u1_guid),
        AbstractLink(drsuapi.DRSUAPI_ATTID_member,
                     drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE,
                     g_guid,
                     u2_guid),
        AbstractLink(drsuapi.DRSUAPI_ATTID_member,
                     drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE,
                     g_guid,
                     u3_guid),
        AbstractLink(drsuapi.DRSUAPI_ATTID_managedBy,
                     drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE,
                     g_guid,
                     u1_guid),
        AbstractLink(drsuapi.DRSUAPI_ATTID_nonSecurityMember,
                     drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE,
                     g_guid,
                     u2_guid),
        ])

        dc_guid_1 = self.ldb_dc1.get_invocation_id()

        drs, drs_handle = self._ds_bind(self.dnsname_dc1)

        req8 = self._exop_req8(dest_dsa=None,
                invocation_id=dc_guid_1,
                nc_dn_str=group_dn,
                exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ)

        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)

        no_inactive = []
        for link in ctr.linked_attributes:
            target_guid = ndr_unpack(drsuapi.DsReplicaObjectIdentifier3,
                                     link.value.blob).guid
            no_inactive.append((link, target_guid))
            self.assertTrue(AbstractLink(link.attid, link.flags,
                                         str(link.identifier.guid),
                                         str(target_guid)) in expected_links)

        no_inactive.sort(cmp=_linked_attribute_compare)

        # assert the two arrays are the same
        self.assertEqual(len(expected_links), ctr.linked_attributes_count)
        self.assertEqual([x[0] for x in no_inactive], ctr.linked_attributes)

        self.remove_linked_attribute(group_dn, user3_dn,
                                     attr='nonSecurityMember')

        # Set the link inactive
        expected_links.remove(set_inactive)
        set_inactive.flags = 0
        expected_links.add(set_inactive)

        has_inactive = []
        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
        for link in ctr.linked_attributes:
            target_guid = ndr_unpack(drsuapi.DsReplicaObjectIdentifier3,
                                     link.value.blob).guid
            has_inactive.append((link, target_guid))
            self.assertTrue(AbstractLink(link.attid, link.flags,
                                         str(link.identifier.guid),
                                         str(target_guid)) in expected_links)

        has_inactive.sort(cmp=_linked_attribute_compare)

        # assert the two arrays are the same
        self.assertEqual(len(expected_links), ctr.linked_attributes_count)
        self.assertEqual([x[0] for x in has_inactive], ctr.linked_attributes)

    def test_sort_behaviour_ncchanges(self):
        """Testing sorting behaviour on a group of objects."""
        user1_dn = "cn=test_user1,%s" % self.ou
        group_dn = "cn=test_group,%s" % self.ou
        self.ldb_dc1.add({"dn": user1_dn, "objectclass": "user"})
        self.ldb_dc1.add({"dn": group_dn, "objectclass": "group"})

        self.add_linked_attribute(group_dn, user1_dn,
                                  attr='member')

        dc_guid_1 = self.ldb_dc1.get_invocation_id()

        drs, drs_handle = self._ds_bind(self.dnsname_dc1)

        # Make sure the max objects count is high enough
        req8 = self._exop_req8(dest_dsa=None,
                               invocation_id=dc_guid_1,
                               nc_dn_str=self.base_dn,
                               replica_flags=0,
                               max_objects=100,
                               exop=drsuapi.DRSUAPI_EXOP_NONE)

        # Loop until we get linked attributes, or we get to the end.
        # Samba sends linked attributes at the end, unlike Windows.
        while True:
            (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
            if ctr.more_data == 0 or ctr.linked_attributes_count != 0:
                break
            req8.highwatermark = ctr.new_highwatermark

        self.assertTrue(ctr.linked_attributes_count != 0)

        no_inactive = []
        for link in ctr.linked_attributes:
            try:
                target_guid = ndr_unpack(drsuapi.DsReplicaObjectIdentifier3,
                                     link.value.blob).guid
            except:
                target_guid = ndr_unpack(drsuapi.DsReplicaObjectIdentifier3Binary,
                                         link.value.blob).guid
            no_inactive.append((link, target_guid))

        no_inactive.sort(cmp=_linked_attribute_compare)

        # assert the two arrays are the same
        self.assertEqual([x[0] for x in no_inactive], ctr.linked_attributes)
