#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Originally based on ./sam.py
from unicodedata import normalize
import locale
locale.setlocale(locale.LC_ALL, ('en_US', 'UTF-8'))

import optparse
import sys
import os
import re

sys.path.insert(0, "bin/python")
import samba
from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

from samba.auth import system_session
import ldb
from samba.samdb import SamDB

parser = optparse.OptionParser("sort.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

parser.add_option('--elements', type='int', default=33,
                  help="use this many elements in the tests")

opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)


def norm(x):
    x = x.decode('utf-8')
    return normalize('NFKC', x).upper().encode('utf-8')

# Python, Windows, and Samba all sort the following sequence in
# drastically different ways. The order here is what you get from
# Windows2012R2.
FIENDISH_TESTS = [' ', ' e', '\t-\t', '\n\t\t', '!@#!@#!', '¼', '¹', '1',
                  '1/4', '1⁄4', '1\xe2\x81\x845', '3', 'abc', 'fo\x00od',

                  # Here we also had '\x00food', but that seems to sort
                  # non-deterministically on Windows vis-a-vis 'fo\x00od'.

                  'kōkako', 'ŋđ¼³ŧ “«đð', 'ŋđ¼³ŧ“«đð',
                  'ｓorttest', 'sorttēst11,', 'śorttest2', 'śoRttest2',
                  'ś-o-r-t-t-e-s-t-2', 'soRTTēst2,', 'ṡorttest4', 'ṡorttesT4',
                  'sörttest-5', 'sÖrttest-5', 'so-rttest7,', '桑巴']


class BaseSortTests(samba.tests.TestCase):
    avoid_tricky_sort = False
    maxDiff = 2000

    def create_user(self, i, n, prefix='sorttest', suffix='', attrs=None,
                    tricky=False):
        name = "%s%d%s" % (prefix, i, suffix)
        user = {
            'cn': name,
            "objectclass": "user",
            'givenName': "abcdefghijklmnopqrstuvwxyz"[i % 26],
            "roomNumber": "%sb\x00c" % (n - i),
            "carLicense": "后来经",
            "employeeNumber": "%s%sx" % (abs(i * (99 - i)), '\n' * (i & 255)),
            "accountExpires": "%s" % (10 ** 9 + 1000000 * i),
            "msTSExpireDate4": "19%02d0101010000.0Z" % (i % 100),
            "flags": str(i * (n - i)),
            "serialNumber": "abc %s%s%s" % ('AaBb |-/'[i & 7],
                                            ' 3z}'[i & 3],
                                            '"@'[i & 1],),
            "comment": "Favourite colour is %d" % (n % (i + 1)),
        }

        if self.avoid_tricky_sort:
            # We are not even going to try passing tests that assume
            # some kind of Unicode awareness.
            for k, v in user.items():
                user[k] = re.sub(r'[^\w,.]', 'X', v)
        else:
            # Add some even trickier ones!
            fiendish_index = i % len(FIENDISH_TESTS)
            user.update({
                # Sort doesn't look past a NUL byte.
                "photo": "\x00%d" % (n - i),
                "audio": "%sn octet string %s%s ♫♬\x00lalala" % ('Aa'[i & 1],
                                                                 chr(i & 255),
                                                                 i),
                "displayNamePrintable": "%d\x00%c" % (i, i & 255),
                "adminDisplayName": "%d\x00b" % (n-i),
                "title": "%d%sb" % (n - i, '\x00' * i),

                # Names that vary only in case. Windows returns
                # equivalent addresses in the order they were put
                # in ('a st', 'A st',...). We don't check that.
                "street": "%s st" % (chr(65 | (i & 14) | ((i & 1) * 32))),

                "streetAddress": FIENDISH_TESTS[fiendish_index],
                "postalAddress": FIENDISH_TESTS[-fiendish_index],
            })

        if attrs is not None:
            user.update(attrs)

        user['dn'] = "cn=%s,%s" % (user['cn'], self.ou)

        self.users.append(user)
        self.ldb.add(user)
        return user

    def setUp(self):
        super(BaseSortTests, self).setUp()
        self.ldb = SamDB(host, credentials=creds,
                         session_info=system_session(lp), lp=lp)

        self.base_dn = self.ldb.domain_dn()
        self.ou = "ou=sort,%s" % self.base_dn
        if False:
            try:
                self.ldb.delete(self.ou, ['tree_delete:1'])
            except ldb.LdbError, e:
                print "tried deleting %s, got error %s" % (self.ou, e)

        self.ldb.add({
            "dn": self.ou,
            "objectclass": "organizationalUnit"})
        self.users = []
        n = opts.elements
        for i in range(n):
            self.create_user(i, n)

        attrs = set(self.users[0].keys()) - set([
            'objectclass', 'dn'])
        self.binary_sorted_keys = attrs.intersection(['audio',
                                                      'photo',
                                                      "msTSExpireDate4",
                                                      'serialNumber',
                                                      "displayNamePrintable"])

        self.numeric_sorted_keys = attrs.intersection(['flags',
                                                       'accountExpires'])

        self.timestamp_keys = attrs.intersection(['msTSExpireDate4'])

        self.int64_keys = set(['accountExpires'])

        self.locale_sorted_keys = [x for x in attrs if
                                   x not in (self.binary_sorted_keys |
                                             self.numeric_sorted_keys)]

        self.expected_results = {}
        self.expected_results_binary = {}

        for k in self.locale_sorted_keys:
            # Using key=locale.strxfrm fails on \x00
            forward = sorted((norm(x[k]) for x in self.users),
                             cmp=locale.strcoll)
            reverse = list(reversed(forward))
            self.expected_results[k] = (forward, reverse)

        for k in self.binary_sorted_keys:
            forward = sorted((x[k] for x in self.users))
            reverse = list(reversed(forward))
            self.expected_results_binary[k] = (forward, reverse)
            self.expected_results[k] = (forward, reverse)

        # Fix up some because Python gets it wrong, using Schwartzian tramsform
        for k in ('adminDisplayName', 'title', 'streetAddress',
                  'employeeNumber'):
            if k in self.expected_results:
                broken = self.expected_results[k][0]
                tmp = [(x.replace('\x00', ''), x) for x in broken]
                tmp.sort()
                fixed = [x[1] for x in tmp]
                self.expected_results[k] = (fixed, list(reversed(fixed)))
        for k in ('streetAddress', 'postalAddress'):
            if k in self.expected_results:
                c = {}
                for u in self.users:
                    x = u[k]
                    if x in c:
                        c[x] += 1
                        continue
                    c[x] = 1
                fixed = []
                for x in FIENDISH_TESTS:
                    fixed += [norm(x)] * c.get(x, 0)

                rev = list(reversed(fixed))
                self.expected_results[k] = (fixed, rev)

    def tearDown(self):
        super(BaseSortTests, self).tearDown()
        self.ldb.delete(self.ou, ['tree_delete:1'])

    def _test_server_sort_default(self):
        attrs = self.locale_sorted_keys

        for attr in attrs:
            for rev in (0, 1):
                res = self.ldb.search(self.ou,
                                      scope=ldb.SCOPE_ONELEVEL, attrs=[attr],
                                      controls=["server_sort:1:%d:%s" %
                                                (rev, attr)])
                self.assertEqual(len(res), len(self.users))

                expected_order = self.expected_results[attr][rev]
                received_order = [norm(x[attr][0]) for x in res]
                if expected_order != received_order:
                    print attr, ['forward', 'reverse'][rev]
                    print "expected", expected_order
                    print "recieved", received_order
                    print "unnormalised:", [x[attr][0] for x in res]
                    print "unnormalised: «%s»" % '»  «'.join(x[attr][0]
                                                             for x in res)
                self.assertEquals(expected_order, received_order)

    def _test_server_sort_binary(self):
        for attr in self.binary_sorted_keys:
            for rev in (0, 1):
                res = self.ldb.search(self.ou,
                                      scope=ldb.SCOPE_ONELEVEL, attrs=[attr],
                                      controls=["server_sort:1:%d:%s" %
                                                (rev, attr)])

                self.assertEqual(len(res), len(self.users))
                expected_order = self.expected_results_binary[attr][rev]
                received_order = [x[attr][0] for x in res]
                if expected_order != received_order:
                    print attr
                    print expected_order
                    print received_order
                self.assertEquals(expected_order, received_order)

    def _test_server_sort_us_english(self):
        # Windows doesn't support many matching rules, but does allow
        # the locale specific sorts -- if it has the locale installed.
        # The most reliable locale is the default US English, which
        # won't change the sort order.

        for lang, oid in [('en_US', '1.2.840.113556.1.4.1499'),
                          ]:

            for attr in self.locale_sorted_keys:
                for rev in (0, 1):
                    res = self.ldb.search(self.ou,
                                          scope=ldb.SCOPE_ONELEVEL,
                                          attrs=[attr],
                                          controls=["server_sort:1:%d:%s:%s" %
                                                    (rev, attr, oid)])

                    self.assertTrue(len(res) == len(self.users))
                    expected_order = self.expected_results[attr][rev]
                    received_order = [norm(x[attr][0]) for x in res]
                    if expected_order != received_order:
                        print attr, lang
                        print ['forward', 'reverse'][rev]
                        print "expected: ", expected_order
                        print "recieved: ", received_order
                        print "unnormalised:", [x[attr][0] for x in res]
                        print "unnormalised: «%s»" % '»  «'.join(x[attr][0]
                                                                 for x in res)

                    self.assertEquals(expected_order, received_order)

    def _test_server_sort_different_attr(self):

        def cmp_locale(a, b):
            return locale.strcoll(a[0], b[0])

        def cmp_binary(a, b):
            return cmp(a[0], b[0])

        def cmp_numeric(a, b):
            return cmp(int(a[0]), int(b[0]))

        # For testing simplicity, the attributes in here need to be
        # unique for each user. Otherwise there are multiple possible
        # valid answers.
        sort_functions = {'cn': cmp_binary,
                          "employeeNumber": cmp_locale,
                          "accountExpires": cmp_numeric,
                          "msTSExpireDate4": cmp_binary}
        attrs = sort_functions.keys()
        attr_pairs = zip(attrs, attrs[1:] + attrs[:1])

        for sort_attr, result_attr in attr_pairs:
            forward = sorted(((norm(x[sort_attr]), norm(x[result_attr]))
                             for x in self.users),
                             cmp=sort_functions[sort_attr])
            reverse = list(reversed(forward))

            for rev in (0, 1):
                res = self.ldb.search(self.ou,
                                      scope=ldb.SCOPE_ONELEVEL,
                                      attrs=[result_attr],
                                      controls=["server_sort:1:%d:%s" %
                                                (rev, sort_attr)])
                self.assertEqual(len(res), len(self.users))
                pairs = (forward, reverse)[rev]

                expected_order = [x[1] for x in pairs]
                received_order = [norm(x[result_attr][0]) for x in res]

                if expected_order != received_order:
                    print sort_attr, result_attr, ['forward', 'reverse'][rev]
                    print "expected", expected_order
                    print "recieved", received_order
                    print "unnormalised:", [x[result_attr][0] for x in res]
                    print "unnormalised: «%s»" % '»  «'.join(x[result_attr][0]
                                                             for x in res)
                    print "pairs:", pairs
                    # There are bugs in Windows that we don't want (or
                    # know how) to replicate regarding timestamp sorting.
                    # Let's remind ourselves.
                    if result_attr == "msTSExpireDate4":
                        print '-' * 72
                        print ("This test fails against Windows with the "
                               "default number of elements (33).")
                        print "Try with --elements=27 (or similar)."
                        print '-' * 72

                self.assertEquals(expected_order, received_order)
                for x in res:
                    if sort_attr in x:
                        self.fail('the search for %s should not return %s' %
                                  (result_attr, sort_attr))


class SimpleSortTests(BaseSortTests):
    avoid_tricky_sort = True
    def test_server_sort_different_attr(self):
        self._test_server_sort_different_attr()

    def test_server_sort_default(self):
        self._test_server_sort_default()

    def test_server_sort_binary(self):
        self._test_server_sort_binary()

    def test_server_sort_us_english(self):
        self._test_server_sort_us_english()


class UnicodeSortTests(BaseSortTests):
    avoid_tricky_sort = False

    def test_server_sort_default(self):
        self._test_server_sort_default()

    def test_server_sort_us_english(self):
        self._test_server_sort_us_english()

    def test_server_sort_different_attr(self):
        self._test_server_sort_different_attr()


if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host


TestProgram(module=__name__, opts=subunitopts)
