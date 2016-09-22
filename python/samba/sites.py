# python site manipulation code
# Copyright Matthieu Patou <mat@matws.net> 2011
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

"""Manipulating sites."""

import ldb
from ldb import FLAG_MOD_ADD, LdbError


class SiteException(Exception):
    """Base element for Sites errors"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "%s: %s" % (self.__class__.__name__, self.value)


class SiteNotFoundException(SiteException):
    """Raised when the site is not found and it's expected to exists."""


class SiteAlreadyExistsException(SiteException):
    """Raised when the site is not found and it's expected not to exists."""


class SiteServerNotEmptyException(SiteException):
    """Raised when the site still has servers attached."""


def create_site(samdb, configDn, siteName):
    """
    Create a site

    :param samdb: A samdb connection
    :param configDn: The DN of the configuration partition
    :param siteName: Name of the site to create
    :return: True upon success
    :raise SiteAlreadyExists: if the site to be created already exists.
    """

    ret = samdb.search(base=configDn, scope=ldb.SCOPE_SUBTREE,
                    expression='(&(objectclass=Site)(cn=%s))' % siteName)
    if len(ret) != 0:
        raise SiteAlreadyExistsException('A site with the name %s already exists' % siteName)

    m = ldb.Message()
    m.dn = ldb.Dn(samdb, "Cn=%s,CN=Sites,%s" % (siteName, str(configDn)))
    m["objectclass"] = ldb.MessageElement("site", FLAG_MOD_ADD, "objectclass")

    samdb.add(m)

    m2 = ldb.Message()
    m2.dn = ldb.Dn(samdb, "Cn=NTDS Site Settings,%s" % str(m.dn))
    m2["objectclass"] = ldb.MessageElement("nTDSSiteSettings", FLAG_MOD_ADD, "objectclass")

    samdb.add(m2)

    m3 = ldb.Message()
    m3.dn = ldb.Dn(samdb, "Cn=Servers,%s" % str(m.dn))
    m3["objectclass"] = ldb.MessageElement("serversContainer", FLAG_MOD_ADD, "objectclass")

    samdb.add(m3)

    return True


def delete_site(samdb, configDn, siteName):
    """
    Delete a site

    :param samdb: A samdb connection
    :param configDn: The DN of the configuration partition
    :param siteName: Name of the site to delete
    :return: True upon success
    :raise SiteNotFoundException: if the site to be deleted do not exists.
    :raise SiteServerNotEmpty: if the site has still servers in it.
    """

    dnsite = ldb.Dn(samdb, "CN=Sites")
    if dnsite.add_base(configDn) == False:
        raise SiteException("dnsites.add_base() failed")
    if dnsite.add_child("CN=X") == False:
        raise SiteException("dnsites.add_child() failed")
    dnsite.set_component(0, "CN", siteName)

    dnservers = ldb.Dn(samdb, "CN=Servers")
    dnservers.add_base(dnsite)

    try:
        ret = samdb.search(base=dnsite, scope=ldb.SCOPE_BASE,
                           expression="objectClass=site")
        if len(ret) != 1:
            raise SiteNotFoundException('Site %s does not exist' % siteName)
    except LdbError as (enum, estr):
        if enum == ldb.ERR_NO_SUCH_OBJECT:
            raise SiteNotFoundException('Site %s does not exist' % siteName)

    ret = samdb.search(base=dnservers, scope=ldb.SCOPE_ONELEVEL,
                       expression='(objectclass=server)')
    if len(ret) != 0:
        raise SiteServerNotEmptyException('Site %s still has servers in it, move them before removal' % siteName)

    samdb.delete(dnsite, ["tree_delete:0"])

    return True
