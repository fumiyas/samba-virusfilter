# user management
#
# Copyright Jelmer Vernooij 2010 <jelmer@samba.org>
# Copyright Theresa Halloran 2011 <theresahalloran@gmail.com>
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
import pwd
import os
import sys
import fcntl
import signal
import errno
import time
import base64
import binascii
from subprocess import Popen, PIPE, STDOUT
from getpass import getpass
from samba.auth import system_session
from samba.samdb import SamDB
from samba.dcerpc import misc
from samba.dcerpc import security
from samba.dcerpc import drsblobs
from samba.ndr import ndr_unpack, ndr_pack, ndr_print
from samba import (
    credentials,
    dsdb,
    gensec,
    generate_random_password,
    Ldb,
    )
from samba.net import Net

from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option,
    )


try:
    import io
    import gpgme
    gpgme_support = True
    decrypt_samba_gpg_help = "Decrypt the SambaGPG password as cleartext source"
except ImportError as e:
    gpgme_support = False
    decrypt_samba_gpg_help = "Decrypt the SambaGPG password not supported, " + \
            "python-gpgme required"

disabled_virtual_attributes = {
    }

virtual_attributes = {
    "virtualClearTextUTF8": {
        "flags": ldb.ATTR_FLAG_FORCE_BASE64_LDIF,
        },
    "virtualClearTextUTF16": {
        "flags": ldb.ATTR_FLAG_FORCE_BASE64_LDIF,
        },
    "virtualSambaGPG": {
        "flags": ldb.ATTR_FLAG_FORCE_BASE64_LDIF,
        },
    }

get_random_bytes_fn = None
if get_random_bytes_fn is None:
    try:
        import Crypto.Random
        get_random_bytes_fn = Crypto.Random.get_random_bytes
    except ImportError as e:
        pass
if get_random_bytes_fn is None:
    try:
        import M2Crypto.Rand
        get_random_bytes_fn = M2Crypto.Rand.rand_bytes
    except ImportError as e:
        pass

def check_random():
    if get_random_bytes_fn is not None:
        return None
    return "Crypto.Random or M2Crypto.Rand required"

def get_random_bytes(num):
    random_reason = check_random()
    if random_reason is not None:
        raise ImportError(random_reason)
    return get_random_bytes_fn(num)

def get_crypt_value(alg, utf8pw):
    algs = {
        "5": {"length": 43},
        "6": {"length": 86},
    }
    assert alg in algs
    salt = get_random_bytes(16)
    # The salt needs to be in [A-Za-z0-9./]
    # base64 is close enough and as we had 16
    # random bytes but only need 16 characters
    # we can ignore the possible == at the end
    # of the base64 string
    # we just need to replace '+' by '.'
    b64salt = base64.b64encode(salt)
    crypt_salt = "$%s$%s$" % (alg, b64salt[0:16].replace('+', '.'))
    crypt_value = crypt.crypt(utf8pw, crypt_salt)
    if crypt_value is None:
        raise NotImplementedError("crypt.crypt(%s) returned None" % (crypt_salt))
    expected_len = len(crypt_salt) + algs[alg]["length"]
    if len(crypt_value) != expected_len:
        raise NotImplementedError("crypt.crypt(%s) returned a value with length %d, expected length is %d" % (
            crypt_salt, len(crypt_value), expected_len))
    return crypt_value

try:
    random_reason = check_random()
    if random_reason is not None:
        raise ImportError(random_reason)
    import hashlib
    h = hashlib.sha1()
    h = None
    virtual_attributes["virtualSSHA"] = {
        }
except ImportError as e:
    reason = "hashlib.sha1()"
    if random_reason:
        reason += " and " + random_reason
    reason += " required"
    disabled_virtual_attributes["virtualSSHA"] = {
        "reason" : reason,
        }

for (alg, attr) in [("5", "virtualCryptSHA256"), ("6", "virtualCryptSHA512")]:
    try:
        random_reason = check_random()
        if random_reason is not None:
            raise ImportError(random_reason)
        import crypt
        v = get_crypt_value(alg, "")
        v = None
        virtual_attributes[attr] = {
            }
    except ImportError as e:
        reason = "crypt"
        if random_reason:
            reason += " and " + random_reason
        reason += " required"
        disabled_virtual_attributes[attr] = {
            "reason" : reason,
            }
    except NotImplementedError as e:
        reason = "modern '$%s$' salt in crypt(3) required" % (alg)
        disabled_virtual_attributes[attr] = {
            "reason" : reason,
            }

virtual_attributes_help  = "The attributes to display (comma separated). "
virtual_attributes_help += "Possible supported virtual attributes: %s" % ", ".join(sorted(virtual_attributes.keys()))
if len(disabled_virtual_attributes) != 0:
    virtual_attributes_help += "Unsupported virtual attributes: %s" % ", ".join(sorted(disabled_virtual_attributes.keys()))

class cmd_user_create(Command):
    """Create a new user.

This command creates a new user account in the Active Directory domain.  The username specified on the command is the sAMaccountName.

User accounts may represent physical entities, such as people or may be used as service accounts for applications.  User accounts are also referred to as security principals and are assigned a security identifier (SID).

A user account enables a user to logon to a computer and domain with an identity that can be authenticated.  To maximize security, each user should have their own unique user account and password.  A user's access to domain resources is based on permissions assigned to the user account.

Unix (RFC2307) attributes may be added to the user account. Attributes taken from NSS are obtained on the local machine. Explicitly given values override values obtained from NSS. Configure 'idmap_ldb:use rfc2307 = Yes' to use these attributes for UID/GID mapping.

The command may be run from the root userid or another authorized userid.  The -H or --URL= option can be used to execute the command against a remote server.

Example1:
samba-tool user create User1 passw0rd --given-name=John --surname=Smith --must-change-at-next-login -H ldap://samba.samdom.example.com -Uadministrator%passw1rd

Example1 shows how to create a new user in the domain against a remote LDAP server.  The -H parameter is used to specify the remote target server.  The -U option is used to pass the userid and password authorized to issue the command remotely.

Example2:
sudo samba-tool user create User2 passw2rd --given-name=Jane --surname=Doe --must-change-at-next-login

Example2 shows how to create a new user in the domain against the local server.   sudo is used so a user may run the command as root.  In this example, after User2 is created, he/she will be forced to change their password when they logon.

Example3:
samba-tool user create User3 passw3rd --userou='OU=OrgUnit'

Example3 shows how to create a new user in the OrgUnit organizational unit.

Example4:
samba-tool user create User4 passw4rd --rfc2307-from-nss --gecos 'some text'

Example4 shows how to create a new user with Unix UID, GID and login-shell set from the local NSS and GECOS set to 'some text'.

Example5:
samba-tool user create User5 passw5rd --nis-domain=samdom --unix-home=/home/User5 \
           --uid-number=10005 --login-shell=/bin/false --gid-number=10000

Example5 shows how to create an RFC2307/NIS domain enabled user account. If
--nis-domain is set, then the other four parameters are mandatory.

"""
    synopsis = "%prog <username> [<password>] [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
        Option("--must-change-at-next-login",
                help="Force password to be changed on next login",
                action="store_true"),
        Option("--random-password",
                help="Generate random password",
                action="store_true"),
        Option("--smartcard-required",
                help="Require a smartcard for interactive logons",
                action="store_true"),
        Option("--use-username-as-cn",
                help="Force use of username as user's CN",
                action="store_true"),
        Option("--userou",
                help="DN of alternative location (without domainDN counterpart) to default CN=Users in which new user object will be created. E. g. 'OU=<OU name>'",
                type=str),
        Option("--surname", help="User's surname", type=str),
        Option("--given-name", help="User's given name", type=str),
        Option("--initials", help="User's initials", type=str),
        Option("--profile-path", help="User's profile path", type=str),
        Option("--script-path", help="User's logon script path", type=str),
        Option("--home-drive", help="User's home drive letter", type=str),
        Option("--home-directory", help="User's home directory path", type=str),
        Option("--job-title", help="User's job title", type=str),
        Option("--department", help="User's department", type=str),
        Option("--company", help="User's company", type=str),
        Option("--description", help="User's description", type=str),
        Option("--mail-address", help="User's email address", type=str),
        Option("--internet-address", help="User's home page", type=str),
        Option("--telephone-number", help="User's phone number", type=str),
        Option("--physical-delivery-office", help="User's office location", type=str),
        Option("--rfc2307-from-nss",
                help="Copy Unix user attributes from NSS (will be overridden by explicit UID/GID/GECOS/shell)",
                action="store_true"),
        Option("--nis-domain", help="User's Unix/RFC2307 NIS domain", type=str),
        Option("--unix-home", help="User's Unix/RFC2307 home directory",
                type=str),
        Option("--uid", help="User's Unix/RFC2307 username", type=str),
        Option("--uid-number", help="User's Unix/RFC2307 numeric UID", type=int),
        Option("--gid-number", help="User's Unix/RFC2307 primary GID number", type=int),
        Option("--gecos", help="User's Unix/RFC2307 GECOS field", type=str),
        Option("--login-shell", help="User's Unix/RFC2307 login shell", type=str),
    ]

    takes_args = ["username", "password?"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, username, password=None, credopts=None, sambaopts=None,
            versionopts=None, H=None, must_change_at_next_login=False,
            random_password=False, use_username_as_cn=False, userou=None,
            surname=None, given_name=None, initials=None, profile_path=None,
            script_path=None, home_drive=None, home_directory=None,
            job_title=None, department=None, company=None, description=None,
            mail_address=None, internet_address=None, telephone_number=None,
            physical_delivery_office=None, rfc2307_from_nss=False,
            nis_domain=None, unix_home=None, uid=None, uid_number=None,
            gid_number=None, gecos=None, login_shell=None,
            smartcard_required=False):

        if smartcard_required:
            if password is not None and password is not '':
                raise CommandError('It is not allowed to specifiy '
                                   '--newpassword '
                                   'together with --smartcard-required.')
            if must_change_at_next_login:
                raise CommandError('It is not allowed to specifiy '
                                   '--must-change-at-next-login '
                                   'together with --smartcard-required.')

        if random_password and not smartcard_required:
            password = generate_random_password(128, 255)

        while True:
            if smartcard_required:
                break
            if password is not None and password is not '':
                break
            password = getpass("New Password: ")
            passwordverify = getpass("Retype Password: ")
            if not password == passwordverify:
                password = None
                self.outf.write("Sorry, passwords do not match.\n")

        if rfc2307_from_nss:
                pwent = pwd.getpwnam(username)
                if uid is None:
                    uid = username
                if uid_number is None:
                    uid_number = pwent[2]
                if gid_number is None:
                    gid_number = pwent[3]
                if gecos is None:
                    gecos = pwent[4]
                if login_shell is None:
                    login_shell = pwent[6]

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        if uid_number or gid_number:
            if not lp.get("idmap_ldb:use rfc2307"):
                self.outf.write("You are setting a Unix/RFC2307 UID or GID. You may want to set 'idmap_ldb:use rfc2307 = Yes' to use those attributes for XID/SID-mapping.\n")

        if nis_domain is not None:
            if None in (uid_number, login_shell, unix_home, gid_number):
                raise CommandError('Missing parameters. To enable NIS features, '
                                   'the following options have to be given: '
                                   '--nis-domain=, --uidNumber=, --login-shell='
                                   ', --unix-home=, --gid-number= Operation '
                                   'cancelled.')

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)
            samdb.newuser(username, password, force_password_change_at_next_login_req=must_change_at_next_login,
                          useusernameascn=use_username_as_cn, userou=userou, surname=surname, givenname=given_name, initials=initials,
                          profilepath=profile_path, homedrive=home_drive, scriptpath=script_path, homedirectory=home_directory,
                          jobtitle=job_title, department=department, company=company, description=description,
                          mailaddress=mail_address, internetaddress=internet_address,
                          telephonenumber=telephone_number, physicaldeliveryoffice=physical_delivery_office,
                          nisdomain=nis_domain, unixhome=unix_home, uid=uid,
                          uidnumber=uid_number, gidnumber=gid_number,
                          gecos=gecos, loginshell=login_shell,
                          smartcard_required=smartcard_required)
        except Exception, e:
            raise CommandError("Failed to add user '%s': " % username, e)

        self.outf.write("User '%s' created successfully\n" % username)


class cmd_user_add(cmd_user_create):
    __doc__ = cmd_user_create.__doc__
    # take this print out after the add subcommand is removed.
    # the add subcommand is deprecated but left in for now to allow people to
    # migrate to create

    def run(self, *args, **kwargs):
        self.outf.write(
            "Note: samba-tool user add is deprecated.  "
            "Please use samba-tool user create for the same function.\n")
        return super(cmd_user_add, self).run(*args, **kwargs)


class cmd_user_delete(Command):
    """Delete a user.

This command deletes a user account from the Active Directory domain.  The username specified on the command is the sAMAccountName.

Once the account is deleted, all permissions and memberships associated with that account are deleted.  If a new user account is added with the same name as a previously deleted account name, the new user does not have the previous permissions.  The new account user will be assigned a new security identifier (SID) and permissions and memberships will have to be added.

The command may be run from the root userid or another authorized userid.  The -H or --URL= option can be used to execute the command against a remote server.

Example1:
samba-tool user delete User1 -H ldap://samba.samdom.example.com --username=administrator --password=passw1rd

Example1 shows how to delete a user in the domain against a remote LDAP server.  The -H parameter is used to specify the remote target server.  The --username= and --password= options are used to pass the username and password of a user that exists on the remote server and is authorized to issue the command on that server.

Example2:
sudo samba-tool user delete User2

Example2 shows how to delete a user in the domain against the local server.   sudo is used so a user may run the command as root.

"""
    synopsis = "%prog <username> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
    ]

    takes_args = ["username"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, username, credopts=None, sambaopts=None, versionopts=None,
            H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)
            samdb.deleteuser(username)
        except Exception, e:
            raise CommandError('Failed to remove user "%s"' % username, e)
        self.outf.write("Deleted user %s\n" % username)


class cmd_user_list(Command):
    """List all users."""

    synopsis = "%prog [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, sambaopts=None, credopts=None, versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
            credentials=creds, lp=lp)

        domain_dn = samdb.domain_dn()
        res = samdb.search(domain_dn, scope=ldb.SCOPE_SUBTREE,
                    expression=("(&(objectClass=user)(userAccountControl:%s:=%u))"
                    % (ldb.OID_COMPARATOR_AND, dsdb.UF_NORMAL_ACCOUNT)),
                    attrs=["samaccountname"])
        if (len(res) == 0):
            return

        for msg in res:
            self.outf.write("%s\n" % msg.get("samaccountname", idx=0))


class cmd_user_enable(Command):
    """Enable an user.

This command enables a user account for logon to an Active Directory domain.  The username specified on the command is the sAMAccountName.  The username may also be specified using the --filter option.

There are many reasons why an account may become disabled.  These include:
- If a user exceeds the account policy for logon attempts
- If an administrator disables the account
- If the account expires

The samba-tool user enable command allows an administrator to enable an account which has become disabled.

Additionally, the enable function allows an administrator to have a set of created user accounts defined and setup with default permissions that can be easily enabled for use.

The command may be run from the root userid or another authorized userid.  The -H or --URL= option can be used to execute the command against a remote server.

Example1:
samba-tool user enable Testuser1 --URL=ldap://samba.samdom.example.com --username=administrator --password=passw1rd

Example1 shows how to enable a user in the domain against a remote LDAP server.  The --URL parameter is used to specify the remote target server.  The --username= and --password= options are used to pass the username and password of a user that exists on the remote server and is authorized to update that server.

Example2:
su samba-tool user enable Testuser2

Example2 shows how to enable user Testuser2 for use in the domain on the local server. sudo is used so a user may run the command as root.

Example3:
samba-tool user enable --filter=samaccountname=Testuser3

Example3 shows how to enable a user in the domain against a local LDAP server.  It uses the --filter=samaccountname to specify the username.

"""
    synopsis = "%prog (<username>|--filter <filter>) [options]"


    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--filter", help="LDAP Filter to set password on", type=str),
        ]

    takes_args = ["username?"]

    def run(self, username=None, sambaopts=None, credopts=None,
            versionopts=None, filter=None, H=None):
        if username is None and filter is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (ldb.binary_encode(username))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
            credentials=creds, lp=lp)
        try:
            samdb.enable_account(filter)
        except Exception, msg:
            raise CommandError("Failed to enable user '%s': %s" % (username or filter, msg))
        self.outf.write("Enabled user '%s'\n" % (username or filter))


class cmd_user_disable(Command):
    """Disable an user."""

    synopsis = "%prog (<username>|--filter <filter>) [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--filter", help="LDAP Filter to set password on", type=str),
        ]

    takes_args = ["username?"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, username=None, sambaopts=None, credopts=None,
            versionopts=None, filter=None, H=None):
        if username is None and filter is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (ldb.binary_encode(username))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
            credentials=creds, lp=lp)
        try:
            samdb.disable_account(filter)
        except Exception, msg:
            raise CommandError("Failed to disable user '%s': %s" % (username or filter, msg))


class cmd_user_setexpiry(Command):
    """Set the expiration of a user account.

The user can either be specified by their sAMAccountName or using the --filter option.

When a user account expires, it becomes disabled and the user is unable to logon.  The administrator may issue the samba-tool user enable command to enable the account for logon.  The permissions and memberships associated with the account are retained when the account is enabled.

The command may be run from the root userid or another authorized userid.  The -H or --URL= option can be used to execute the command on a remote server.

Example1:
samba-tool user setexpiry User1 --days=20 --URL=ldap://samba.samdom.example.com --username=administrator --password=passw1rd

Example1 shows how to set the expiration of an account in a remote LDAP server.  The --URL parameter is used to specify the remote target server.  The --username= and --password= options are used to pass the username and password of a user that exists on the remote server and is authorized to update that server.

Example2:
su samba-tool user setexpiry User2

Example2 shows how to set the account expiration of user User2 so it will never expire.  The user in this example resides on the  local server.   sudo is used so a user may run the command as root.

Example3:
samba-tool user setexpiry --days=20 --filter=samaccountname=User3

Example3 shows how to set the account expiration date to end of day 20 days from the current day.  The username or sAMAccountName is specified using the --filter= parameter and the username in this example is User3.

Example4:
samba-tool user setexpiry --noexpiry User4
Example4 shows how to set the account expiration so that it will never expire.  The username and sAMAccountName in this example is User4.

"""
    synopsis = "%prog (<username>|--filter <filter>) [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--filter", help="LDAP Filter to set password on", type=str),
        Option("--days", help="Days to expiry", type=int, default=0),
        Option("--noexpiry", help="Password does never expire", action="store_true", default=False),
    ]

    takes_args = ["username?"]

    def run(self, username=None, sambaopts=None, credopts=None,
            versionopts=None, H=None, filter=None, days=None, noexpiry=None):
        if username is None and filter is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (ldb.binary_encode(username))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
            credentials=creds, lp=lp)

        try:
            samdb.setexpiry(filter, days*24*3600, no_expiry_req=noexpiry)
        except Exception, msg:
            # FIXME: Catch more specific exception
            raise CommandError("Failed to set expiry for user '%s': %s" % (
                username or filter, msg))
        if noexpiry:
            self.outf.write("Expiry for user '%s' disabled.\n" % (
                username or filter))
        else:
            self.outf.write("Expiry for user '%s' set to %u days.\n" % (
                username or filter, days))


class cmd_user_password(Command):
    """Change password for a user account (the one provided in authentication).
"""

    synopsis = "%prog [options]"

    takes_options = [
        Option("--newpassword", help="New password", type=str),
        ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, credopts=None, sambaopts=None, versionopts=None,
                newpassword=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        # get old password now, to get the password prompts in the right order
        old_password = creds.get_password()

        net = Net(creds, lp, server=credopts.ipaddress)

        password = newpassword
        while True:
            if password is not None and password is not '':
                break
            password = getpass("New Password: ")
            passwordverify = getpass("Retype Password: ")
            if not password == passwordverify:
                password = None
                self.outf.write("Sorry, passwords do not match.\n")

        try:
            net.change_password(password)
        except Exception, msg:
            # FIXME: catch more specific exception
            raise CommandError("Failed to change password : %s" % msg)
        self.outf.write("Changed password OK\n")


class cmd_user_setpassword(Command):
    """Set or reset the password of a user account.

This command sets or resets the logon password for a user account.  The username specified on the command is the sAMAccountName.  The username may also be specified using the --filter option.

If the password is not specified on the command through the --newpassword parameter, the user is prompted for the password to be entered through the command line.

It is good security practice for the administrator to use the --must-change-at-next-login option which requires that when the user logs on to the account for the first time following the password change, he/she must change the password.

The command may be run from the root userid or another authorized userid.  The -H or --URL= option can be used to execute the command against a remote server.

Example1:
samba-tool user setpassword TestUser1 --newpassword=passw0rd --URL=ldap://samba.samdom.example.com -Uadministrator%passw1rd

Example1 shows how to set the password of user TestUser1 on a remote LDAP server.  The --URL parameter is used to specify the remote target server.  The -U option is used to pass the username and password of a user that exists on the remote server and is authorized to update the server.

Example2:
sudo samba-tool user setpassword TestUser2 --newpassword=passw0rd --must-change-at-next-login

Example2 shows how an administrator would reset the TestUser2 user's password to passw0rd.  The user is running under the root userid using the sudo command.  In this example the user TestUser2 must change their password the next time they logon to the account.

Example3:
samba-tool user setpassword --filter=samaccountname=TestUser3 --newpassword=passw0rd

Example3 shows how an administrator would reset TestUser3 user's password to passw0rd using the --filter= option to specify the username.

"""
    synopsis = "%prog (<username>|--filter <filter>) [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--filter", help="LDAP Filter to set password on", type=str),
        Option("--newpassword", help="Set password", type=str),
        Option("--must-change-at-next-login",
               help="Force password to be changed on next login",
               action="store_true"),
        Option("--random-password",
                help="Generate random password",
                action="store_true"),
        Option("--smartcard-required",
                help="Require a smartcard for interactive logons",
                action="store_true"),
        Option("--clear-smartcard-required",
                help="Don't require a smartcard for interactive logons",
                action="store_true"),
        ]

    takes_args = ["username?"]

    def run(self, username=None, filter=None, credopts=None, sambaopts=None,
            versionopts=None, H=None, newpassword=None,
            must_change_at_next_login=False, random_password=False,
            smartcard_required=False, clear_smartcard_required=False):
        if filter is None and username is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        password = newpassword

        if smartcard_required:
            if password is not None and password is not '':
                raise CommandError('It is not allowed to specifiy '
                                   '--newpassword '
                                   'together with --smartcard-required.')
            if must_change_at_next_login:
                raise CommandError('It is not allowed to specifiy '
                                   '--must-change-at-next-login '
                                   'together with --smartcard-required.')
            if clear_smartcard_required:
                raise CommandError('It is not allowed to specifiy '
                                   '--clear-smartcard-required '
                                   'together with --smartcard-required.')

        if random_password and not smartcard_required:
            password = generate_random_password(128, 255)

        while True:
            if smartcard_required:
                break
            if password is not None and password is not '':
                break
            password = getpass("New Password: ")
            passwordverify = getpass("Retype Password: ")
            if not password == passwordverify:
                password = None
                self.outf.write("Sorry, passwords do not match.\n")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (ldb.binary_encode(username))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        if smartcard_required:
            command = ""
            try:
                command = "Failed to set UF_SMARTCARD_REQUIRED for user '%s'" % (username or filter)
                flags = dsdb.UF_SMARTCARD_REQUIRED
                samdb.toggle_userAccountFlags(filter, flags, on=True)
                command = "Failed to enable account for user '%s'" % (username or filter)
                samdb.enable_account(filter)
            except Exception, msg:
                # FIXME: catch more specific exception
                raise CommandError("%s: %s" % (command, msg))
            self.outf.write("Added UF_SMARTCARD_REQUIRED OK\n")
        else:
            command = ""
            try:
                if clear_smartcard_required:
                    command = "Failed to remove UF_SMARTCARD_REQUIRED for user '%s'" % (username or filter)
                    flags = dsdb.UF_SMARTCARD_REQUIRED
                    samdb.toggle_userAccountFlags(filter, flags, on=False)
                command = "Failed to set password for user '%s'" % (username or filter)
                samdb.setpassword(filter, password,
                                  force_change_at_next_login=must_change_at_next_login,
                                  username=username)
            except Exception, msg:
                # FIXME: catch more specific exception
                raise CommandError("%s: %s" % (command, msg))
            self.outf.write("Changed password OK\n")

class GetPasswordCommand(Command):

    def __init__(self):
        super(GetPasswordCommand, self).__init__()
        self.lp = None

    def connect_system_samdb(self, url, allow_local=False, verbose=False):

        # using anonymous here, results in no authentication
        # which means we can get system privileges via
        # the privileged ldapi socket
        creds = credentials.Credentials()
        creds.set_anonymous()

        if url is None and allow_local:
            pass
        elif url.lower().startswith("ldapi://"):
            pass
        elif url.lower().startswith("ldap://"):
            raise CommandError("--url ldap:// is not supported for this command")
        elif url.lower().startswith("ldaps://"):
            raise CommandError("--url ldaps:// is not supported for this command")
        elif not allow_local:
            raise CommandError("--url requires an ldapi:// url for this command")

        if verbose:
            self.outf.write("Connecting to '%s'\n" % url)

        samdb = SamDB(url=url, session_info=system_session(),
                      credentials=creds, lp=self.lp)

        try:
            #
            # Make sure we're connected as SYSTEM
            #
            res = samdb.search(base='', scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
            assert len(res) == 1
            sids = res[0].get("tokenGroups")
            assert len(sids) == 1
            sid = ndr_unpack(security.dom_sid, sids[0])
            assert str(sid) == security.SID_NT_SYSTEM
        except Exception as msg:
            raise CommandError("You need to specify an URL that gives privileges as SID_NT_SYSTEM(%s)" %
                               (security.SID_NT_SYSTEM))

        # We use sort here in order to have a predictable processing order
        # this might not be strictly needed, but also doesn't hurt here
        for a in sorted(virtual_attributes.keys()):
            flags = ldb.ATTR_FLAG_HIDDEN | virtual_attributes[a].get("flags", 0)
            samdb.schema_attribute_add(a, flags, ldb.SYNTAX_OCTET_STRING)

        return samdb

    def get_account_attributes(self, samdb, username, basedn, filter, scope,
                               attrs, decrypt):

        require_supplementalCredentials = False
        search_attrs = attrs[:]
        lower_attrs = [x.lower() for x in search_attrs]
        for a in virtual_attributes.keys():
            if a.lower() in lower_attrs:
                require_supplementalCredentials = True
        add_supplementalCredentials = False
        add_unicodePwd = False
        if require_supplementalCredentials:
            a = "supplementalCredentials"
            if a.lower() not in lower_attrs:
                search_attrs += [a]
                add_supplementalCredentials = True
            a = "unicodePwd"
            if a.lower() not in lower_attrs:
                search_attrs += [a]
                add_unicodePwd = True
        add_sAMAcountName = False
        a = "sAMAccountName"
        if a.lower() not in lower_attrs:
            search_attrs += [a]
            add_sAMAcountName = True

        if scope == ldb.SCOPE_BASE:
            search_controls = ["show_deleted:1", "show_recycled:1"]
        else:
            search_controls = []
        try:
            res = samdb.search(base=basedn, expression=filter,
                               scope=scope, attrs=search_attrs,
                               controls=search_controls)
            if len(res) == 0:
                raise Exception('Unable to find user "%s"' % (username or filter))
            if len(res) > 1:
                raise Exception('Matched %u multiple users with filter "%s"' % (len(res), filter))
        except Exception as msg:
            # FIXME: catch more specific exception
            raise CommandError("Failed to get password for user '%s': %s" % (username or filter, msg))
        obj = res[0]

        sc = None
        unicodePwd = None
        if "supplementalCredentials" in obj:
            sc_blob = obj["supplementalCredentials"][0]
            sc = ndr_unpack(drsblobs.supplementalCredentialsBlob, sc_blob)
            if add_supplementalCredentials:
                del obj["supplementalCredentials"]
        if "unicodePwd" in obj:
            unicodePwd = obj["unicodePwd"][0]
            if add_unicodePwd:
                del obj["unicodePwd"]
        account_name = obj["sAMAccountName"][0]
        if add_sAMAcountName:
            del obj["sAMAccountName"]

        calculated = {}
        def get_package(name, min_idx=0):
            if name in calculated:
                return calculated[name]
            if sc is None:
                return None
            if min_idx < 0:
                min_idx = len(sc.sub.packages) + min_idx
            idx = 0
            for p in sc.sub.packages:
                idx += 1
                if idx <= min_idx:
                    continue
                if name != p.name:
                    continue

                return binascii.a2b_hex(p.data)
            return None

        if decrypt:
            #
            # Samba adds 'Primary:SambaGPG' at the end.
            # When Windows sets the password it keeps
            # 'Primary:SambaGPG' and rotates it to
            # the begining. So we can only use the value,
            # if it is the last one.
            #
            # In order to get more protection we verify
            # the nthash of the decrypted utf16 password
            # against the stored nthash in unicodePwd.
            #
            sgv = get_package("Primary:SambaGPG", min_idx=-1)
            if sgv is not None and unicodePwd is not None:
                ctx = gpgme.Context()
                ctx.armor = True
                cipher_io = io.BytesIO(sgv)
                plain_io = io.BytesIO()
                try:
                    ctx.decrypt(cipher_io, plain_io)
                    cv = plain_io.getvalue()
                    #
                    # We only use the password if it matches
                    # the current nthash stored in the unicodePwd
                    # attribute
                    #
                    tmp = credentials.Credentials()
                    tmp.set_anonymous()
                    tmp.set_utf16_password(cv)
                    nthash = tmp.get_nt_hash()
                    if nthash == unicodePwd:
                        calculated["Primary:CLEARTEXT"] = cv
                except gpgme.GpgmeError as (major, minor, msg):
                    if major == gpgme.ERR_BAD_SECKEY:
                        msg = "ERR_BAD_SECKEY: " + msg
                    else:
                        msg = "MAJOR:%d, MINOR:%d: %s" % (major, minor, msg)
                    self.outf.write("WARNING: '%s': SambaGPG can't be decrypted into CLEARTEXT: %s\n" % (
                                    username or account_name, msg))

        def get_utf8(a, b, username):
            try:
                u = unicode(b, 'utf-16-le')
            except UnicodeDecodeError as e:
                self.outf.write("WARNING: '%s': CLEARTEXT is invalid UTF-16-LE unable to generate %s\n" % (
                                username, a))
                return None
            u8 = u.encode('utf-8')
            return u8

        # We use sort here in order to have a predictable processing order
        for a in sorted(virtual_attributes.keys()):
            if not a.lower() in lower_attrs:
                continue

            if a == "virtualClearTextUTF8":
                b = get_package("Primary:CLEARTEXT")
                if b is None:
                    continue
                u8 = get_utf8(a, b, username or account_name)
                if u8 is None:
                    continue
                v = u8
            elif a == "virtualClearTextUTF16":
                v = get_package("Primary:CLEARTEXT")
                if v is None:
                    continue
            elif a == "virtualSSHA":
                b = get_package("Primary:CLEARTEXT")
                if b is None:
                    continue
                u8 = get_utf8(a, b, username or account_name)
                if u8 is None:
                    continue
                salt = get_random_bytes(4)
                h = hashlib.sha1()
                h.update(u8)
                h.update(salt)
                bv = h.digest() + salt
                v = "{SSHA}" + base64.b64encode(bv)
            elif a == "virtualCryptSHA256":
                b = get_package("Primary:CLEARTEXT")
                if b is None:
                    continue
                u8 = get_utf8(a, b, username or account_name)
                if u8 is None:
                    continue
                sv = get_crypt_value("5", u8)
                v = "{CRYPT}" + sv
            elif a == "virtualCryptSHA512":
                b = get_package("Primary:CLEARTEXT")
                if b is None:
                    continue
                u8 = get_utf8(a, b, username or account_name)
                if u8 is None:
                    continue
                sv = get_crypt_value("6", u8)
                v = "{CRYPT}" + sv
            elif a == "virtualSambaGPG":
                # Samba adds 'Primary:SambaGPG' at the end.
                # When Windows sets the password it keeps
                # 'Primary:SambaGPG' and rotates it to
                # the begining. So we can only use the value,
                # if it is the last one.
                v = get_package("Primary:SambaGPG", min_idx=-1)
                if v is None:
                    continue
            else:
                continue
            obj[a] = ldb.MessageElement(v, ldb.FLAG_MOD_REPLACE, a)
        return obj

    def parse_attributes(self, attributes):

        if attributes is None:
            raise CommandError("Please specify --attributes")
        attrs = attributes.split(',')
        password_attrs = []
        for pa in attrs:
            pa = pa.lstrip().rstrip()
            for da in disabled_virtual_attributes.keys():
                if pa.lower() == da.lower():
                    r = disabled_virtual_attributes[da]["reason"]
                    raise CommandError("Virtual attribute '%s' not supported: %s" % (
                                       da, r))
            for va in virtual_attributes.keys():
                if pa.lower() == va.lower():
                    # Take the real name
                    pa = va
                    break
            password_attrs += [pa]

        return password_attrs

class cmd_user_getpassword(GetPasswordCommand):
    """Get the password fields of a user/computer account.

This command gets the logon password for a user/computer account.

The username specified on the command is the sAMAccountName.
The username may also be specified using the --filter option.

The command must be run from the root user id or another authorized user id.
The '-H' or '--URL' option only supports ldapi:// or [tdb://] and can be
used to adjust the local path. By default tdb:// is used by default.

The '--attributes' parameter takes a comma separated list of attributes,
which will be printed or given to the script specified by '--script'. If a
specified attribute is not available on an object it's silently omitted.
All attributes defined in the schema (e.g. the unicodePwd attribute holds
the NTHASH) and the following virtual attributes are possible (see --help
for which virtual attributes are supported in your environment):

   virtualClearTextUTF16: The raw cleartext as stored in the
                          'Primary:CLEARTEXT' (or 'Primary:SambaGPG'
                          with '--decrypt-samba-gpg') buffer inside of the
                          supplementalCredentials attribute. This typically
                          contains valid UTF-16-LE, but may contain random
                          bytes, e.g. for computer accounts.

   virtualClearTextUTF8:  As virtualClearTextUTF16, but converted to UTF-8
                          (only from valid UTF-16-LE)

   virtualSSHA:           As virtualClearTextUTF8, but a salted SHA-1
                          checksum, useful for OpenLDAP's '{SSHA}' algorithm.

   virtualCryptSHA256:    As virtualClearTextUTF8, but a salted SHA256
                          checksum, useful for OpenLDAP's '{CRYPT}' algorithm,
                          with a $5$... salt, see crypt(3) on modern systems.

   virtualCryptSHA512:    As virtualClearTextUTF8, but a salted SHA512
                          checksum, useful for OpenLDAP's '{CRYPT}' algorithm,
                          with a $6$... salt, see crypt(3) on modern systems.

   virtualSambaGPG:       The raw cleartext as stored in the
                          'Primary:SambaGPG' buffer inside of the
                          supplementalCredentials attribute.
                          See the 'password hash gpg key ids' option in
                          smb.conf.

The '--decrypt-samba-gpg' option triggers decryption of the
Primary:SambaGPG buffer. Check with '--help' if this feature is available
in your environment or not (the python-gpgme package is required).  Please
note that you might need to set the GNUPGHOME environment variable.  If the
decryption key has a passphrase you have to make sure that the GPG_AGENT_INFO
environment variable has been set correctly and the passphrase is already
known by the gpg-agent.

Example1:
samba-tool user getpassword TestUser1 --attributes=pwdLastSet,virtualClearTextUTF8

Example2:
samba-tool user getpassword --filter=samaccountname=TestUser3 --attributes=msDS-KeyVersionNumber,unicodePwd,virtualClearTextUTF16

"""
    def __init__(self):
        super(cmd_user_getpassword, self).__init__()

    synopsis = "%prog (<username>|--filter <filter>) [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for sam.ldb database or local ldapi server", type=str,
               metavar="URL", dest="H"),
        Option("--filter", help="LDAP Filter to set password on", type=str),
        Option("--attributes", type=str,
               help=virtual_attributes_help,
               metavar="ATTRIBUTELIST", dest="attributes"),
        Option("--decrypt-samba-gpg",
               help=decrypt_samba_gpg_help,
               action="store_true", default=False, dest="decrypt_samba_gpg"),
        ]

    takes_args = ["username?"]

    def run(self, username=None, H=None, filter=None,
            attributes=None, decrypt_samba_gpg=None,
            sambaopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()

        if decrypt_samba_gpg and not gpgme_support:
            raise CommandError(decrypt_samba_gpg_help)

        if filter is None and username is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (ldb.binary_encode(username))

        if attributes is None:
            raise CommandError("Please specify --attributes")

        password_attrs = self.parse_attributes(attributes)

        samdb = self.connect_system_samdb(url=H, allow_local=True)

        obj = self.get_account_attributes(samdb, username,
                                          basedn=None,
                                          filter=filter,
                                          scope=ldb.SCOPE_SUBTREE,
                                          attrs=password_attrs,
                                          decrypt=decrypt_samba_gpg)

        ldif = samdb.write_ldif(obj, ldb.CHANGETYPE_NONE)
        self.outf.write("%s" % ldif)
        self.outf.write("Got password OK\n")

class cmd_user_syncpasswords(GetPasswordCommand):
    """Sync the password of user accounts.

This syncs logon passwords for user accounts.

Note that this command should run on a single domain controller only
(typically the PDC-emulator). However the "password hash gpg key ids"
option should to be configured on all domain controllers.

The command must be run from the root user id or another authorized user id.
The '-H' or '--URL' option only supports ldapi:// and can be used to adjust the
local path.  By default, ldapi:// is used with the default path to the
privileged ldapi socket.

This command has three modes: "Cache Initialization", "Sync Loop Run" and
"Sync Loop Terminate".


Cache Initialization
====================

The first time, this command needs to be called with
'--cache-ldb-initialize' in order to initialize its cache.

The cache initialization requires '--attributes' and allows the following
optional options: '--decrypt-samba-gpg', '--script', '--filter' or
'-H/--URL'.

The '--attributes' parameter takes a comma separated list of attributes,
which will be printed or given to the script specified by '--script'. If a
specified attribute is not available on an object it will be silently omitted.
All attributes defined in the schema (e.g. the unicodePwd attribute holds
the NTHASH) and the following virtual attributes are possible (see '--help'
for supported virtual attributes in your environment):

   virtualClearTextUTF16: The raw cleartext as stored in the
                          'Primary:CLEARTEXT' (or 'Primary:SambaGPG'
                          with '--decrypt-samba-gpg') buffer inside of the
                          supplementalCredentials attribute. This typically
                          contains valid UTF-16-LE, but may contain random
                          bytes, e.g. for computer accounts.

   virtualClearTextUTF8:  As virtualClearTextUTF16, but converted to UTF-8
                          (only from valid UTF-16-LE)

   virtualSSHA:           As virtualClearTextUTF8, but a salted SHA-1
                          checksum, useful for OpenLDAP's '{SSHA}' algorithm.

   virtualCryptSHA256:    As virtualClearTextUTF8, but a salted SHA256
                          checksum, useful for OpenLDAP's '{CRYPT}' algorithm,
                          with a $5$... salt, see crypt(3) on modern systems.

   virtualCryptSHA512:    As virtualClearTextUTF8, but a salted SHA512
                          checksum, useful for OpenLDAP's '{CRYPT}' algorithm,
                          with a $6$... salt, see crypt(3) on modern systems.

   virtualSambaGPG:       The raw cleartext as stored in the
                          'Primary:SambaGPG' buffer inside of the
                          supplementalCredentials attribute.
                          See the 'password hash gpg key ids' option in
                          smb.conf.

The '--decrypt-samba-gpg' option triggers decryption of the
Primary:SambaGPG buffer. Check with '--help' if this feature is available
in your environment or not (the python-gpgme package is required).  Please
note that you might need to set the GNUPGHOME environment variable.  If the
decryption key has a passphrase you have to make sure that the GPG_AGENT_INFO
environment variable has been set correctly and the passphrase is already
known by the gpg-agent.

The '--script' option specifies a custom script that is called whenever any
of the dirsyncAttributes (see below) was changed. The script is called
without any arguments. It gets the LDIF for exactly one object on STDIN.
If the script processed the object successfully it has to respond with a
single line starting with 'DONE-EXIT: ' followed by an optional message.

Note that the script might be called without any password change, e.g. if
the account was disabled (an userAccountControl change) or the
sAMAccountName was changed. The objectGUID,isDeleted,isRecycled attributes
are always returned as unique identifier of the account. It might be useful
to also ask for non-password attributes like: objectSid, sAMAccountName,
userPrincipalName, userAccountControl, pwdLastSet and msDS-KeyVersionNumber.
Depending on the object, some attributes may not be present/available,
but you always get the current state (and not a diff).

If no '--script' option is specified, the LDIF will be printed on STDOUT or
into the logfile.

The default filter for the LDAP_SERVER_DIRSYNC_OID search is:
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=512)\\
    (!(sAMAccountName=krbtgt*)))
This means only normal (non-krbtgt) user
accounts are monitored.  The '--filter' can modify that, e.g. if it's
required to also sync computer accounts.


Sync Loop Run
=============

This (default) mode runs in an endless loop waiting for password related
changes in the active directory database. It makes use of the
LDAP_SERVER_DIRSYNC_OID and LDAP_SERVER_NOTIFICATION_OID controls in order
get changes in a reliable fashion. Objects are monitored for changes of the
following dirsyncAttributes:

  unicodePwd, dBCSPwd, supplementalCredentials, pwdLastSet, sAMAccountName,
  userPrincipalName and userAccountControl.

It recovers from LDAP disconnects and updates the cache in conservative way
(in single steps after each succesfully processed change).  An error from
the script (specified by '--script') will result in fatal error and this
command will exit.  But the cache state should be still valid and can be
resumed in the next "Sync Loop Run".

The '--logfile' option specifies an optional (required if '--daemon' is
specified) logfile that takes all output of the command. The logfile is
automatically reopened if fstat returns st_nlink == 0.

The optional '--daemon' option will put the command into the background.

You can stop the command without the '--daemon' option, also by hitting
strg+c.

If you specify the '--no-wait' option the command skips the
LDAP_SERVER_NOTIFICATION_OID 'waiting' step and exit once
all LDAP_SERVER_DIRSYNC_OID changes are consumed.

Sync Loop Terminate
===================

In order to terminate an already running command (likely as daemon) the
'--terminate' option can be used. This also requires the '--logfile' option
to be specified.


Example1:
samba-tool user syncpasswords --cache-ldb-initialize \\
    --attributes=virtualClearTextUTF8
samba-tool user syncpasswords

Example2:
samba-tool user syncpasswords --cache-ldb-initialize \\
    --attributes=objectGUID,objectSID,sAMAccountName,\\
    userPrincipalName,userAccountControl,pwdLastSet,\\
    msDS-KeyVersionNumber,virtualCryptSHA512 \\
    --script=/path/to/my-custom-syncpasswords-script.py
samba-tool user syncpasswords --daemon \\
    --logfile=/var/log/samba/user-syncpasswords.log
samba-tool user syncpasswords --terminate \\
    --logfile=/var/log/samba/user-syncpasswords.log

"""
    def __init__(self):
        super(cmd_user_syncpasswords, self).__init__()

    synopsis = "%prog [--cache-ldb-initialize] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("--cache-ldb-initialize",
               help="Initialize the cache for the first time",
               dest="cache_ldb_initialize", action="store_true"),
        Option("--cache-ldb", help="optional LDB URL user-syncpasswords-cache.ldb", type=str,
               metavar="CACHE-LDB-PATH", dest="cache_ldb"),
        Option("-H", "--URL", help="optional LDB URL for a local ldapi server", type=str,
               metavar="URL", dest="H"),
        Option("--filter", help="optional LDAP filter to set password on", type=str,
               metavar="LDAP-SEARCH-FILTER", dest="filter"),
        Option("--attributes", type=str,
               help=virtual_attributes_help,
               metavar="ATTRIBUTELIST", dest="attributes"),
        Option("--decrypt-samba-gpg",
               help=decrypt_samba_gpg_help,
               action="store_true", default=False, dest="decrypt_samba_gpg"),
        Option("--script", help="Script that is called for each password change", type=str,
               metavar="/path/to/syncpasswords.script", dest="script"),
        Option("--no-wait", help="Don't block waiting for changes",
               action="store_true", default=False, dest="nowait"),
        Option("--logfile", type=str,
               help="The logfile to use (required in --daemon mode).",
               metavar="/path/to/syncpasswords.log", dest="logfile"),
        Option("--daemon", help="daemonize after initial setup",
               action="store_true", default=False, dest="daemon"),
        Option("--terminate",
               help="Send a SIGTERM to an already running (daemon) process",
               action="store_true", default=False, dest="terminate"),
        ]

    def run(self, cache_ldb_initialize=False, cache_ldb=None,
            H=None, filter=None,
            attributes=None, decrypt_samba_gpg=None,
            script=None, nowait=None, logfile=None, daemon=None, terminate=None,
            sambaopts=None, versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.logfile = None
        self.samdb_url = None
        self.samdb = None
        self.cache = None

        if not cache_ldb_initialize:
            if attributes is not None:
                raise CommandError("--attributes is only allowed together with --cache-ldb-initialize")
            if decrypt_samba_gpg:
                raise CommandError("--decrypt-samba-gpg is only allowed together with --cache-ldb-initialize")
            if script is not None:
                raise CommandError("--script is only allowed together with --cache-ldb-initialize")
            if filter is not None:
                raise CommandError("--filter is only allowed together with --cache-ldb-initialize")
            if H is not None:
                raise CommandError("-H/--URL is only allowed together with --cache-ldb-initialize")
        else:
            if nowait is not False:
                raise CommandError("--no-wait is not allowed together with --cache-ldb-initialize")
            if logfile is not None:
                raise CommandError("--logfile is not allowed together with --cache-ldb-initialize")
            if daemon is not False:
                raise CommandError("--daemon is not allowed together with --cache-ldb-initialize")
            if terminate is not False:
                raise CommandError("--terminate is not allowed together with --cache-ldb-initialize")

        if nowait is True:
            if daemon is True:
                raise CommandError("--daemon is not allowed together with --no-wait")
            if terminate is not False:
                raise CommandError("--terminate is not allowed together with --no-wait")

        if terminate is True and daemon is True:
            raise CommandError("--terminate is not allowed together with --daemon")

        if daemon is True and logfile is None:
            raise CommandError("--daemon is only allowed together with --logfile")

        if terminate is True and logfile is None:
            raise CommandError("--terminate is only allowed together with --logfile")

        if script is not None:
            if not os.path.exists(script):
                raise CommandError("script[%s] does not exist!" % script)

            sync_command = "%s" % os.path.abspath(script)
        else:
            sync_command = None

        dirsync_filter = filter
        if dirsync_filter is None:
            dirsync_filter = "(&" + \
                               "(objectClass=user)" + \
                               "(userAccountControl:%s:=%u)" % (
                                ldb.OID_COMPARATOR_AND, dsdb.UF_NORMAL_ACCOUNT) + \
                               "(!(sAMAccountName=krbtgt*))" + \
                             ")"

        dirsync_secret_attrs = [
            "unicodePwd",
            "dBCSPwd",
            "supplementalCredentials",
        ]

        dirsync_attrs = dirsync_secret_attrs + [
            "pwdLastSet",
            "sAMAccountName",
            "userPrincipalName",
            "userAccountControl",
            "isDeleted",
            "isRecycled",
        ]

        password_attrs = None

        if cache_ldb_initialize:
            if H is None:
                H = "ldapi://%s" % os.path.abspath(self.lp.private_path("ldap_priv/ldapi"))

            if decrypt_samba_gpg and not gpgme_support:
                raise CommandError(decrypt_samba_gpg_help)

            password_attrs = self.parse_attributes(attributes)
            lower_attrs = [x.lower() for x in password_attrs]
            # We always return these in order to track deletions
            for a in ["objectGUID", "isDeleted", "isRecycled"]:
                if a.lower() not in lower_attrs:
                    password_attrs += [a]

        if cache_ldb is not None:
            if cache_ldb.lower().startswith("ldapi://"):
                raise CommandError("--cache_ldb ldapi:// is not supported")
            elif cache_ldb.lower().startswith("ldap://"):
                raise CommandError("--cache_ldb ldap:// is not supported")
            elif cache_ldb.lower().startswith("ldaps://"):
                raise CommandError("--cache_ldb ldaps:// is not supported")
            elif cache_ldb.lower().startswith("tdb://"):
                pass
            else:
                if not os.path.exists(cache_ldb):
                    cache_ldb = self.lp.private_path(cache_ldb)
        else:
            cache_ldb = self.lp.private_path("user-syncpasswords-cache.ldb")

        self.lockfile = "%s.pid" % cache_ldb

        def log_msg(msg):
            if self.logfile is not None:
                info = os.fstat(0)
                if info.st_nlink == 0:
                    logfile = self.logfile
                    self.logfile = None
                    log_msg("Closing logfile[%s] (st_nlink == 0)\n" % (logfile))
                    logfd = os.open(logfile, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0600)
                    os.dup2(logfd, 0)
                    os.dup2(logfd, 1)
                    os.dup2(logfd, 2)
                    os.close(logfd)
                    log_msg("Reopened logfile[%s]\n" % (logfile))
                    self.logfile = logfile
            msg = "%s: pid[%d]: %s" % (
                    time.ctime(),
                    os.getpid(),
                    msg)
            self.outf.write(msg)
            return

        def load_cache():
            cache_attrs = [
                "samdbUrl",
                "dirsyncFilter",
                "dirsyncAttribute",
                "dirsyncControl",
                "passwordAttribute",
                "decryptSambaGPG",
                "syncCommand",
                "currentPid",
            ]

            self.cache = Ldb(cache_ldb)
            self.cache_dn = ldb.Dn(self.cache, "KEY=USERSYNCPASSWORDS")
            res = self.cache.search(base=self.cache_dn, scope=ldb.SCOPE_BASE,
                                    attrs=cache_attrs)
            if len(res) == 1:
                try:
                    self.samdb_url = res[0]["samdbUrl"][0]
                except KeyError as e:
                    self.samdb_url = None
            else:
                self.samdb_url = None
            if self.samdb_url is None and not cache_ldb_initialize:
                raise CommandError("cache_ldb[%s] not initialized, use --cache-ldb-initialize the first time" % (
                                   cache_ldb))
            if self.samdb_url is not None and cache_ldb_initialize:
                raise CommandError("cache_ldb[%s] already initialized, --cache-ldb-initialize not allowed" % (
                                   cache_ldb))
            if self.samdb_url is None:
                self.samdb_url = H
                self.dirsync_filter = dirsync_filter
                self.dirsync_attrs = dirsync_attrs
                self.dirsync_controls = ["dirsync:1:0:0","extended_dn:1:0"];
                self.password_attrs = password_attrs
                self.decrypt_samba_gpg = decrypt_samba_gpg
                self.sync_command = sync_command
                add_ldif  = "dn: %s\n" % self.cache_dn
                add_ldif += "objectClass: userSyncPasswords\n"
                add_ldif += "samdbUrl:: %s\n" % base64.b64encode(self.samdb_url)
                add_ldif += "dirsyncFilter:: %s\n" % base64.b64encode(self.dirsync_filter)
                for a in self.dirsync_attrs:
                    add_ldif += "dirsyncAttribute:: %s\n" % base64.b64encode(a)
                add_ldif += "dirsyncControl: %s\n" % self.dirsync_controls[0]
                for a in self.password_attrs:
                    add_ldif += "passwordAttribute:: %s\n" % base64.b64encode(a)
                if self.decrypt_samba_gpg == True:
                    add_ldif += "decryptSambaGPG: TRUE\n"
                else:
                    add_ldif += "decryptSambaGPG: FALSE\n"
                if self.sync_command is not None:
                    add_ldif += "syncCommand: %s\n" % self.sync_command
                add_ldif += "currentTime: %s\n" % ldb.timestring(int(time.time()))
                self.cache.add_ldif(add_ldif)
                self.current_pid = None
                self.outf.write("Initialized cache_ldb[%s]\n" % (cache_ldb))
                msgs = self.cache.parse_ldif(add_ldif)
                changetype,msg = msgs.next()
                ldif = self.cache.write_ldif(msg, ldb.CHANGETYPE_NONE)
                self.outf.write("%s" % ldif)
            else:
                self.dirsync_filter = res[0]["dirsyncFilter"][0]
                self.dirsync_attrs = []
                for a in res[0]["dirsyncAttribute"]:
                    self.dirsync_attrs.append(a)
                self.dirsync_controls = [res[0]["dirsyncControl"][0], "extended_dn:1:0"]
                self.password_attrs = []
                for a in res[0]["passwordAttribute"]:
                    self.password_attrs.append(a)
                decrypt_string = res[0]["decryptSambaGPG"][0]
                assert(decrypt_string in ["TRUE", "FALSE"])
                if decrypt_string == "TRUE":
                    self.decrypt_samba_gpg = True
                else:
                    self.decrypt_samba_gpg = False
                if "syncCommand" in res[0]:
                    self.sync_command = res[0]["syncCommand"][0]
                else:
                    self.sync_command = None
                if "currentPid" in res[0]:
                    self.current_pid = int(res[0]["currentPid"][0])
                else:
                    self.current_pid = None
                log_msg("Using cache_ldb[%s]\n" % (cache_ldb))

            return

        def run_sync_command(dn, ldif):
            log_msg("Call Popen[%s] for %s\n" % (dn, self.sync_command))
            sync_command_p = Popen(self.sync_command,
                                   stdin=PIPE,
                                   stdout=PIPE,
                                   stderr=STDOUT)

            res = sync_command_p.poll()
            assert res is None

            input = "%s" % (ldif)
            reply = sync_command_p.communicate(input)[0]
            log_msg("%s\n" % (reply))
            res = sync_command_p.poll()
            if res is None:
                sync_command_p.terminate()
            res = sync_command_p.wait()

            if reply.startswith("DONE-EXIT: "):
                return

            log_msg("RESULT: %s\n" % (res))
            raise Exception("ERROR: %s - %s\n" % (res, reply))

        def handle_object(idx, dirsync_obj):
            binary_guid = dirsync_obj.dn.get_extended_component("GUID")
            guid = ndr_unpack(misc.GUID, binary_guid)
            binary_sid = dirsync_obj.dn.get_extended_component("SID")
            sid = ndr_unpack(security.dom_sid, binary_sid)
            domain_sid, rid = sid.split()
            if rid == security.DOMAIN_RID_KRBTGT:
                log_msg("# Dirsync[%d] SKIP: DOMAIN_RID_KRBTGT\n\n" % (idx))
                return
            for a in list(dirsync_obj.keys()):
                for h in dirsync_secret_attrs:
                    if a.lower() == h.lower():
                        del dirsync_obj[a]
                        dirsync_obj["# %s::" % a] = ["REDACTED SECRET ATTRIBUTE"]
            dirsync_ldif = self.samdb.write_ldif(dirsync_obj, ldb.CHANGETYPE_NONE)
            log_msg("# Dirsync[%d] %s %s\n%s" %(idx, guid, sid, dirsync_ldif))
            obj = self.get_account_attributes(self.samdb,
                                              username="%s" % sid,
                                              basedn="<GUID=%s>" % guid,
                                              filter="(objectClass=user)",
                                              scope=ldb.SCOPE_BASE,
                                              attrs=self.password_attrs,
                                              decrypt=self.decrypt_samba_gpg)
            ldif = self.samdb.write_ldif(obj, ldb.CHANGETYPE_NONE)
            log_msg("# Passwords[%d] %s %s\n" % (idx, guid, sid))
            if self.sync_command is None:
                self.outf.write("%s" % (ldif))
                return
            self.outf.write("# attrs=%s\n" % (sorted(obj.keys())))
            run_sync_command(obj.dn, ldif)

        def check_current_pid_conflict(terminate):
            flags = os.O_RDWR
            if not terminate:
                flags |= os.O_CREAT

            try:
                self.lockfd = os.open(self.lockfile, flags, 0600)
            except IOError as (err, msg):
                if err == errno.ENOENT:
                    if terminate:
                        return False
                log_msg("check_current_pid_conflict: failed to open[%s] - %s (%d)" %
                        (self.lockfile, msg, err))
                raise

            got_exclusive = False
            try:
                fcntl.lockf(self.lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                got_exclusive = True
            except IOError as (err, msg):
                if err != errno.EACCES and err != errno.EAGAIN:
                    log_msg("check_current_pid_conflict: failed to get exclusive lock[%s] - %s (%d)" %
                            (self.lockfile, msg, err))
                    raise

            if not got_exclusive:
                buf = os.read(self.lockfd, 64)
                self.current_pid = None
                try:
                    self.current_pid = int(buf)
                except ValueError as e:
                    pass
                if self.current_pid is not None:
                    return True

            if got_exclusive and terminate:
                try:
                    os.ftruncate(self.lockfd, 0)
                except IOError as (err, msg):
                    log_msg("check_current_pid_conflict: failed to truncate [%s] - %s (%d)" %
                            (self.lockfile, msg, err))
                    raise
                os.close(self.lockfd)
                self.lockfd = -1
                return False

            try:
                fcntl.lockf(self.lockfd, fcntl.LOCK_SH)
            except IOError as (err, msg):
                log_msg("check_current_pid_conflict: failed to get shared lock[%s] - %s (%d)" %
                        (self.lockfile, msg, err))

            # We leave the function with the shared lock.
            return False

        def update_pid(pid):
            if self.lockfd != -1:
                got_exclusive = False
                # Try 5 times to get the exclusiv lock.
                for i in xrange(0, 5):
                    try:
                        fcntl.lockf(self.lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        got_exclusive = True
                    except IOError as (err, msg):
                        if err != errno.EACCES and err != errno.EAGAIN:
                            log_msg("update_pid(%r): failed to get exclusive lock[%s] - %s (%d)" %
                                    (pid, self.lockfile, msg, err))
                            raise
                    if got_exclusive:
                        break
                    time.sleep(1)
                if not got_exclusive:
                    log_msg("update_pid(%r): failed to get exclusive lock[%s] - %s" %
                            (pid, self.lockfile))
                    raise CommandError("update_pid(%r): failed to get exclusive lock[%s] after 5 seconds" %
                                       (pid, self.lockfile))

                if pid is not None:
                    buf = "%d\n" % pid
                else:
                    buf = None
                try:
                    os.ftruncate(self.lockfd, 0)
                    if buf is not None:
                        os.write(self.lockfd, buf)
                except IOError as (err, msg):
                    log_msg("check_current_pid_conflict: failed to write pid to [%s] - %s (%d)" %
                            (self.lockfile, msg, err))
                    raise
            self.current_pid = pid
            if self.current_pid is not None:
                log_msg("currentPid: %d\n" % self.current_pid)

            modify_ldif =  "dn: %s\n" % (self.cache_dn)
            modify_ldif += "changetype: modify\n"
            modify_ldif += "replace: currentPid\n"
            if self.current_pid is not None:
                modify_ldif += "currentPid: %d\n" % (self.current_pid)
            modify_ldif += "replace: currentTime\n"
            modify_ldif += "currentTime: %s\n" % ldb.timestring(int(time.time()))
            self.cache.modify_ldif(modify_ldif)
            return

        def update_cache(res_controls):
            assert len(res_controls) > 0
            assert res_controls[0].oid == "1.2.840.113556.1.4.841"
            res_controls[0].critical = True
            self.dirsync_controls = [str(res_controls[0]),"extended_dn:1:0"]
            log_msg("dirsyncControls: %r\n" % self.dirsync_controls)

            modify_ldif =  "dn: %s\n" % (self.cache_dn)
            modify_ldif += "changetype: modify\n"
            modify_ldif += "replace: dirsyncControl\n"
            modify_ldif += "dirsyncControl: %s\n" % (self.dirsync_controls[0])
            modify_ldif += "replace: currentTime\n"
            modify_ldif += "currentTime: %s\n" % ldb.timestring(int(time.time()))
            self.cache.modify_ldif(modify_ldif)
            return

        def check_object(dirsync_obj, res_controls):
            assert len(res_controls) > 0
            assert res_controls[0].oid == "1.2.840.113556.1.4.841"

            binary_sid = dirsync_obj.dn.get_extended_component("SID")
            sid = ndr_unpack(security.dom_sid, binary_sid)
            dn = "KEY=%s" % sid
            lastCookie = str(res_controls[0])

            res = self.cache.search(base=dn, scope=ldb.SCOPE_BASE,
                                    expression="(lastCookie=%s)" % (
                                        ldb.binary_encode(lastCookie)),
                                    attrs=[])
            if len(res) == 1:
                return True
            return False

        def update_object(dirsync_obj, res_controls):
            assert len(res_controls) > 0
            assert res_controls[0].oid == "1.2.840.113556.1.4.841"

            binary_sid = dirsync_obj.dn.get_extended_component("SID")
            sid = ndr_unpack(security.dom_sid, binary_sid)
            dn = "KEY=%s" % sid
            lastCookie = str(res_controls[0])

            self.cache.transaction_start()
            try:
                res = self.cache.search(base=dn, scope=ldb.SCOPE_BASE,
                                        expression="(objectClass=*)",
                                        attrs=["lastCookie"])
                if len(res) == 0:
                    add_ldif  = "dn: %s\n" % (dn)
                    add_ldif += "objectClass: userCookie\n"
                    add_ldif += "lastCookie: %s\n" % (lastCookie)
                    add_ldif += "currentTime: %s\n" % ldb.timestring(int(time.time()))
                    self.cache.add_ldif(add_ldif)
                else:
                    modify_ldif =  "dn: %s\n" % (dn)
                    modify_ldif += "changetype: modify\n"
                    modify_ldif += "replace: lastCookie\n"
                    modify_ldif += "lastCookie: %s\n" % (lastCookie)
                    modify_ldif += "replace: currentTime\n"
                    modify_ldif += "currentTime: %s\n" % ldb.timestring(int(time.time()))
                    self.cache.modify_ldif(modify_ldif)
                self.cache.transaction_commit()
            except Exception as e:
                self.cache.transaction_cancel()

            return

        def dirsync_loop():
            while True:
                res = self.samdb.search(expression=self.dirsync_filter,
                                        scope=ldb.SCOPE_SUBTREE,
                                        attrs=self.dirsync_attrs,
                                        controls=self.dirsync_controls)
                log_msg("dirsync_loop(): results %d\n" % len(res))
                ri = 0
                for r in res:
                    done = check_object(r, res.controls)
                    if not done:
                        handle_object(ri, r)
                        update_object(r, res.controls)
                    ri += 1
                update_cache(res.controls)
                if len(res) == 0:
                    break

        def sync_loop(wait):
            notify_attrs = ["name", "uSNCreated", "uSNChanged", "objectClass"]
            notify_controls = ["notification:1"]
            notify_handle = self.samdb.search_iterator(expression="objectClass=*",
                                                       scope=ldb.SCOPE_SUBTREE,
                                                       attrs=notify_attrs,
                                                       controls=notify_controls,
                                                       timeout=-1)

            if wait is True:
                log_msg("Resuming monitoring\n")
            else:
                log_msg("Getting changes\n")
            self.outf.write("dirsyncFilter: %s\n" % self.dirsync_filter)
            self.outf.write("dirsyncControls: %r\n" % self.dirsync_controls)
            self.outf.write("syncCommand: %s\n" % self.sync_command)
            dirsync_loop()

            if wait is not True:
                return

            for msg in notify_handle:
                if not isinstance(msg, ldb.Message):
                    self.outf.write("referal: %s\n" % msg)
                    continue
                created = msg.get("uSNCreated")[0]
                changed = msg.get("uSNChanged")[0]
                log_msg("# Notify %s uSNCreated[%s] uSNChanged[%s]\n" %
                        (msg.dn, created, changed))

                dirsync_loop()

            res = notify_handle.result()

        def daemonize():
            self.samdb = None
            self.cache = None
            orig_pid = os.getpid()
            pid = os.fork()
            if pid == 0:
                os.setsid()
                pid = os.fork()
                if pid == 0: # Actual daemon
                    pid = os.getpid()
                    log_msg("Daemonized as pid %d (from %d)\n" % (pid, orig_pid))
                    load_cache()
                    return
            os._exit(0)

        if cache_ldb_initialize:
            self.samdb_url = H
            self.samdb = self.connect_system_samdb(url=self.samdb_url,
                                                   verbose=True)
            load_cache()
            return

        if logfile is not None:
            import resource      # Resource usage information.
            maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
            if maxfd == resource.RLIM_INFINITY:
                maxfd = 1024 # Rough guess at maximum number of open file descriptors.
            logfd = os.open(logfile, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0600)
            self.outf.write("Using logfile[%s]\n" % logfile)
            for fd in range(0, maxfd):
                if fd == logfd:
                    continue
                try:
                    os.close(fd)
                except OSError:
                    pass
            os.dup2(logfd, 0)
            os.dup2(logfd, 1)
            os.dup2(logfd, 2)
            os.close(logfd)
            log_msg("Attached to logfile[%s]\n" % (logfile))
            self.logfile = logfile

        load_cache()
        conflict = check_current_pid_conflict(terminate)
        if terminate:
            if self.current_pid is None:
                log_msg("No process running.\n")
                return
            if not conflict:
                log_msg("Proccess %d is not running anymore.\n" % (
                        self.current_pid))
                update_pid(None)
                return
            log_msg("Sending SIGTERM to proccess %d.\n" % (
                    self.current_pid))
            os.kill(self.current_pid, signal.SIGTERM)
            return
        if conflict:
            raise CommandError("Exiting pid %d, command is already running as pid %d" % (
                               os.getpid(), self.current_pid))

        if daemon is True:
            daemonize()
        update_pid(os.getpid())

        wait = True
        while wait is True:
            retry_sleep_min = 1
            retry_sleep_max = 600
            if nowait is True:
                wait = False
                retry_sleep = 0
            else:
                retry_sleep = retry_sleep_min

            while self.samdb is None:
                if retry_sleep != 0:
                    log_msg("Wait before connect - sleep(%d)\n" % retry_sleep)
                    time.sleep(retry_sleep)
                retry_sleep = retry_sleep * 2
                if retry_sleep >= retry_sleep_max:
                    retry_sleep = retry_sleep_max
                log_msg("Connecting to '%s'\n" % self.samdb_url)
                try:
                    self.samdb = self.connect_system_samdb(url=self.samdb_url)
                except Exception as msg:
                    self.samdb = None
                    log_msg("Connect to samdb Exception => (%s)\n" % msg)
                    if wait is not True:
                        raise

            try:
                sync_loop(wait)
            except ldb.LdbError as (enum, estr):
                self.samdb = None
                log_msg("ldb.LdbError(%d) => (%s)\n" % (enum, estr))

        update_pid(None)
        return

class cmd_user(SuperCommand):
    """User management."""

    subcommands = {}
    subcommands["add"] = cmd_user_add()
    subcommands["create"] = cmd_user_create()
    subcommands["delete"] = cmd_user_delete()
    subcommands["disable"] = cmd_user_disable()
    subcommands["enable"] = cmd_user_enable()
    subcommands["list"] = cmd_user_list()
    subcommands["setexpiry"] = cmd_user_setexpiry()
    subcommands["password"] = cmd_user_password()
    subcommands["setpassword"] = cmd_user_setpassword()
    subcommands["getpassword"] = cmd_user_getpassword()
    subcommands["syncpasswords"] = cmd_user_syncpasswords()
