# Authors: Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2015  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
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

import krbV
import sys

from ipalib import api
from ipalib import errors
from ipapython import admintool
from ipapython.dn import DN
from ipapython.ipautil import realm_to_suffix
from ipapython.ipa_log_manager import log_mgr
from ipaserver.plugins.ldap2 import ldap2
from ipaserver.install import replication

DEFAULT_TRUST_VIEW_NAME = u'Default Trust View'


class MigrateWinsync(admintool.AdminTool):
    """
    Tool to migrate winsync users.
    """

    command_name = 'ipa-migrate-winsync'
    usage = "ipa-migrate-winsync"
    description = (
        "This tool creates user ID overrides for all the users "
        "that were previously synced from AD domain using the "
        "winsync replication agreement. It requires that trust "
        "with the AD forest has already been established and "
        "the users in question are resolvable using SSSD. "
        "For more information, see `man ipa-migrate-winsync`."
        )

    @classmethod
    def add_options(cls, parser):
        """
        Adds command line options to the tool.
        """
        super(MigrateWinsync, cls).add_options(parser)

        parser.add_option(
            "--realm",
            dest="realm",
            help="The AD realm the winsynced users belong to")
        parser.add_option(
            "--server",
            dest="server",
            help="The AD DC the winsync agreement is established with")
        parser.add_option(
            "-U", "--unattended",
            dest="interactive",
            action="store_false",
            default=True,
            help="Never prompt for user input")

    def validate_options(self):
        """
        Validates the options passed by the user:
            - Checks that trust has been established with
              the realm passed via --realm option
        """

        # Require root to have access to HTTP keytab
        super(MigrateWinsync, self).validate_options(needs_root=True)

        if self.options.realm is None:
            raise admintool.ScriptError(
                "AD realm the winsynced users belong to needs to be "
                "specified.")
        else:
            try:
                api.Command['trust_show'](unicode(self.options.realm))
            except errors.NotFound:
                raise admintool.ScriptError(
                    "Trust with the given realm %s could not be found. "
                    "Please establish the trust prior to migration."
                    % self.options.realm)
            except Exception as e:
                raise admintool.ScriptError(
                    "An error occured during detection of the established "
                    "trust with %s: %s" % (self.options.realm, str(e)))

        if self.options.server is None:
            raise admintool.ScriptError(
                "The AD DC the winsync agreement is established with "
                "needs to be specified.")
        else:
            # Validate the replication agreement between given host and localhost
            try:
                manager = replication.ReplicationManager(
                    api.env.realm,
                    api.env.host,
                    None)  # Use GSSAPI instead of raw directory manager access

                replica_type = manager.get_agreement_type(self.options.server)
            except errors.ACIError as e:
                raise admintool.ScriptError(
                    "Used Kerberos account does not have privileges to access "
                    "the replication agreement info: %s" % str(e))
            except errors.NotFound as e:
                raise admintool.ScriptError(
                    "The replication agreement between %s and %s could not "
                    "be detected" % (api.env.host, self.options.server))

            # Check that the replication agreement is indeed WINSYNC
            if replica_type != replication.WINSYNC:
                raise admintool.ScriptError(
                    "Replication agreement between %s and %s is not winsync."
                    % (api.env.host, self.options.server))

            # Save the reference to the replication manager in the object
            self.manager = manager

    def delete_winsync_agreement(self):
        """
        Deletes the winsync agreement between the current master and the
        given AD server.
        """

        try:
            self.manager.delete_agreement(self.options.server)
            self.manager.delete_referral(self.options.server)

            dn = DN(('cn', self.options.server),
                    ('cn', 'replicas'),
                    ('cn', 'ipa'),
                    ('cn', 'etc'),
                    realm_to_suffix(api.env.realm))
            entries = self.manager.conn.get_entries(dn,
                                                    self.ldap.SCOPE_SUBTREE)
            if entries:
                entries.sort(key=len, reverse=True)
                for entry in entries:
                    self.ldap.delete_entry(entry)

        except Exception as e:
            raise admintool.ScriptError(
                "Deletion of the winsync agreement failed: %s" % str(e))


    def create_id_user_override(self, entry):
        """
        Creates ID override corresponding to this user entry.
        """

        user_identifier = u"%s@%s" % (entry['uid'][0], self.options.realm)

        kwargs = {
            'uid': entry['uid'][0],
            'uidnumber': entry['uidnumber'][0],
            'gidnumber': entry['gidnumber'][0],
            'gecos': entry['gecos'][0],
            'loginshell': entry['loginshell'][0]
        }

        try:
            result = api.Command['idoverrideuser_add'](
                DEFAULT_TRUST_VIEW_NAME,
                user_identifier,
                **kwargs
            )
        except Exception as e:
            self.log.warning("Migration failed: %s (%s)"
                             % (user_identifier, str(e)))
        else:
            self.log.debug("Migrated: %s" % user_identifier)

    def find_winsync_users(self):
        """
        Finds all users that were mirrored from AD using winsync.
        """

        user_filter = "(&(objectclass=ntuser)(ntUserDomainId=*))"
        user_base = DN(api.env.container_user, api.env.basedn)
        entries, _ = self.ldap.find_entries(
            filter=user_filter,
            base_dn=user_base,
            paged_search=True)

        for entry in entries:
            self.log.debug("Discovered entry: %s" % entry)

        return entries

    @classmethod
    def main(cls, argv):
        """
        Sets up API and LDAP connection for the tool, then runs the rest of
        the plumbing.
        """

        # Finalize API
        api.bootstrap(in_server=True, context='server')
        api.finalize()

        # Setup LDAP connection
        try:
            ctx = krbV.default_context()
            ccache = ctx.default_ccache()
            api.Backend.ldap2.connect(ccache)
            cls.ldap = api.Backend.ldap2
        except krbV.Krb5Error, e:
            sys.exit("Must have Kerberos credentials to migrate Winsync users.")
        except errors.ACIError, e:
            sys.exit("Outdated Kerberos credentials. Use kdestroy and kinit to update your ticket.")
        except errors.DatabaseError, e:
            sys.exit("Cannot connect to the LDAP database. Please check if IPA is running.")

        super(MigrateWinsync, cls).main(argv)

    def run(self):
        super(MigrateWinsync, self).run()

        # Stop winsync agreement with the given host
        self.delete_winsync_agreement()

        # Create ID overrides replacing the user winsync entries
        entries = self.find_winsync_users()
        for entry in entries:
            self.create_id_user_override(entry)
            self.ldap.delete_entry(entry)
