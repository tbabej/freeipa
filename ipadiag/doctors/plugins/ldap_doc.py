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

import tempfile

from ipalib import api
from ipaplatform.paths import paths
from ipadiag.pluggable import Doctor, register
from ipadiag.errors import DiagException


@register()
class check_max_agreements(Doctor):
    """
    Checks that host does not have more than recommended
    number of replication agreements.
    """

    group = 'LDAP'
    cli_name = 'Number of replication agreements'
    requires_root = True
    server_only = True

    def is_applicable(self, reports):
        # This doctor should not be applicable if the number of agreements
        # could not be determined

        agreements_count = reports.get('replication_agreements_count')
        return agreements_count is not None and agreements_count.status is True

    def check(self, reports):
        # Get the number of agreemets from reports
        agreements = int(reports['replication_agreements_count'].value)

        # More than 4 agreements per host are not recommended
        if agreements > 4:
            raise DiagException(
                message="{0} agreements, at most 4 recommended."
                        .format(agreements))


@register()
class check_masters_readability(Doctor):
    """
    Tries to access LDAP service on each host
    it has replication agreement with using
    the DS keytab.
    """

    group = 'LDAP'
    cli_name = 'Check replica readability'
    requires_root = True
    server_only = True

    def check_host_ldap_readability(self, host):
        """
        Checks if LDAP server is readable with current
        credentials by performing a dummy search.
        """

        result = self.run(
            ['ldapsearch',
             '-Y', 'GSSAPI',
             '-h', host,
             '-b', '',
             '-s', 'base'],
              env=self.temp_ccache_env,
              raiseonerr=False)

        return result

    def check(self, reports):
        # Generated a named temporary file, which is deleted
        # when the object is destroyed
        ccache = tempfile.NamedTemporaryFile()
        self.temp_ccache_env = {'KRB5CCNAME': ccache.name}

        # Obtain a ticket using a DS keytab
        # The root permissions are necessary for access
        # to this file
        result = self.run(['kinit',
                           '-kt', '/etc/dirsrv/ds.keytab',
                           'ldap/%s' % api.env.host],
                           env=self.temp_ccache_env,
                           raiseonerr=False)
        if result.returncode != 0:
            raise DiagException("Unable to kinit using DS keytab.", key="kinit-unable")


        # Run sanity-check search against own LDAP server
        result = self.check_host_ldap_readability(api.env.host)
        if result.returncode != 0:
            raise DiagException("master unreachable", key="master-unreachable")

        # Verify we can read any replica
        replicas_raw = reports.get('replication_agreements_list', []).value.split(',')
        replicas = [
            replica.strip()
            for replica in replicas_raw
        ]

        # Check if we can read all the replicas we have replication agreement
        # with
        for replica in replicas:
            result = self.check_host_ldap_readability(replica)
            if result.returncode != 0:
                raise DiagException("%s unreachable" % replica,
                                    key="replica-unreachable")

    def get_advice(self, key):
        if key == 'master-unreachable':
            return ("Local LDAP service is unreadable using the DS keytab. "
                    "Check if the dirsrv process is running and firewall "
                    "open.")
        elif key == 'replica-unreachable':
            return ("Remote replica LDAP is unreachable but local LDAP "
                    "service is. Please check that LDAP service on remote "
                    "replica is running and firewall open on port 389.")
        elif key == 'kinit-unable':
            kvno_command = "# kvno -k /etc/dirsrv/ds.keytab ldap/%s" % api.env.host
            return ("Unable to kinit using DS keytab. Check Kerberos server. "
                    "Additionally, keytab kvno of /etc/dirsrv/ds.keytab "
                    "might be stale. Check with: %s" % kvno_command)
