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

from ipapython.dn import DN
from ipadiag.pluggable import Reporter, register


class base_replica_reporter(Reporter):
    """
    Base class for replica replated reporters.
    """

    group = 'LDAP'
    server_only = True

    def get_replica_names(self):
        agreements_base = DN(
            ('cn','replica'),
            ('cn', self.api.env.basedn),
            ('cn','mapping tree'),
            ('cn','config')
        )

        agreements_filter = self.ldap.make_filter_from_attr(
            'cn', 'meTo',
            exact=False,
            leading_wildcard=False
        )

        result, _ = self.ldap.find_entries(
            agreements_filter,
            attrs_list=['cn'],
            base_dn=agreements_base,
            scope=self.ldap.SCOPE_ONELEVEL
        )

        # Return the list of replicas, by stripping the
        # meTo prefix
        return [entry['cn'][0][4:] for entry in result]


@register()
class replication_agreements_list(base_replica_reporter):
    """
    Reports the number of replication agreements of this particular master.
    """

    group = 'LDAP'
    cli_name = 'List of current hosts replicas'
    server_only = True

    def report(self):
        return self.get_replica_names()


@register()
class replication_agreements_count(base_replica_reporter):
    """
    Reports the number of replication agreements of this particular master.
    """

    group = 'LDAP'
    cli_name = 'Number of replication agreements'
    server_only = True

    def report(self):
        return len(self.get_replica_names())
