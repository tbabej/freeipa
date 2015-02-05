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

from ipadiag.pluggable import Reporter, register
from ipapython.dn import DN
from ipalib import errors


class service_enabled(Reporter):
    """
    Reports the enablement of a particular service.
    """

    cli_name = 'Enabled'
    server_only = True
    service_name = None

    def report(self):
        assert self.service_name is not None

        service_dn = DN(
            ('cn', self.service_name),
            ('cn', self.api.env.host),
            ('cn', 'masters'),
            ('cn', 'ipa'),
            ('cn', 'etc'),
            self.api.env.basedn
        )

        try:
            self.ldap.get_entry(service_dn)
        except errors.NotFound:
            return False

        return True
