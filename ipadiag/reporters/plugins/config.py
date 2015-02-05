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

class config_entry_reporter(Reporter):
    """
    Reports the machine's hostname
    """

    group = 'Config'
    server_only = True
    attribute = None

    def get_config_value(self):
        config_dn = DN(('cn', 'ipaConfig'), ('cn', 'etc'), self.api.env.basedn)
        config = self.ldap.get_entry(config_dn, attrs_list=[self.attribute])

        return config[self.attribute]


@register()
class migration_enabled(config_entry_reporter):
    """
    Reports on migration mode status.
    """

    attribute = 'ipaMigrationEnabled'
    cli_name = "Migration mode enabled"

    def report(self):
        enabled = self.get_config_value()[0]

        if enabled == 'FALSE':
            return False
        elif enabled == 'TRUE':
            return True


@register()
class default_selinuxusermap(config_entry_reporter):
    """
    Reports the default SELinux user map.
    """

    attribute = 'ipaSELinuxUserMapDefault'
    cli_name = "Default SELinux user map"

    def report(self):
        return self.get_config_value()[0]
