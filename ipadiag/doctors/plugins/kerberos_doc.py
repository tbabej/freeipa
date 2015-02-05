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

from ipalib import api
from ipaplatform.paths import paths
from ipadiag.pluggable import Doctor, register

@register()
class obtain_host_tgt(Doctor):
    """
    Tries to obtain host Ticket Granting Ticket.
    """

    group = 'System'
    cli_name = 'Obtain host TGT'
    requires_root = True

    def check(self, reports):
        host_principal = 'host/{0}@{1}'.format(api.env.host, api.env.realm)

        # Try to obtain the host TGT
        result = self.run([
            paths.KINIT,
            '-k', '-t', paths.KRB5_KEYTAB,
            host_principal
        ])

        return result.returncode == 0
