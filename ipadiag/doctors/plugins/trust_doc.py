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
class ad_service_records(Doctor):
    """
    Checks that DNS service records are resolvable from IPA side.
    """

    group = 'Trust'
    cli_name = 'Verify IPA LDAP SRV records'
    server_only = True

    def is_applicable(self, reports):
        # If trusts are not enabled, bail out
        if reports.get('trusts_enabled').value != True:
            return False

        return super(ad_service_records, self).is_applicable(reports)

    def check(self, reports):
        ipa_srv_record = '_ldap._tcp.{0}'.format(api.env.realm.lower())

        # Try to obtain the host TGT
        result = self.run([
            paths.DIG,
            "+noall", "+answer",
            "SRV",
            ipa_srv_record
        ])

        return ipa_srv_record in result.stdout
