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

import dns
import dns.resolver

from dns.exception import DNSException
from ipadiag.errors import DiagException

from ipapython.dn import DN
from ipadiag.pluggable import Doctor, register
from ipadiag.util import get_masters_fqdn

SERVICE_RECORDS = [
    u"_ldap._tcp",
    u"_kerberos._tcp",
    u"_kerberos._udp",
    u"_kerberos-master._tcp",
    u"_kerberos-master._udp",
    u"_kpasswd._tcp",
    u"_kpasswd._udp",
]


class check_master_records_base(Doctor):
    """
    Base class for Doctors which check master records.
    """

    group = 'DNS'
    record_type = None

    def check(self, reports):
        fqdns = get_masters_fqdn(self.api, self.ldap)
        failed = []

        for master in [fqdn + '.' for fqdn in fqdns]:
            try:
                dns.resolver.query(master, self.record_type)
            except DNSException:
                failed.append(master)
        if failed:
            raise DiagException(
                message=', '.join(failed),
                key='failed-resolving'
            )


@register()
class check_master_a_records(check_master_records_base):
    """
    Checks if all IPA masters have A records.
    """

    cli_name = 'IPA masters A records resolvable'
    record_type = 'A'


@register()
class check_master_aaaa_records(check_master_records_base):
    """
    Checks if all IPA masters have AAAA records.
    """

    cli_name = 'IPA masters AAAA records resolvable'
    record_type = 'AAAA'


@register()
class check_ipa_service_records(Doctor):
    """
    Checks if IPA domain has valid service records.
    """

    group = 'DNS'
    cli_name = 'IPA domain service records correct'

    def check(self, reports):
        fqdns = [fqdn + '.' 
                 for fqdn in get_masters_fqdn(self.api, self.ldap)]
        failed = []

        # Check each service
        for service_record in SERVICE_RECORDS:
            try:
                record = "{0}.{1}".format(service_record, self.api.env.domain)
                result = dns.resolver.query(record, 'SRV')

                for answer in result.rrset:
                    if answer.target.to_text() not in fqdns:
                        # In case no answer matches a master, raise an error
                        raise DiagException(
                            message="{0} does not point to IPA master"
                                    .format(service_record),
                            key='not-ipa-master')

            except DNSException:
                # If lookup failed, make a note
                failed.append(service_record)

        # If any lookup failed, raise a DiagException
        if failed:
            raise DiagException(
                message=', '.join(failed),
                key='failed-resolving'
            )
