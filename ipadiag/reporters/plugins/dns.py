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
from ipadiag.reporters.plugins.base import service_enabled

@register()
class dns_enabled(service_enabled):
    """
    Reports the enablement of the DNS service.
    """

    group = 'DNS'
    service_name = 'DNS'
