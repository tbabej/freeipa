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
from ipadiag.pluggable import Reporter, register

import socket
import resource

@register()
class disrv_process_size(Reporter):
    """
    Reports the machine's hostname
    """

    group = 'LDAP'
    cli_name = 'Process size'
    server_only = True

    def get_dirsrv_pid(self):
        result = self.run(['pgrep', 'ns-slapd'])
        return result.stdout.strip()

    def get_process_size(self, pid):
        page_size = resource.getpagesize()

        with open("/proc/%s/statm" % pid, "r") as stats:
            data = stats.read().strip().split()

        pages_used = int(data[0])
        process_size = pages_used * page_size

        return process_size

    def report(self):
        pid = self.get_dirsrv_pid()
        bytes_used = self.get_process_size(pid)
        return "%s kB" % (bytes_used / 1024)
