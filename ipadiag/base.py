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

import os
from ipalib import api
from ipapython import admintool
from ipapython.ipa_log_manager import log_mgr

import json


class IpaDiagnose(admintool.AdminTool):
    """
    Admin tool that given systems's configuration provides instructions how to
    configure the systems for various use cases.
    """

    command_name = 'ipa-diagnose'
    usage = "%prog"
    description = "Provides diagnosis for the given FreeIPA deployment."

    def __init__(self, options, args):
        super(IpaDiagnose, self).__init__(options, args)

    @classmethod
    def add_options(cls, parser):
        super(IpaDiagnose, cls).add_options(parser)

    def validate_options(self):
        super(IpaDiagnose, self).validate_options(needs_root=False)
        pass
        # TODO: validate options properly

    def log_success(self):
        pass

    def collect_reports(self):
        report_collection = {reporter.name: reporter.get_report()
                             for reporter in reporters}
        return json.dumps(report_collection)

    def run(self):
        super(IpaDiagnose, self).run()

        api.bootstrap(in_server=False, context='diagnose')
        api.finalize()

        if not self.options.verbose:
            # Do not print connection information by default
            logger_name = r'ipa\.ipalib\.plugins\.rpcclient'
            log_mgr.configure(dict(logger_regexps=[(logger_name, 'warning')]))

        # With no argument, print the list out and exit
        report = self.collect_reports()
        print report
