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

import itertools
import krbV
import json
import os

from ipalib import api
from ipalib import cli
from ipalib.util import cachedproperty
from ipapython import admintool
from ipapython.ipa_log_manager import log_mgr

from ipadiag import util
from ipadiag.pluggable import api as diag_api
from ipadiag.result import HostDiagnosticsResult, DomainDiagnosticsResult

# Detect if we're running on IPA master

IN_SERVER = False

try:
    from ipaserver.plugins import ldap2
    IN_SERVER = True
except ImportError:
    pass


class IpaDiagnose(admintool.AdminTool):
    """
    Diagnostics tool that reports information about given FreeIPA deployment
    and performs diagnostics checks upon it.
    """

    command_name = 'ipa-diagnose'
    usage = "%prog"
    description = "Provides diagnosis for the given FreeIPA deployment."

    def __init__(self, options, args):
        super(IpaDiagnose, self).__init__(options, args)

    # Option parsing and validation

    @classmethod
    def add_options(cls, parser):
        """
        Setup option handling via IPAOptParser, which is a wrapper
        around optparse module.
        """

        super(IpaDiagnose, cls).add_options(parser)

        parser.add_option(
            "--all-servers",
            dest="diagnose_servers", action="store_true", default=False,
            help="automatically diagnose all IPA servers")

        parser.add_option(
            "--domain",
            dest="diagnose_domain", action="store_true", default=False,
            help="automatically diagnose whole IPA domain, including clients")

        parser.add_option(
            "--skip-hosts",
            dest="skip_hosts", action='append',
            help="hosts to be skipped during the check")

        parser.add_option(
            "--check-hosts",
            dest="check_hosts", action="append", default=False,
            help="hosts to be checked during the check")

        parser.add_option(
            "--advice",
            dest="advice", action="store_true", default=False,
            help="Generate remediation advice."
                 "on other remote machines")

        parser.add_option(
            "--json-only",
            dest="json_only", action="store_true", default=False,
            help="Produce structured output only")

    def validate_options(self):
        """
        Validates the options passed by the user and terminates the tool
        in case of validation error.
        """

        # Check the rules according to default admintool implementation
        super(IpaDiagnose, self).validate_options(needs_root=False)

        # The --advice and --json-only exclude themselves
        if self.options.advice and self.options.json_only:
            self.option_parser.error("Both --json-only and --advice cannot "
                                     "be specified.")


    def run(self):
        """
        Main body of the diagnosis tool.
        """

        super(IpaDiagnose, self).run()

        # Initialize the server api
        api.bootstrap(in_server=False, context='server')
        api.finalize()

        # Initialize the diagnostics api
        diag_api.bootstrap(in_server=False, context='server')
        diag_api.finalize()

        # Establish LDAP connection
        if os.geteuid() == 0:
            api.Backend.ldap2.connect(autobind=True)
        else:
            ctx = krbV.default_context()
            ccache = ctx.default_ccache()
            api.Backend.ldap2.connect(ccache)

        if not self.options.verbose:
            # Do not print connection information by default
            logger_name = r'ipa\.ipalib\.plugins\.rpcclient'
            log_mgr.configure(dict(logger_regexps=[(logger_name, 'warning')]))

        # Initialize the plugin proxy, output handler and the runner itself
        plugins = DiagnosePluginProxy()
        runner = DiagnoseRunner(plugins, self.options)
        output = DiagnoseOutputHandler(plugins, self.options)

        # Collect data with runner and handle output
        local_results, domain_results = runner.main()
        output.main(local_results, domain_results)

    def log_success(self):
        # Overriden base admintool.AdminTool method.
        # Silence unnecessary status message upon success.
        pass


class DiagnosePluginProxy(object):
    """
    Plugin proxy that provides access to all diagnostics plugin.
    """

    reports = None
    host_reports = None
    domain_reports = None

    # Reporter and doctor access properties

    def __init__(self):
        # Provide the plugins with convenient api and ldap instances
        self.initialize_plugins()

    @property
    def reporters(self):
        """
        Return iterator over instances of all Reporter plugins.
        """
        return dict(diag_api.Reporter.__todict__()).values()

    @property
    def doctors(self):
        """
        Return iterator over instances of all Doctor plugins.
        """
        return dict(diag_api.Doctor.__todict__()).values()

    @property
    def domain_reporters(self):
        """
        Return iterator over instances of all DomainReporter plugins.
        """
        return dict(diag_api.DomainReporter.__todict__()).values()

    @property
    def domain_doctors(self):
        """
        Return iterator over instances of all DomainDoctors plugins.
        """
        return dict(diag_api.DomainDoctor.__todict__()).values()

    @property
    def plugins(self):
        """
        Return iterator over instances of all plugins.
        """
        return itertools.chain(self.reporters, self.doctors,
                               self.domain_reporters, self.domain_doctors)


    def filter_applicable_only(self, plugins, *args, **kwargs):
        """
        Generic plugin filter method.
        """

        # Generate a sorted interable of available plugins of given type
        plugins_sorted = sorted(plugins,
                                key=lambda x: (x.group, x.pretty_name))

        # Filter out the non-applicable instances
        return [plugin for plugin in plugins_sorted
                if plugin.is_applicable(*args, **kwargs)]


    @cachedproperty
    def applicable_reporters(self):
        """
        Property that yields all the available reporters, filtering out
        those that are not applicable to the given host.
        """

        return self.filter_applicable_only(self.reporters)

    @cachedproperty
    def applicable_doctors(self):
        """
        Property that yields all the available doctors, filtering out
        those that are not applicable to the given host.
        """

        if self.reports is None:
            raise ValueError("Applicable doctors cannot be accessed unless "
                             "proxy has received the reports.")

        return self.filter_applicable_only(self.doctors, self.reports)

    @cachedproperty
    def applicable_domain_reporters(self):
        """
        Property that yields all the available reporters, filtering out
        those that are not applicable to the given host.
        """
        if self.reports is None:
            raise ValueError("Applicable doctors cannot be accessed unless "
                             "proxy has received the host reports.")

        return self.filter_applicable_only(self.domain_reporters, self.host_reports)

    @cachedproperty
    def applicable_domain_doctors(self):
        """
        Property that yields all the available doctors, filtering out
        those that are not applicable to the given host.
        """

        if self.host_reports is None or self.domain_reports is None:
            raise ValueError("Applicable doctors cannot be accessed unless "
                             "proxy has received both the host and domain "
                             "reports.")

        return self.filter_applicable_only(self.domain_doctors,
            self.host_reports, self.domain_reports)

    def initialize_plugins(self):
        """
        Intialize the api and ldap attributes of the plugins.
        """

        for plugin in self.plugins:
            if IN_SERVER:
                # Set ldap connection only if on master
                plugin.initialize(api=api, ldap=api.Backend.ldap2)
            else:
                plugin.initialize(api=api)


class DiagnoseOutputHandler(object):
    # Output related methods

    def __init__(self, plugins, options):
        # Set the output helper instance
        self.textui = cli.textui()
        self.plugins = plugins
        self.options = options

    def print_welcome(self):
        # Show the heading
        self.textui.print_h1('IPA Diagnostics report')

    def print_reporters(self, results):
        """
        Print the results of the host-level reporters, grouped.
        """

        self.textui.print_h2('System information')

        reports = results.reports

        # Group reporters by their report group
        reporters_grouped = itertools.groupby(
            self.plugins.applicable_reporters, key=lambda x: x.group)

        for group, reporters in reporters_grouped:
            self.textui.print_indented(group + ":", indent=2)

            for reporter in reporters:
                reporter.print_formatted(self.textui, reports[reporter.name])

        print('')

    def print_doctors(self, results):
        """
        Print the results of the host-level doctors, grouped.
        """

        self.textui.print_h2('System health check')

        checks = results.checks

        # Group doctors by their report group
        doctors_grouped = itertools.groupby(
            self.plugins.applicable_doctors, key=lambda x: x.group)

        for group, doctors in doctors_grouped:
            self.textui.print_indented(group + ":", indent=2)

            for doctor in doctors:
                doctor.print_formatted(self.textui, checks[doctor.name])

        print('')

    def print_domain_reporters(self, results):
        """
        Print the results of the domain-level reporters, grouped.
        """

        self.textui.print_h2('Domain information')

        reports = results.reports

        reporters_grouped = itertools.groupby(
            self.plugins.applicable_domain_reporters, key=lambda x: x.group)

        for group, reporters in reporters_grouped:
            self.textui.print_indented(group + ":", indent=2)

            for reporter in reporters:
                reporter.print_formatted(self.textui, reports[reporter.name])

        print('')

    def print_domain_doctors(self, results):
        """
        Print the results of the domain-level doctors, grouped.
        """

        self.textui.print_h2('Domain health check')

        checks = results.checks

        # Group doctors by their report group
        doctors_grouped = itertools.groupby(
            self.plugins.applicable_domain_doctors, key=lambda x: x.group)

        for group, doctors in doctors_grouped:
            self.textui.print_indented(group + ":", indent=2)

            for doctor in doctors:
                doctor.print_formatted(self.textui, checks[doctor.name])

        print('')

    def print_json_only(self, local_results, domain_results):
        """
        Produces the JSON output, suitable for further processing.
        """

        data_dict = {
            'reports': {key: value.to_dict()
                        for key, value in local_results.reports.iteritems()},
            'checks': {key: value.to_dict()
                        for key, value in local_results.checks.iteritems()},
        }

        # If there is any domain data available, include it in the report
        if domain_results is not None:
            domain_data_dict = {
                'domain_reports': {key: value.to_dict()
                        for key, value in domain_results.reports.iteritems()},
                'domain_checks': {key: value.to_dict()
                        for key, value in domain_results.checks.iteritems()},
            }

            data_dict.update(domain_data_dict)

        # Serialize to json and print
        print(json.dumps(data_dict))

    def offer_advice(self, local_checks, domain_checks):
        """
        Generates and displays remediation advice.
        """

        self.textui.print_h2('Remediation advice')

        # Filter out only failed checks
        failed_local_doctor = [
            (name, result)
            for name, result in local_checks.iteritems()
            if not result.status
        ]

        failed_domain_doctor = [
            (name, result)
            for name, result in domain_checks.iteritems()
            if not result.status
        ]

        # Print a remediation advice for each failed Doctor
        for name, check in failed_local_doctor:
            doctor = diag_api.Doctor[name]
            advice = doctor.get_advice(check.error_key)
            self.print_advice(doctor.pretty_name, advice)

        for name, check in failed_domain_doctor:
            doctor = diag_api.DomainDoctor[name]
            advice = doctor.get_advice(check.error_key)
            self.print_advice(doctor.pretty_name, advice)

    def print_advice(self, name, advice):
        """
        Prints the advice of with the given prefix. Makes sure lines are properly
        aligned.
        """

        # If no advice is generated, do not print anything.
        if advice is None:
            return

        self.textui.print_indented(name + ":", indent=2)
        self.textui.print_indented(advice, indent=3)

    def main(self, local_results, domain_results):
        # Welcome the user!
        if self.options.json_only:
            self.print_json_only(local_results, domain_results)
        else:
            # Print hosts reporters and doctors result in any case
            self.print_welcome()
            self.print_reporters(local_results)
            self.print_doctors(local_results)

            # Display domain section only if any results were generated
            if domain_results is not None:
                self.print_domain_reporters(domain_results)
                self.print_domain_doctors(domain_results)

            # Offer advice only if requested
            if self.options.advice:
                self.offer_advice(
                    local_results.checks,
                    domain_results.checks if domain_results is not None else {}
                    )


class DiagnoseRunner(object):
    """
    DiagnoseRunner takes care of the plugin execution and data collection.
    """

    def __init__(self, plugins, options):
        self.textui = cli.textui()
        self.plugins = plugins
        self.options = options

    def perform_diagnosis(self):
        """
        Performs both the host and domain level diagnosis
        and returns the result as a tuple.
        """

        # Collect and let proxy know about the results
        self.reports = self.collect_local_reports()
        self.plugins.reports = self.reports

        # Perform the checks
        self.checks = self.collect_local_checks(self.reports)

        host_result = HostDiagnosticsResult(self.reports, self.checks)
        domain_result = self.domain_diagnosis()

        return host_result, domain_result

    def domain_diagnosis(self):
        """
        Performs both the host and domain level diagnosis
        and returns the result as a tuple.
        """

        host_data_collection = self.collect_host_reports()
        if host_data_collection is None:
            return None

        host_reports, host_checks, unreachable = host_data_collection
        domain_reports = self.collect_domain_reports(host_reports)
        self.plugins.host_reports = host_reports
        self.plugins.domain_reports = domain_reports

        # Perform the checks
        domain_checks = self.collect_domain_checks(host_reports, domain_reports)

        return DomainDiagnosticsResult(domain_reports, domain_checks,
                                       unreachable)

    def collect_host_reports(self):
        """
        Collects reports from remote hosts.
        """

        hosts_to_diagnose = set()

        # Build a set of hosts to diagnose
        if self.options.diagnose_domain:
            hosts_to_diagnose |= util.get_hosts_fqdn(api, api.Backend.ldap2)
        elif self.options.diagnose_servers:
            hosts_to_diagnose |= util.get_masters_fqdn(api, api.Backend.ldap2)
        else:
            return None

        host_reports = dict()
        host_checks = dict()

        unreachable = []

        # Setup parameters for the progress bar
        step = 0
        steps = len(hosts_to_diagnose)
        label = "Collecting remote data:"

        # We deliberately do not execute the jobs in parallel.
        #print hosts_to_diagnose
        for host in hosts_to_diagnose:
            self.update_bar(step, steps, label)
            step += 1

            if host == api.env.host:
                host_reports[host] = self.reports
                host_checks[host] = self.checks
                continue
            else:
                pass

            try:
                remote_results = self.collect_host_results(host)

                if remote_results is None:
                    unreachable.append(host)
                else:
                    host_reports[host] = remote_results.reports
                    host_checks[host] = remote_results.checks

            except Exception:
                # If anything went wrong, do not abort
                pass

        self.update_bar(step, steps, label)

        return host_reports, host_checks, unreachable

    def collect_host_results(self, host):
        """
        Collects host results from one host.
        """

        # Fist try to execute the command with sudo
        result = util.execute_remote(
            host,
            ['sudo', '/usr/sbin/ipa-diag', '--json-only']
        )

        # After that, use ordinary privileges
        if result.returncode != 0:
            result = util.execute_remote(
                host,
                ['/usr/sbin/ipa-diag', '--json-only']
            )
            #print result

        if result.returncode != 0:
            return None

        # Parse the obtained data
        remote_data = json.loads(result.stdout.strip())

        return HostDiagnosticsResult(remote_data['reports'],
                                     remote_data['checks'])

    def update_bar(self, step, steps, label):
        """
        Update the progressbar. No-op if in json-only mode.
        """
        if not self.options.json_only:
            self.textui.display_progressbar(step, steps, prefix=label, size=20)

    def generic_result_collector(self, plugins, exec_method, label, *args):
        """
        Generic method to collect results from plugin execution
        """

        # Setup progressbar
        result_collection = {}
        steps = len(list(plugins))
        step = 0

        self.update_bar(step, steps, label)

        # Evaluate each plugin
        for plugin in plugins:
            plugin_executor = getattr(plugin, exec_method)
            result_collection[plugin.name] = plugin_executor(*args)
            step = step + 1
            self.update_bar(step, steps, label)


        return result_collection

    def collect_local_reports(self):
        return self.generic_result_collector(
            self.plugins.applicable_reporters,
            'report_safe',
            'Collecting reports:'
        )

    def collect_local_checks(self, reports):
        return self.generic_result_collector(
            self.plugins.applicable_doctors,
            'check_safe',
            'Performing checks:',
            reports
        )

    def collect_domain_reports(self, host_reports):
        return self.generic_result_collector(
            self.plugins.applicable_domain_reporters,
            'report_safe',
            'Collecting domain reports:',
            host_reports
        )

    def collect_domain_checks(self, host_reports, domain_reports):
        return self.generic_result_collector(
            self.plugins.applicable_domain_doctors,
            'check_safe',
            'Performing domain checks:',
            host_reports,
            domain_reports
        )

    def main(self):
        return self.perform_diagnosis()
