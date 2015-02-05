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

import abc
import collections
import os

from ipalib.plugable import Plugin, Registry, API
from ipapython import ipautil

from ipadiag.result import ReporterResult, DoctorResult
from ipadiag.errors import DiagException
from ipadiag.util import CommandResult


register = Registry()

def prepare_for_output(value):
    """
    Simple output format handler helper.
    """

    if isinstance(value, bool) or value is None:
        return value
    elif isinstance(value, list):
        return ', '.join(value)
    else:
        return str(value)


class BaseDiagnosePlugin(Plugin):
    """
    Base class for any diagnosis plugin.
    """

    requires_root = False

    cli_name = None
    group = 'Other'

    @property
    def pretty_name(self):
        """
        Returns a CLI friendly name.
        """

        return self.cli_name or self.__class__.__name__

    def print_formatted(self, textui, result):
        """
        Formats the result for output and prints it.
        Plugin instances can override this method to generate
        custom output.
        """

        template = "{0}: {1}{2}"
        data = (
            self.pretty_name,
            '[Fail] ' if result.status is False else '',
            result.value,
        )

        # Fill in the template
        text = template.format(*data)

        # Print it out
        textui.print_indented(text, indent=3)

    def run(self, args, **kwargs):
        """
        Executes the specified command, returning a CommandResult instance.
        """

        result = ipautil.run(args, **kwargs)
        return CommandResult(*result)

    @property
    def api(self):
        return self._api

    def initialize(self, api, ldap=None):
        """
        Initializes the API and LDAP attributes on the plugin.
        """

        self._api = api
        self.ldap = ldap


class BaseHostDiagnosePlugin(BaseDiagnosePlugin):
    """
    Base class for host diagnosis plugins.
    """

    server_only = False
    client_only = False

    def is_applicable(self):
        """
        Detects whether diagnosis should be run on the instance.
        """

        # Check if the current reporter/doctor requires root
        if self.requires_root and os.geteuid() != 0:
            return False

        if self.server_only and self.api.env.context != "server":
            return False

        if self.client_only and self.api.env.context == "server":
            return False

        return True


class BaseDomainDiagnosePlugin(BaseDiagnosePlugin):
    """
    Base class for domain diagnosis plugins.
    """

    def is_applicable(self, host_reports):
        """
        Detects whether diagnosis should be run on the instance.
        """

        # Check if the current reporter/doctor requires root
        if self.requires_root and os.geteuid() != 0:
            return False

        if self.api.env.context != "server":
            return False

        return True


class BaseReporter(object):
    """
    Base class for reporters plugins.
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def report(self):
        """
        Main body of the reporter script.
        """
        raise NotImplementedError

    def report_safe(self, *args):
        """
        Wrapper around the report method, which ensures that a proper
        ReporterResult is returned under all circumstances.
        """

        try:
            result = self.report(*args)

            # If this is not a instance of ReporterResult, we need to format it
            if not isinstance(result, ReporterResult):
                result = ReporterResult(True, value=prepare_for_output(result))
        except DiagException as diag_exc:
            # For DiagException use specialized constructor
            result = ReporterResult.from_diagnose_exception(diag_exc)
        except Exception as exception:
            result = ReporterResult(False, str(exception), error_key='unknown-error')

        return result


class BaseDoctor(object):
    """
    Base class for doctor plugins.
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def check(self, reports):
        """
        Main body of the doctor script.
        """
        raise NotImplementedError

    def check_safe(self, reports, *args):
        """
        Wrapper around the check method, which ensures
        that a proper DoctorResult object is returned.
        """

        try:
            result = self.check(reports, *args)
            if not isinstance(result, DoctorResult):
                result = DoctorResult(
                    status=True,
                    value=prepare_for_output(result)
                )
        except DiagException as diag_exc:
            result = DoctorResult.from_diagnose_exception(
                diag_exc,
                self.get_advice(diag_exc.key),
                )
        except Exception as exception:
            result = DoctorResult(False, str(exception),
                                  error_key='unexpected')

        return result

    def is_applicable(self, reports):
        """
        Detects whether diagnosis should be run on the instance.
        """

        return super(BaseDoctor, self).is_applicable()

    def get_advice(self, key):
        """
        Generates advice for given error key.
        """

        return None

    def print_formatted(self, textui, result):
        if result.value is True or result.value is None:
            result_formatted = DoctorResult(
                result.status,
                "[Pass]",
                result.error_key,
                result.advice
            )
        else:
            result_formatted = result

        return super(BaseDoctor, self).print_formatted(textui, result_formatted)


@register.base()
class Reporter(BaseReporter, BaseHostDiagnosePlugin):
    """
    Host level reporter.
    """
    pass


@register.base()
class Doctor(BaseDoctor, BaseHostDiagnosePlugin):
    """
    Host level doctor.
    """
    pass


@register.base()
class DomainReporter(BaseReporter, BaseDomainDiagnosePlugin):
    """
    Domain level reporter.
    """

    def is_applicable(self, host_reports):
        """
        Detects whether diagnosis should be run on the instance.
        """

        return super(DomainReporter, self).is_applicable(host_reports)


@register.base()
class DomainDoctor(BaseDoctor, BaseDomainDiagnosePlugin):
    """
    Domain level doctor.
    """

    def is_applicable(self, host_reports, domain_reports):
        """
        Detects whether diagnosis should be run on the instance.
        """

        return super(DomainDoctor, self).is_applicable(host_reports)


api = API((Reporter, Doctor, DomainReporter, DomainDoctor), ('ipadiag/reporters/plugins', 'ipadiag/doctors/plugins'))
