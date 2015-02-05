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
import json
import collections

from ipadiag.errors import DiagException

class abstractclassmethod(classmethod):

    __isabstractmethod__ = True

    def __init__(self, method):
        method.__isabstractmethod__ = True
        super(abstractclassmethod, self).__init__(method)


class DiagPluginResult(object):

    __metaclasses__ = abc.ABCMeta

    def __init__(self, status, value, error_key=None):
        if not isinstance(status, bool):
            raise ValueError("Result status must be either True or False")

        self.status = status
        self.value = value
        self.error_key = error_key

    @abstractclassmethod
    def from_diagnose_exception(cls, exception):
        pass

    @abc.abstractmethod
    def to_dict(self):
        pass

    @abstractclassmethod
    def from_dict(cls, data):
        pass


class ReporterResult(DiagPluginResult):

    @classmethod
    def from_diagnose_exception(cls, exception):
        return cls(False, exception.message, exception.key)

    def to_dict(self):
        data = {
            'status': self.status,
            'value': self.value,
        }

        if self.error_key:
            data['error_key'] = self.error_key

        return data

    @classmethod
    def from_dict(cls, data):
        return cls(
            status=data['status'],
            value=data['value'],
            error_key=data.get('error_key')
        )


class DoctorResult(DiagPluginResult):

    def __init__(self, status, value, error_key=None, advice=None):
        """
        Initializes the Doctor result instance.
        """

        super(DoctorResult, self).__init__(status, value, error_key)
        self.advice = advice

    @classmethod
    def from_diagnose_exception(cls, exception, advice=None):
        """
        Constructs the Doctor result instance from DiagException object.
        """

        return cls(False, exception.message, exception.key, advice)

    def to_dict(self):
        """
        Converts the DoctorResult to a dict representation.
        """

        data = {
            'status': self.status,
            'value': self.value,
        }

        if self.error_key:
            data['error_key'] = self.error_key

        if self.advice:
            data['advice'] = self.advice

        return data

    @classmethod
    def from_dict(cls, data):
        """
        Constructs the DoctorResult from a dict representation
        """

        return cls(
            status=data['status'],
            value=data['value'],
            error_key=data.get('error_key'),
            advice=data.get('advice')
        )

# Define named tuples for the result of the diagnostics

HostDiagnosticsResult = collections.namedtuple(
    'HostDiagnosticsResult',
    ['reports', 'checks']
)


DomainDiagnosticsResult = collections.namedtuple(
    'DomainDiagnosticsResult',
    ['reports', 'checks', 'unreachable']
)
