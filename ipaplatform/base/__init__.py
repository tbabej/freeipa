# Authors:
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2013  Red Hat
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

'''
This module contains default implementations for the functions that are expected
to be implemented by the platforms, and therefore defines the platform API.
'''

# authconfig is an entry point to platform-provided AuthConfig implementation
# (instance of ipapython.platform.base.AuthConfig)
authconfig = None

# knownservices is an entry point to known platform services
# (instance of ipapython.platform.base.KnownServices)
knownservices = None

# service is a class to instantiate ipapython.platform.base.PlatformService
service = None


# ===== Platform dependant paths =====


# ===== Platform specific services ======


# ===== Platform-specific authconfig =====


# ===== Platform-specific functions =====

