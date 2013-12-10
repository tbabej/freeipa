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
This file contains filesystem paths.
'''

SVC_LIST_FILE = "/var/run/ipa/services.list"


# Firefox paths

FIREFOX_EXEC = "/usr/bin/firefox"
FIREFOX_INSTALL_DIRS = ["/usr/lib64/firefox", "/usr/lib/firefox"]

# /firefox/install/dir/FIREFOX_PREFERENCES_REL_PATH
FIREFOX_PREFERENCES_REL_PATH = "browser/defaults/preferences"