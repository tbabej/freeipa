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
This module contains default platform-specific implementations of system tasks.
'''


def restore_context(filepath):
    '''
    Restores security context for a given path.
    '''
    return


def backup_and_replace_hostname(fstore, statestore, hostname):
    '''
    Backups the current hostname to the filestore and replaces it with the
    hostname give as an argument to this function.
    '''
    return


def check_selinux_status():
    '''
    Raises RuntimeError if SELinux is available, enabled, but restorecon tool
    is not available.
    '''
    return


def get_svc_list_file():
    '''
    Returns the path to the file containing the list of IPA services.
    '''
    return SVC_LIST_FILE


def insert_ca_cert_into_systemwide_ca_store(path):
    '''
    Inserts certificate file at given path to the systemwide ca store.
    Returns True/False to denote success/failure of the insertion.
    '''

    return True


def remove_ca_cert_from_systemwide_ca_store(path):
    '''
    Removes certificate file at given path from the systemwide ca store.
    Returns True/False to denote success/failure of the removal.
    '''

    return True