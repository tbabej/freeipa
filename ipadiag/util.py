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

import collections
import tempfile
import distutils.spawn

from ipapython.dn import DN
from ipapython.ipautil import run


# Namedtuple to wrap the result of executed commands
CommandResult = collections.namedtuple(
    'CommandResult',
    ['stdout', 'stderr', 'returncode']
)


class abstractclassmethod(classmethod):
    """
    A backport of abstractclassmethod decorator from Python 3.3.
    """

    __isabstractmethod__ = True

    def __init__(self, method):
        method.__isabstractmethod__ = True
        super(abstractclassmethod, self).__init__(method)


def get_hosts_fqdn(api, ldap):
    """
    Returns list of fully qualified domain names of all the hosts in the domain.
    """

    hosts_dn = DN(api.env.container_host, api.env.basedn)

    # Perform the search, asking only for the fqdn attribute
    result, _ = ldap.find_entries(
        attrs_list=['fqdn'],
        base_dn=hosts_dn,
        scope=ldap.SCOPE_ONELEVEL
    )

    hosts_fqdns = set([entry['fqdn'][0] for entry in result])

    return hosts_fqdns


def get_masters_fqdn(api, ldap):
    """
    Returns list of fully qualified domain names of all the masters in the domain.
    """

    masters_dn = DN(
        ('cn', 'masters'),
        ('cn', 'ipa'),
        ('cn', 'etc'),
        api.env.basedn
    )

    # Perform the search, asking only for the cn attribute
    result, _ = ldap.find_entries(
        attrs_list=['cn'],
        base_dn=masters_dn,
        scope=ldap.SCOPE_ONELEVEL
    )

    fqdns = set([entry['cn'][0] for entry in result])

    return fqdns


def get_clients_fqdn(api, ldap):
    """
    Returns list of fully qualified domain names of all the clients in the domain.
    """

    # Clients can be computed as set difference of hosts - masters
    master_fqdns = get_masters_fqdn(api, ldap)
    hosts_fqdns = get_hosts_fqdn(api, ldap)

    return hosts_fqdns - master_fqdns


def execute_remote(host, args):
    """
    Execute a command on the remote host.
    """

    # Locate the ssh executable
    ssh_path = distutils.spawn.find_executable('ssh')
    command = ' '.join(args)

    if ssh_path is None:
        return None

    # Generate temporary file for UserKnownHostsFile
    tmpf = tempfile.NamedTemporaryFile()
    local_cmd = [
        ssh_path,
        '-K',
        '-o BatchMode=yes',
        '-o StrictHostKeychecking=no',
        '-o GSSAPIKeyExchange=yes',
        '-o UserKnownHostsFile=%s' % tmpf.name,
        host, command
    ]

    remote_result = run(local_cmd, raiseonerr=False)
    return CommandResult(*remote_result)
