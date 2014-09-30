# Authors:
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

import re

from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration import tasks


class UtilTestUser(object):
    """
    A little helper class, which represents a test user as the client sees it.
    """

    def __init__(self, login, uid=None, gid=None, gecos='', homedir='',
                 shell='', sshpubkey=None, original_login=None):
        self.login = login
        self.uid = uid
        self.gid = gid
        self.gecos = gecos
        self.homedir = homedir
        self.shell = shell
        self.sshpubkey = sshpubkey
        self.original_login = original_login or login

    def build_regex(self):
        regex = ("{username}:\*:{uid}:{gid}:{gecos}:{homedir}:{shell}"
                 .format(username=re.escape(self.username),
                         uid=re.escape(self.uid) if self.uid else '(\d+)',
                         gid=re.escape(self.gid) if self.gid else '(\d+)',
                         gecos=re.escape(self.gecos),
                         home=re.escape(self.home),
                         shell=re.escape(self.shell),
                         )
        )

        return regex

    def check_getent_passwd(self, host):
        result = host.run_command(['getent', 'passwd', self.login])
        assert re.search(self.build_regex(), result.stdout_text)

    def modify_override(self, host, view, mod=True):
        args = [
            'ipa',
            'idoverrideuser-%s' % ('mod' if mod else 'add'),
            view,
            self.original_login,
        ]

        args += ['--login', self.login] if self.login else []
        args += ['--uid', self.uid] if self.uid else []
        args += ['--gidnumber', self.gid] if self.gid else []
        args += ['--gecos', self.gecos] if self.gecos else []
        args += ['--homedir', self.homedir] if self.homedir else []
        args += ['--shell', self.shell] if self.shell else []
        args += ['--sshpubkey', self.sshpubkey] if self.sshpubkey else []

        result = self.master.run_command(args)

    def execute_test(self, master, client, view, mod=True):
        self.modify_override(master, view, mod)
        tasks.clear_sssd_cache(client)
        self.check_getent_passwd(client)


class TestIDViewsIPA(IntegrationTest):
    """Provides common checks for the AD trust integration testing."""

    topology = 'line'
    num_clients = 1

    @classmethod
    def setup_class(cls):
        super(TestIDViewsIPA, cls).setup_class()

        cls.client = cls.clients[0]

        for i in range(1, 3):
            # Add 1. and 2. testing user
            cls.master.run_command(['ipa', 'user-add',
                                     'testuser%d' % i,
                                     '--first', 'Test',
                                     '--last', 'User%d' % i])

            # Add 1. and 2. testing groups
            cls.master.run_command(['ipa', 'group-add',
                                     'testgroup%d' % i,
                                     '--desc', '"%d. testing group"' % i])

        # Add hostgroup containing the client
        cls.master.run_command(['ipa', 'hostgroup-add',
                                 'testhostgroup',
                                 '--desc', '"Contains client"'])

        # Add the client to the host group
        cls.master.run_command(['ipa', 'hostgroup-add-member',
                                 'testhostgroup',
                                 '--hosts', cls.client.hostname])

        cls.testuser1 = UtilTestUser('testuser1',
                                     gecos='Test User1',
                                     homedir='/home/testuser1',
                                     shell='/bin/sh')

        cls.testuser2 = UtilTestUser('testuser2',
                                     gecos='Test User2',
                                     homedir='/home/testuser2',
                                     shell='/bin/sh')

    def test_add_idview(self):
        self.master.run_command(['ipa', 'idview-add', 'testview'])

    def test_apply_idview(self):
        self.master.run_command(['ipa',
                                 'idview-apply',
                                 '--hosts', self.client.hostname])

    def test_add_override_for_uid(self):
        self.testuser1.uid = 12345
        self.testuser1.execute_test(self.master, self.client, 'testview',
                                    mod=False)

    def test_remove_override_for_uid(self):
        self.testuser1.uid = None
        self.testuser1.execute_test(self.master, self.client, 'testview')

    def test_add_override_for_login(self):
        self.testuser1.login = 'overridenlogin'
        self.testuser1.execute_test(self.master, self.client, 'testview')

    def test_remove_override_for_login(self):
        self.testuser1.login = None
        self.testuser1.execute_test(self.master, self.client, 'testview')

    def test_add_override_for_gid(self):
        self.testuser1.gid = 12345
        self.testuser1.execute_test(self.master, self.client, 'testview')

    def test_remove_override_for_gid(self):
        self.testuser1.gid = None
        self.testuser1.execute_test(self.master, self.client, 'testview')

    def test_add_override_for_gecos(self):
        self.testuser1.gecos = 'Overriden gecos'
        self.testuser1.execute_test(self.master, self.client, 'testview')

    def test_remove_override_for_gecos(self):
        self.testuser1.gecos = None
        self.testuser1.execute_test(self.master, self.client, 'testview')

    def test_add_override_for_shell(self):
        self.testuser1.shell = '/bin/randomshell'
        self.testuser1.execute_test(self.master, self.client, 'testview')

    def test_remove_override_for_shell(self):
        self.testuser1.shell = None
        self.testuser1.execute_test(self.master, self.client, 'testview')






