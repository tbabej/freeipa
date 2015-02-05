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

from ipapython.dn import DN
from ipadiag.pluggable import Reporter, register

KNOWN_PLUGINS = set([
    u'7-bit check',
    u'Account Policy Plugin',
    u'Account Usability Plugin',
    u'ACL Plugin',
    u'ACL preoperation',
    u'attribute uniqueness',
    u'Auto Membership Plugin',
    u'Binary Syntax',
    u'Bit String',
    u'Bitwise Plugin',
    u'Boolean Syntax',
    u'Case Exact String Syntax',
    u'Case Ignore String Syntax',
    u'certificate store issuer/serial uniqueness',
    u'certificate store subject uniqueness',
    u'chaining database',
    u'Class of Service',
    u'Content Synchronization',
    u'Country String Syntax',
    u'Delivery Method Syntax',
    u'deref',
    u'Distinguished Name Syntax',
    u'Distributed Numeric Assignment Plugin',
    u'Enhanced Guide Syntax',
    u'Facsimile Telephone Number Syntax',
    u'Fax Syntax',
    u'Generalized Time Syntax',
    u'Guide Syntax',
    u'HTTP Client',
    u'Integer Syntax',
    u'Internationalization Plugin',
    u'IPA DNS',
    u'IPA Lockout',
    u'IPA MODRDN',
    u'IPA OTP Counter',
    u'IPA OTP Last Token',
    u'IPA Range-Check',
    u'IPA UUID',
    u'IPA Version Replication',
    u'ipa-winsync',
    u'ipa_enrollment_extop',
    u'ipa_pwd_extop',
    u'ipaUniqueID uniqueness',
    u'JPEG Syntax',
    u'krbCanonicalName uniqueness',
    u'krbPrincipalName uniqueness',
    u'ldbm database',
    u'Legacy Replication Plugin',
    u'Linked Attributes',
    u'Managed Entries',
    u'MemberOf Plugin',
    u'Multimaster Replication Plugin',
    u'Name And Optional UID Syntax',
    u'netgroup uniqueness',
    u'Numeric String Syntax',
    u'Octet String Syntax',
    u'OID Syntax',
    u'PAM Pass Through Auth',
    u'Pass Through Authentication',
    u'Posix Winsync API',
    u'Postal Address Syntax',
    u'Printable String Syntax',
    u'referential integrity postoperation',
    u'Retro Changelog Plugin',
    u'Roles Plugin',
    u'RootDN Access Control',
    u'Schema Compatibility',
    u'Schema Reload',
    u'Space Insensitive String Syntax',
    u'State Change Plugin',
    u'sudorule name uniqueness',
    u'Syntax Validation Task',
    u'Telephone Syntax',
    u'Teletex Terminal Identifier Syntax',
    u'Telex Number Syntax',
    u'uid uniqueness',
    u'URI Syntax',
    u'USN',
    u'Views',
    u'whoami'
])


KNOWN_DISABLED_PLUGINS = set([
    u'Account Policy Plugin',
    u'attribute uniqueness',
    u'PAM Pass Through Auth',
    u'Pass Through Authentication',
    u'Posix Winsync API',
    u'RootDN Access Control',
    u'Space Insensitive String Syntax',
    u'URI Syntax'
])


class ldap_plugins_base(Reporter):
    """
    Base class for plugins related to LDAP plugins.
    """

    group = 'LDAP'
    requires_root = True
    server_only = True

    def get_enabled_plugins(self):
        plugins_base = DN(('cn','plugins'), ('cn','config'))

        enabled_plugins_filter = self.ldap.make_filter_from_attr(
            'nsslapd-pluginEnabled', 'on',
        )

        result, _ = self.ldap.find_entries(
            enabled_plugins_filter,
            attrs_list=['cn'],
            base_dn=plugins_base,
            scope=self.ldap.SCOPE_ONELEVEL
        )

        return set([entry['cn'][0] for entry in result])


@register()
class ldap_plugins_count(ldap_plugins_base):
    """
    Returns the total number of allowed LDAP plugins.
    """

    cli_name = 'Number of enabled plugins'

    def report(self):
        plugins = self.get_enabled_plugins()
        return len(plugins)


@register()
class ldap_plugins_extra(ldap_plugins_base):
    """
    Returns names of any non-default LDAP plugins.
    """

    cli_name = 'Extra plugins'

    def report(self):
        plugins = self.get_enabled_plugins()
        return ', '.join(plugins - KNOWN_PLUGINS)


@register()
class ldap_plugins_missing(ldap_plugins_base):
    """
    Returns names of any missing LDAP plugins.
    """

    cli_name = 'Missing plugins'

    def report(self):
        plugins = self.get_enabled_plugins()
        return ', '.join(KNOWN_PLUGINS - KNOWN_DISABLED_PLUGINS - plugins)

