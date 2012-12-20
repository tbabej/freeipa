#!/usr/bin/python
# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#          Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2008-2012  Red Hat
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
import tempfile
from optparse import OptionGroup

from ipaserver.install import certs, installutils, bindinstance, dsinstance
from ipaserver.install.replication import enable_replication_version_checking
from ipaserver.plugins.ldap2 import ldap2
from ipaserver.install.bindinstance import dns_container_exists
from ipapython import ipautil, admintool, dogtag
from ipapython.dn import DN
from ipalib import api
from ipalib import errors


class ReplicaPrepare(admintool.AdminTool):
    command_name = 'ipa-replica-prepare'

    usage = "%prog [options] <replica-fqdn>"

    description = "Prepare a file for replica installation."

    @classmethod
    def add_options(cls, parser):
        super(ReplicaPrepare, cls).add_options(parser, debug_option=True)

        parser.add_option("-p", "--password", dest="password",
            help="Directory Manager password (for the existing master)")
        parser.add_option("--ip-address", dest="ip_address", type="ip",
            help="add A and PTR records of the future replica")
        parser.add_option("--reverse-zone", dest="reverse_zone",
            help="the reverse DNS zone to use")
        parser.add_option("--no-reverse", dest="no_reverse",
            action="store_true", default=False,
            help="do not create reverse DNS zone")
        parser.add_option("--no-pkinit", dest="setup_pkinit",
            action="store_false", default=True,
            help="disables pkinit setup steps")
        parser.add_option("--ca", dest="ca_file", default="/root/cacert.p12",
            metavar="FILE",
            help="location of CA PKCS#12 file, default /root/cacert.p12")

        group = OptionGroup(parser, "SSL certificate options",
            "Only used if the server was installed using custom SSL certificates")
        group.add_option("--dirsrv_pkcs12", dest="dirsrv_pkcs12",
            metavar="FILE",
            help="install certificate for the directory server")
        group.add_option("--http_pkcs12", dest="http_pkcs12",
            metavar="FILE",
            help="install certificate for the http server")
        group.add_option("--pkinit_pkcs12", dest="pkinit_pkcs12",
            metavar="FILE",
            help="install certificate for the KDC")
        group.add_option("--dirsrv_pin", dest="dirsrv_pin", metavar="PIN",
            help="PIN for the Directory Server PKCS#12 file")
        group.add_option("--http_pin", dest="http_pin", metavar="PIN",
            help="PIN for the Apache Server PKCS#12 file")
        group.add_option("--pkinit_pin", dest="pkinit_pin", metavar="PIN",
            help="PIN for the KDC pkinit PKCS#12 file")
        parser.add_option_group(group)

    def validate_options(self):
        options = self.options
        super(ReplicaPrepare, self).validate_options(needs_root=True)
        installutils.check_server_configuration()

        if not options.ip_address:
            if options.reverse_zone:
                self.option_parser.error("You cannot specify a --reverse-zone "
                    "option without the --ip-address option")
            if options.no_reverse:
                self.option_parser.error("You cannot specify a --no-reverse "
                    "option without the --ip-address option")
        elif options.reverse_zone and options.no_reverse:
            self.option_parser.error("You cannot specify a --reverse-zone "
                "option together with --no-reverse")

        # If any of the PKCS#12 options are selected, all are required.
        pkcs12_opts = [options.dirsrv_pkcs12, options.dirsrv_pin,
                    options.http_pkcs12, options.http_pin]
        if options.setup_pkinit:
            pkcs12_opts.extend([options.pkinit_pkcs12, options.pkinit_pin])
        if pkcs12_opts[0]:
            pkcs12_okay = all(opt for opt in pkcs12_opts)
        else:
            pkcs12_okay = all(opt is None for opt in pkcs12_opts)
        if not pkcs12_okay:
            self.option_parser.error(
                "All PKCS#12 options are required if any are used.")

        if len(self.args) < 1:
            self.option_parser.error(
                "must provide the fully-qualified name of the replica")
        elif len(self.args) > 1:
            self.option_parser.error(
                "must provide exactly one name for the replica")
        else:
            [self.replica_fqdn] = self.args

        api.bootstrap(in_server=True)
        api.finalize()

        if api.env.host == self.replica_fqdn:
            raise admintool.ScriptError("You can't create a replica on itself")

        #Automatically disable pkinit w/ dogtag until that is supported
        #[certs.ipa_self_signed() must be called only after api.finalize()]
        if not options.pkinit_pkcs12 and not certs.ipa_self_signed():
            options.setup_pkinit = False

        # FIXME: certs.ipa_self_signed_master return value can be
        # True, False, None, with different meanings.
        # So, we need to explicitly compare to False
        if certs.ipa_self_signed_master() == False:
            raise admintool.ScriptError("A selfsign CA backend can only "
                "prepare on the original master")

        config_dir = dsinstance.config_dirname(
            dsinstance.realm_to_serverid(api.env.realm))
        if not ipautil.dir_exists(config_dir):
            raise admintool.ScriptError(
                "could not find directory instance: %s" % config_dir)

    def ask_for_options(self):
        options = self.options
        super(ReplicaPrepare, self).ask_for_options()

        # get the directory manager password
        self.dirman_password = options.password
        if not options.password:
            self.dirman_password = installutils.read_password(
                "Directory Manager (existing master)",
                confirm=False, validate=False)
            if self.dirman_password is None:
                raise admintool.ScriptError(
                    "Directory Manager password required")

        # Try out the password
        try:
            conn = ldap2(shared_instance=False)
            conn.connect(bind_dn=DN(('cn', 'directory manager')),
                         bind_pw=self.dirman_password)
            conn.disconnect()
        except errors.ACIError:
            raise admintool.ScriptError("The password provided is incorrect "
                "for LDAP server %s" % api.env.host)
        except errors.LDAPError:
            raise admintool.ScriptError(
                "Unable to connect to LDAP server %s" % api.env.host)
        except errors.DatabaseError, e:
            raise admintool.ScriptError(e.desc)

        # Validate more options using the password
        try:
            installutils.verify_fqdn(self.replica_fqdn, local_hostname=False)
        except installutils.BadHostError, e:
            msg = str(e)
            if isinstance(e, installutils.HostLookupError):
                if options.ip_address is None:
                    if dns_container_exists(
                            api.env.host, api.env.basedn,
                            dm_password=self.dirman_password,
                            ldapi=True, realm=api.env.realm):
                        self.log.info('Add the --ip-address argument to '
                            'create a DNS entry.')
                    raise
                else:
                    # The host doesn't exist in DNS but we're adding it.
                    pass
            else:
                raise

        if options.ip_address:
            if not dns_container_exists(api.env.host, api.env.basedn,
                                        dm_password=self.dirman_password,
                                        ldapi=True, realm=api.env.realm):
                raise admintool.ScriptError("You can't add a DNS record "
                    "because DNS is not set up.")
            if options.reverse_zone and not bindinstance.verify_reverse_zone(
                    options.reverse_zone, options.ip_address):
                raise admintool.ScriptError("Invalid reverse zone")

        if (not certs.ipa_self_signed() and
                not ipautil.file_exists(
                    dogtag.configured_constants().CS_CFG_PATH) and
                not options.dirsrv_pin):
            self.log.info("If you installed IPA with your own certificates "
                "using PKCS#12 files you must provide PKCS#12 files for any "
                "replicas you create as well.")
            raise admintool.ScriptError("The replica must be created on the "
                "primary IPA server.")

    def run(self):
        options = self.options
        super(ReplicaPrepare, self).run()

        self.log.info("Preparing replica for %s from %s",
            self.replica_fqdn, api.env.host)
        enable_replication_version_checking(api.env.host, api.env.realm,
            self.dirman_password)

        subject_base = self.get_subject_base(
            api.env.host, self.dirman_password,
            ipautil.realm_to_suffix(api.env.realm))

        top_dir = tempfile.mkdtemp("ipa")
        info_dir = top_dir + "/realm_info"
        os.mkdir(info_dir, 0700)

        passwd_fname = os.path.join(info_dir, "dirsrv_pin.txt")
        with open(passwd_fname, "w") as fd:
            fd.write("%s\n" % (options.dirsrv_pin or ''))

    def get_subject_base(self, host_name, dm_password, suffix):
        try:
            conn = ldap2(shared_instance=False, base_dn=suffix)
            conn.connect(
                bind_dn=DN(('cn', 'directory manager')), bind_pw=dm_password)
        except errors.ExecutionError, e:
            self.log.critical(
                "Could not connect to the Directory Server on %s", host_name)
            raise e
        dn, entry_attrs = conn.get_ipa_config()
        conn.disconnect()
        subject_base = entry_attrs.get('ipacertificatesubjectbase', [None])[0]
        if subject_base is not None:
            subject_base = DN(subject_base)
        return subject_base
