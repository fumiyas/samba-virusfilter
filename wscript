#!/usr/bin/env python

import sys, os

sys.path.insert(0, "../buildtools/wafsamba")
import wafsamba, samba_version

def configure(conf):
    from samba_utils import TO_LIST

    old_defines = conf.env['defines']
    conf.env['defines'] = {}
    conf.define('PACKAGE_BUGREPORT', '')
    conf.define('PACKAGE_NAME', 'samba-virusfilter')
    conf.define('PACKAGE_STRING', 'samba-virusfilter 0.1.4')
    conf.define('PACKAGE_TARNAME', 'samba-virusfilter')
    conf.define('PACKAGE_URL', '')
    conf.define('PACKAGE_VERSION', '0.1.4')
    conf.define('VARDIR', conf.env['STATEDIR'])

    sambaversion = samba_version.load_version(env=None)
    conf.define('SAMBA_VERSION_NUMBER', int('%d%02d%02d' % (
        sambaversion.MAJOR,
        sambaversion.MINOR,
        sambaversion.RELEASE,
    )))
    conf.write_config_header('include/virusfilter-config.h')
    conf.env['defines'] = old_defines

    conf.ADD_EXTRA_INCLUDES('include')
    conf.env['shared_modules'].extend(TO_LIST('vfs_virusfilter_clamav vfs_virusfilter_fsav vfs_virusfilter_sophos'))
