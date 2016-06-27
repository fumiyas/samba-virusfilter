Samba-VirusFilter - On-access anti-virus filter for Samba
======================================================================

  * Copyright (C) 2010-2015 SATOH Fumiyasu @ OSS Technology Corp., Japan
  * License: GNU General Public License version 3
  * Development home: <https://github.com/fumiyas/samba-virusfilter>
  * Author's home: <https://fumiyas.github.io/>

What's this?
---------------------------------------------------------------------

This is a set of various Samba VFS modules to scan and filter virus
files on Samba file services with an anti-virus scanner.

This software is freely distributable under the GNU public license, a
copy of which you should have received with this software (in a file
called COPYING).

For installation instructions, please refer to the INSTALL file.

Supported Anti-Virus engines
---------------------------------------------------------------------

  * ClamAV (clamd daemon)
    http://www.clamav.net/
  * F-Secure Anti-Virus (fsavd daemon)
    http://www.f-secure.com/
  * Sophos Anti-Virus (savdid daemon)
    http://www.sophos.com/

Downloads
---------------------------------------------------------------------

  https://bitbucket.org/fumiyas/samba-virusfilter/downloads

Commercial support for Samba & Samba-VirusFilter
---------------------------------------------------------------------

  * Japan
    * Open Source Solution Technology Corp., Japan  
      http://www.OSSTech.co.jp/

Contributors
---------------------------------------------------------------------

  * Luke Dixon <luke.dixon@zynstra.com>
    * Samba 4 support

TODO
---------------------------------------------------------------------

For Samba 4 integration / inclusion:

  * More enhancements, fixes and others for Samba 4.x and
    remove Samba 3.x support
  * Use and add test suite in Samba source
  * Write manpages
  * Replace own "stupid" result cache implementation with
    Samba memcache implementation or another

For general:

  * Remove a cache entry on close if file was modified
    when `svf-*:scan on open = yes` and `svf-*:scan on close = no`
  * Support other anti-virus engines:
    * External command
    * misc.
  * More test cases
    * Use Bats? (https://github.com/sstephenson/bats)
  * clamd privileges (root or group that has rights to access Samba shares)

