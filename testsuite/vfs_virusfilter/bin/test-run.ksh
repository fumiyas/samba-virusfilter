#!@KSH_COMMAND@
##
## test-run.ksh: Provides a simple framework for writing test scripts
##               (Test::More Perl module clone)
##
## Copyright (C) 2010-2011 SATOH Fumiyasu @ OSS Technology Corp., Japan
## Copyright (C) 2003-2004 SATOH Fumiyasu @ MIRACLE LINUX Corporation
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.
##

set -u
export LC_ALL=C

if [[ -n "${ZSH_VERSION-}" ]] && [[ $(emulate 2>/dev/null) != "ksh" ]]; then
  sh_opts="$-"
  emulate -R ksh
  setopt FUNCTION_ARGZERO
  [[ -z "${sh_opts##*x*}" ]] && set -x
  unset sh_opts
fi

pdie() { echo "$0: ERROR: ${1-}" 1>&2; exit "${2-1}"; }

## Initialization
## ======================================================================

case "$0" in
/*)
  TEST_bin_dir="${0%/*}"
  ;;
*)
  TEST_bin_dir=$(cd "${0%/*}" && pwd)
  if [ $? -ne 0 ]; then
    echo "$0: ERROR: Cannot determine directory" 1>&2
    exit 100
  fi
  ;;
esac

export TEST_dir="${TEST_bin_dir%/*}"
export TEST_sysconf_dir="$TEST_dir/etc"
export TEST_lib_dir="$TEST_dir/lib"
export TEST_log_dir="$TEST_dir/log"
export TEST_tmp_dir="$TEST_dir/tmp"
export TEST_case_dir="$TEST_dir/case"

export PATH="$TEST_bin_dir:$TEST_lib_dir:$TEST_case_dir:$PATH"

## Options
## ======================================================================

CMD_usage="Usage: $0 [OPTIONS] TEST [TEST-OPTIONS]"
CMD_help="$CMD_usage
"

## ======================================================================

. "$TEST_lib_dir/test.ksh"
. "$TEST_lib_dir/package.ksh"

test_configure ${1+"$@"}

. "$TEST_case_file" ${1+"$@"}

## DEBUG: If the -x option is set, enable trace flag on all functions
[ x"${-#*x}" != x"$-" ] && typeset -ft $(typeset +f)

if [ -n "$TEST_list_case" ]; then
  echo all
  typeset +f |sed -n 's/^tc_//p' |egrep -v '^(configure|init|reset|end|all)$'
  exit 0
fi

## ======================================================================

test_init

test_case_configure ${1+"$@"}
test_case_init
test_case_run
test_case_end

test_stats
test_end

