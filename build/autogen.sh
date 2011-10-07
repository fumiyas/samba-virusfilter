#!/bin/sh

set -u
set -e

rm -rf autom4te*.cache

grep AC_CONFIG_HEADER configure.in >/dev/null && autoheader
autoconf

rm -rf autom4te*.cache

sed -n \
  -e "s/^/ /;s/$/ /;s/'/ ' /" \
  -e "/^ ac_subst_vars=/,/'/s/^.* \([A-Za-z_][A-Za-z0-9_]*\) .*/\1=@\1@/p" \
  configure \
  >build/subst.vars.in

