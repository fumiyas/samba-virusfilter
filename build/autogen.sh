#!/bin/sh

set -u
set -e

rm -rf autom4te*.cache

autoheader
autoconf

cp build/subst.in.pl build/subst.in
sed -n \
  -e "s/^/ /;s/$/ /;s/'/ ' /" \
  -e "/^ ac_subst_vars=/,/'/s/^.* \([A-Za-z_][A-Za-z0-9_]*\) .*/\1=@\1@/p" \
  configure \
  >>build/subst.in

rm -rf autom4te*.cache

