#!/bin/sh

set -u
set -e

rm -rf autom4te*.cache

autoheader
autoconf

rm -rf autom4te*.cache

