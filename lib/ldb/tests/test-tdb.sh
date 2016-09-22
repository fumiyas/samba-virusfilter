#!/bin/sh

BINDIR=$1

if [ -n "$TEST_DATA_PREFIX" ]; then
	LDB_URL="$TEST_DATA_PREFIX/tdbtest.ldb"
	PYDESTDIR="$TEST_DATA_PREFIX"
else
	LDB_URL="tdbtest.ldb"
fi
export LDB_URL

PATH=$BINDIR:$PATH
export PATH

if [ -z "$LDBDIR" ]; then
    LDBDIR=`dirname $0`/..
    export LDBDIR
fi

cd $LDBDIR

rm -f $LDB_URL*

cat <<EOF | $VALGRIND ldbadd || exit 1
dn: @MODULES
@LIST: rdn_name
EOF

$VALGRIND ldbadd $LDBDIR/tests/init.ldif || exit 1

. $LDBDIR/tests/test-generic.sh

. $LDBDIR/tests/test-extended.sh

. $LDBDIR/tests/test-tdb-features.sh

. $LDBDIR/tests/test-controls.sh
