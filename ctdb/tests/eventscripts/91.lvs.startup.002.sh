#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "configured"

setup_ctdb
setup_ctdb_lvs "10.1.1.201" "eth0" <<EOF
EOF

ok_null
simple_test

check_ipvsadm NULL
check_lvs_ip "host"
