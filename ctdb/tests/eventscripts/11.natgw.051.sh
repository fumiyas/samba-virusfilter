#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Monitor CTDB_NATGW_PUBLIC_IFACE, slave, up"

setup_ctdb
setup_ctdb_natgw <<EOF
192.168.1.21
192.168.1.22 master
192.168.1.23
192.168.1.24
EOF

ok_null
simple_test_event "monitor"
