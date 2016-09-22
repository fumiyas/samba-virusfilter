#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, missing file on 1"

setup_nodes <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

setup_nodes 1 <<EOF
192.168.20.41
#192.168.20.42
192.168.20.43
EOF

rm "$CTDB_NODES_1"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

required_result 1 <<EOF
Control GET_NODES_FILE failed, ret=-1
ERROR: Failed to get nodes file from node 1
EOF

simple_test
