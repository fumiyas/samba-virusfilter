#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, no LVS, all ok"

setup_lvs <<EOF
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

#####

required_result 255 <<EOF
EOF

simple_test master

#####

required_result 0 <<EOF
EOF

simple_test list

#####

required_result 0 <<EOF
EOF

simple_test status
