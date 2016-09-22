#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "all possible legal levels, including some abbreviations"

debug_set_result ()
{
	case "$1" in
	0|ERR*)   ok "ERROR" ;;
	1|WARN*)  ok "WARNING" ;;
	2|NOTICE) ok "NOTICE" ;;
	3|INFO)   ok "INFO" ;;
	4|DEBUG)  ok "DEBUG" ;;
	*) required_result 42 "foo" ;;
	esac
}

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

for i in "ERROR" "WARNING" "NOTICE" "INFO" "DEBUG" 0 1 2 3 4 "ERR" "WARN" ; do
	ok_null
	simple_test "$i"

	debug_set_result "$i"
	simple_test_other getdebug
done
