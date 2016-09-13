T_virusfilter_module_name="virusfilter-fsav"
T_scanner_name="fsavd"
T_scanner_pid=""
T_scanner_socket_suffix="-`id |sed -n 's/^[^=]*=\([0-9]*\).*$/\1/p'`"

. "$TEST_case_dir/common.ksh"

function tc_all
{
  tcs_common
  tcs_scanner_socket
}

