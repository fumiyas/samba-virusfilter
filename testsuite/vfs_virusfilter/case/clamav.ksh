T_virusfilter_module_name="virusfilter-clamav"
T_scanner_name="clamd"
T_scanner_pid=""

. "$TEST_case_dir/common.ksh"

function tc_all
{
  tcs_common
  tcs_scanner_socket
}

