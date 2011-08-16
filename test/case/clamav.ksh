T_svf_module_name="svf-clamav"
T_clamd_pid=""

. "$TEST_case_dir/common.ksh"

function tc_init
{
  rm -rf "$TEST_tmp_dir/clamd" \
    || exit 1
  "$TEST_bin_dir/clamd-svconf.cmd" "$TEST_tmp_dir/clamd" \
    || exit 1
  echo "$TEST_sysconf_dir/clamd.conf.test" >"$TEST_tmp_dir/clamd/env/CONFIGFILE" \
    || exit 1

  test_at_exit 'tcu_clamd_stop'
  tcu_clamd_start
}

function tc_reset
{
  echo "$T_svf_module_name: socket path = $TEST_tmp_dir/clamd.socket" \
    >>"$T_smb_conf_file" \
    || exit 1
}

function tc_run
{
  tcx_common
}

function tcu_clamd_start
{
  tcu_clamd_stop

  test_verbose 1 "Starting clamd ..."
  (cd "$TEST_tmp_dir/clamd" && exec ./run >"$TEST_log_dir/clamd-run.log") &
  T_clamd_pid="$!"

  sleep 1
  kill -0 "$TC_savdid_pid" || test_abort "$0: Starting clamd failed"
}

function tcu_clamd_stop
{
  [ -z "$T_clamd_pid" ] && return

  test_verbose 1 "Stopping clamd ..."
  kill "$T_clamd_pid"
  wait "$T_clamd_pid"
  T_clamd_pid=""
}
