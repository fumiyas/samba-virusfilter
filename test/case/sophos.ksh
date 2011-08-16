T_svf_module_name="svf-sophos"
T_savdid_pid=""

. "$TEST_case_dir/common.ksh"

function tc_init
{
  rm -rf "$TEST_tmp_dir/savdid" \
    || exit 1
  "$TEST_bin_dir/savdid-svconf.cmd" "$TEST_tmp_dir/savdid" \
    || exit 1
  echo "$TEST_sysconf_dir/savdid.conf.test" >"$TEST_tmp_dir/savdid/env/CONFIGFILE" \
    || exit 1

  test_at_exit 'tcu_savdid_stop'
  tcu_savdid_start
}

function tc_reset
{
  echo "$T_svf_module_name: socket path = $TEST_tmp_dir/sssp.sock" \
    >>"$T_smb_conf_file" \
    || exit 1
}

function tc_all
{
  tcx_common
  ## FIXME: Extra test case for savdid specific options
}

function tcu_savdid_start
{
  tcu_savdid_stop

  test_verbose 1 "Starting savdid ..."
  (cd "$TEST_tmp_dir/savdid" && exec ./run >"$TEST_log_dir/savdid-run.log") &
  T_savdid_pid="$!"

  sleep 1
  kill -0 "$T_savdid_pid" || test_abort "$0: Starting savdid failed"
}

function tcu_savdid_stop
{
  [ -z "$T_savdid_pid" ] && return

  test_verbose 1 "Stopping savdid ..."
  kill "$T_savdid_pid"
  wait "$T_savdid_pid"
  T_savdid_pid=""
}

