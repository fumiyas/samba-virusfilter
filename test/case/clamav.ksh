T_svf_module_name="svf-clamav"

. "$TEST_case_dir/common.ksh"

function tc_init
{
  rm -rf "$TEST_tmp_dir/clamd" \
    || exit 1
  "$TEST_bin_dir/clamd-svconf.cmd" "$TEST_tmp_dir/clamd" \
    || exit 1
  echo "$TEST_sysconf_dir/clamd.conf.test" >"$TEST_tmp_dir/clamd/env/CONFIGFILE" \
    || exit 1

  test_verbose 1 "Starting clamd ..."
  (cd "$TEST_tmp_dir/clamd" && exec ./run >"$TEST_log_dir/clamd-run.log") &
  test_at_exit "kill $!"
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

