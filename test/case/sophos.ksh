T_svf_module_name="svf-sophos"

. "$TEST_case_dir/common.ksh"

function tc_init
{
  rm -rf "$TEST_tmp_dir/savdid" \
    || exit 1
  "$TEST_bin_dir/savdid-svconf.cmd" "$TEST_tmp_dir/savdid" \
    || exit 1
  echo "$TEST_sysconf_dir/savdid.conf.test" >"$TEST_tmp_dir/savdid/env/CONFIGFILE" \
    || exit 1

  test_verbose 1 "Starting savdid ..."
  (cd "$TEST_tmp_dir/savdid" && exec ./run >"$TEST_log_dir/savdid-run.log") &
  test_at_exit "kill $!"
}

function tc_reset
{
  echo "$T_svf_module_name: socket path = $TEST_tmp_dir/sssp.sock" \
    >>"$T_smb_conf_file" \
    || exit 1
}

function tc_run
{
  tcx_common
  ## FIXME: Extra test case for savdid specific options
}

