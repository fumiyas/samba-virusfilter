#!/bin/ksh

function tc_init
{
  rm -rf "$TEST_tmp_dir/$T_scanner_name" \
    || exit 1
  "$TEST_bin_dir/$T_scanner_name-svconf.cmd" "$TEST_tmp_dir/$T_scanner_name" \
    || exit 1
  echo "$TEST_sysconf_dir/$T_scanner_name.conf.test" \
    >"$TEST_tmp_dir/$T_scanner_name/env/CONFIGFILE" \
    || exit 1

  test_at_exit 'tcu_scanner_stop'
  tcu_scanner_start
}

function tc_reset
{
  tu_smb_conf_append_virusfilter_option "socket path = $TEST_tmp_dir/$T_scanner_name.socket${T_scanner_socket_suffix-}"
}

## ======================================================================

function tcu_scanner_start
{
  tcu_scanner_stop

  test_verbose 1 "Starting $T_scanner_name ..."
  (
    cd "$TEST_tmp_dir/$T_scanner_name" || exit 1
    exec ./run >>"$TEST_log_dir/$T_scanner_name-run.log"
  ) &
  T_scanner_pid="$!"

  sleep 5
  kill -0 "$T_scanner_pid" || test_abort "$0: Starting $T_scanner_name failed"
}

function tcu_scanner_stop
{
  [ -z "$T_scanner_pid" ] && return

  test_verbose 1 "Stopping $T_scanner_name ..."
  kill "$T_scanner_pid"
  wait "$T_scanner_pid"
  T_scanner_pid=""
}

function tcu_scanner_pause
{
  [ -z "$T_scanner_pid" ] && return

  test_verbose 1 "Pausing $T_scanner_name ..."
  kill -STOP "$T_scanner_pid"
}

function tcu_scanner_continue
{
  [ -z "$T_scanner_pid" ] && return

  test_verbose 1 "Continuing $T_scanner_name ..."
  kill -CONT "$T_scanner_pid"
}

## ======================================================================

function tc_basic
{
  typeset tc=""

  test_verbose 0 "Testing basic function"
  tu_reset
  tcx_connect_share "$tc"
  tcx_get_safe_file "$tc"
  tcx_get_safe_file "$tc" --filename-suffix "$T_file_excluded_suffix"
  tcx_get_virus_file "$tc"
  tcx_get_virus_file "$tc" --filename-suffix "$T_file_excluded_suffix"
  tcx_get_safe_files_on_a_session "$tc"
  tcx_get_safe_files_on_a_session "$tc" --filename-suffix "$T_file_excluded_suffix"
  tcx_get_virus_files_on_a_session "$tc"
  tcx_get_virus_files_on_a_session "$tc" --filename-suffix "$T_file_excluded_suffix"
}

function tc_option_exclude_files
{
  typeset tc="exclude files"

  test_verbose 0 "Testing 'exclude files' option"
  tu_reset
  tu_smb_conf_append_virusfilter_option "exclude files = /dummy.*/*$T_file_excluded_suffix/dummy.*/"
  tcx_connect_share "$tc"
  tcx_get_safe_file "$tc"
  tcx_get_safe_file "$tc" --filename-suffix "$T_file_excluded_suffix"
  tcx_get_virus_file "$tc" --exclude-files "*$T_file_excluded_suffix"
  tcx_get_virus_file "$tc" --exclude-files "*$T_file_excluded_suffix" --filename-suffix "$T_file_excluded_suffix"
  tcx_get_safe_files_on_a_session "$tc"
  tcx_get_safe_files_on_a_session "$tc" --filename-suffix "$T_file_excluded_suffix"
  tcx_get_virus_files_on_a_session "$tc" --exclude-files "*$T_file_excluded_suffix"
  tcx_get_virus_files_on_a_session "$tc" --exclude-files "*$T_file_excluded_suffix" --filename-suffix "$T_file_excluded_suffix"
}

function tc_option_minmax_file_size
{
  typeset tc="min/max file size"

  test_verbose 0 "Testing 'min/max file size' option"
  tu_reset
  tu_smb_conf_append_virusfilter_option "min file size = $T_min_file_size"
  tu_smb_conf_append_virusfilter_option "max file size = $T_max_file_size"
  tcx_connect_share "$tc"
  tcx_get_safe_file "$tc"
  tcx_get_safe_file "$tc" --filename-suffix "$T_file_excluded_suffix"
  tcx_get_virus_file "$tc" --min-file-size "$T_min_file_size" --max-file-size "$T_max_file_size"
  tcx_get_virus_file "$tc" --min-file-size "$T_min_file_size" --max-file-size "$T_max_file_size" --filename-suffix "$T_file_excluded_suffix"
  tcx_get_safe_files_on_a_session "$tc"
  tcx_get_safe_files_on_a_session "$tc" --filename-suffix "$T_file_excluded_suffix"
  tcx_get_virus_files_on_a_session "$tc" --min-file-size "$T_min_file_size" --max-file-size "$T_max_file_size"
  tcx_get_virus_files_on_a_session "$tc" --min-file-size "$T_min_file_size" --max-file-size "$T_max_file_size" --filename-suffix "$T_file_excluded_suffix"
}

function tc_option_infected_file_action_nothing
{
  typeset tc="infected file action = nothing"

  test_verbose 0 "Testing 'infected file action = none' option"
  tu_reset
  tu_smb_conf_append_virusfilter_option "infected file action = nothing"
  tcx_get_virus_file "$tc" --infected-file-action nothing
  tcx_get_virus_files_on_a_session "$tc" --infected-file-action nothing
}

function tc_option_infected_file_action_delete
{
  typeset tc="infected file action = delete"

  test_verbose 0 "Testing 'infected file action = delete' option"
  tu_reset
  tu_smb_conf_append_virusfilter_option "infected file action = delete"
  tcx_get_virus_file "$tc" --infected-file-action delete
  tu_reset
  tu_smb_conf_append_virusfilter_option "infected file action = delete"
  tcx_get_virus_files_on_a_session "$tc" --infected-file-action delete
}

function tc_option_infected_file_action_quarantine
{
  typeset tc="infected file action = quarantine"

  test_verbose 0 "Testing 'infected file action = quarantine' option"
  tu_reset
  tu_smb_conf_append_virusfilter_option "infected file action = quarantine"
  tcx_get_virus_file "$tc" --infected-file-action quarantine
  tu_reset
  tu_smb_conf_append_virusfilter_option "infected file action = quarantine"
  tcx_get_virus_files_on_a_session "$tc" --infected-file-action quarantine
}

function tc_option_infected_file_command
{
  typeset tc="infected file command"

  test_verbose 0 "Testing 'infected file command' option"
  tu_reset
  typeset command_out="$TEST_tmp_dir/command.out"
  tu_smb_conf_append_virusfilter_option "infected file command = sh -c 'env >>$command_out'"
  tcx_get_virus_file "$tc" --infected-file-command-env-out "$command_out"
}

function tc_option_scan_limit
{
  typeset tc="scan limit"

  test_verbose 0 "Testing 'scan limit' option"
  tu_reset
  tu_smb_conf_append_virusfilter_option "scan limit = 2"
  tcx_get_safe_files_on_a_session "$tc"
  tcx_get_virus_files_on_a_session "$tc"
}

function tc_option_scanner_timeout
{
  typeset tc="io timeout (no block access)"

  test_verbose 0 "Testing 'connect/io timeout' option (no block access)"
  tu_reset
  tcu_scanner_pause
  tu_smb_conf_append_virusfilter_option "connect timeout = 1000" ## msec
  tu_smb_conf_append_virusfilter_option "io timeout = 1000" ## msec

  tcx_connect_share "$tc"
  tcx_get_safe_file "$tc"
  tcx_get_virus_file "$tc" --no-failure

  typeset tc="io timeout (block access)"

  tu_smb_conf_append_virusfilter_option "block access on error = yes"

  test_verbose 0 "Testing 'connect/io timeout' option (block access)"
  tcx_connect_share "$tc"
  tcx_get_safe_file "$tc" --fail-with ACCESS_DENIED
  tcx_get_virus_file "$tc"

  tcu_scanner_continue
}

function tc_option_scan_error_command
{
  typeset tc="scan error command"

  test_verbose 0 "Testing 'scan error command' option"
  tu_reset
  tcu_scanner_pause
  tu_smb_conf_append_virusfilter_option "connect timeout = 1" ## msec
  tu_smb_conf_append_virusfilter_option "io timeout = 1" ## msec

  typeset command_out="$TEST_tmp_dir/command.out"
  tu_smb_conf_append_virusfilter_option "scan error command = sh -c 'env >>$command_out'"
  tcx_get_safe_file "$tc" --scan-error-command-env-out "$command_out"

  tcu_scanner_continue
}

function tc_option_cache_time_limit
{
  typeset tc="cache time limit"

  test_verbose 0 "Testing 'cache time limit' option"
  tu_reset

  tu_smb_conf_append_virusfilter_option "cache time limit = 999"
  tcx_get_safe_file "$tc" --get-count 2

  tu_smb_conf_append_virusfilter_option "cache time limit = 1"
  tcx_get_safe_file "$tc exceeded" --get-count 2 --get-count-interval 2
}

function tc_option_cache_entry_limit
{
  typeset tc="cache entry limit"

  test_verbose 0 "Testing 'cache entry limit' option"
  tu_reset

  typeset limit
  for limit in 1 5 1000; do
    tu_smb_conf_append_virusfilter_option "cache entry limit = $limit"
    tcx_get_safe_files_on_a_session "$tc=$limit"
    tcx_get_safe_files_on_a_session "$tc=$limit, 2 times" \
      --file-size-list "$T_file_size_list $T_file_size_list"
    tcx_get_safe_files_on_a_session "$tc=$limit, 2 times in series" \
      --file-size-list "`echo $T_file_size_list $T_file_size_list |tr ' ' '\n' |sort -n`"
    tcx_get_virus_files_on_a_session "$tc=$limit"
    tcx_get_virus_files_on_a_session "$tc=$limit, 2 times" \
      --file-size-list "$T_file_size_list $T_file_size_list"
    tcx_get_virus_files_on_a_session "$tc=$limit, 2 times in series" \
      --file-size-list "`echo $T_file_size_list $T_file_size_list |tr ' ' '\n' |sort -n`"
  done
}

## ======================================================================

function tcs_common
{
  tc_basic
  tc_option_exclude_files
  tc_option_minmax_file_size
  tc_option_infected_file_action_nothing
  tc_option_infected_file_action_delete
  tc_option_infected_file_action_quarantine
  tc_option_infected_file_command
  tc_option_scan_error_command
  tc_option_cache_time_limit
}

function tcs_scanner_socket
{
  tc_option_scanner_timeout
}


## ======================================================================

function tcx_connect_share
{
  typeset comment="$1"; shift
  typeset out

  out=$(
    print -r "ls \"$T_file_marker\"" \
    |tu_smbclient
  )
  test_assert_match "$out" "*$T_file_marker*" "Connecting to share${comment:+ ($comment)}"
}

function tcx_get_safe_file
{
  typeset comment="$1"; shift
  typeset out file size

  typeset opt
  typeset suffix=""
  typeset fail_with=""
  typeset get_count="1"
  typeset get_count_interval="0"
  typeset scan_error_command_env_out=""
  typeset hostname=$(hostname |sed 's/\..*//')
  typeset -u hostname_upper="$hostname"
  while [ "$#" -gt 0 ]; do
    opt="$1"; shift
    case "$opt" in
    --filename-suffix)
      suffix="$1"; shift
      ;;
    --fail-with)
      fail_with="$1"; shift
      ;;
    --get-count)
      get_count="$1"; shift
      ;;
    --get-count-interval)
      get_count_interval="$1"; shift
      ;;
    --scan-error-command-env-out)
      scan_error_command_env_out="$1"; shift
      ;;
    *)
      test_abort "$0: Invalid option: $opt"
      ;;
    esac
  done

  for size in $T_file_size_list; do
    if [ -n "$scan_error_command_env_out" ]; then
      rm -f "$scan_error_command_env_out"
    fi

    file="$T_file_prefix.$size$suffix"
    out=$(
      while [ $get_count -gt 0 ]; do
	print -r "get \"$file\" /dev/null"
	if [ "$get_count" -gt 1 ] && [ "$get_count_interval" -gt 0 ]; then
	  sleep "$get_count_interval"
	fi
	let get_count-=1
      done \
      |tu_smbclient
    )
    if [ -z "$fail_with" ]; then
      test_assert_empty "$out" "Getting SAFE file is OK${comment:+ ($comment)}: $file"
    else
      test_assert_match "$out" "NT_STATUS_$fail_with *" \
	"Getting SAFE file is DENIED${comment:+ ($comment)}: $file"
    fi

    if [ -n "$scan_error_command_env_out" ]; then
      [ -f "$scan_error_command_env_out" ]
      test_assert_zero "$?" \
	"Scan error triggers external command${comment:+ ($comment)}: $file"

      env_ok=
      sed -n '/^VIRUSFILTER_/p' "$scan_error_command_env_out" \
      |sort \
      |for env_expected in \
	VIRUSFILTER_CLIENT_IP="127.0.0.1" \
	VIRUSFILTER_CLIENT_NAME="127.0.0.1" \
	VIRUSFILTER_CLIENT_NETBIOS_NAME="$hostname" \
	VIRUSFILTER_MODULE_NAME="$T_virusfilter_module_name" \
	VIRUSFILTER_SCAN_ERROR_REPORT="*" \
	VIRUSFILTER_SCAN_ERROR_SERVICE_FILE_PATH="$file" \
	VIRUSFILTER_SERVER_IP="127.0.0.1" \
	VIRUSFILTER_SERVER_NAME="$hostname" \
	VIRUSFILTER_SERVER_NETBIOS_NAME="127.0.0.1" \
	VIRUSFILTER_SERVER_PID="[0-9]*" \
	VIRUSFILTER_SERVICE_NAME="$T_samba_share_name" \
	VIRUSFILTER_SERVICE_PATH="$T_samba_share_dir" \
	VIRUSFILTER_USER_DOMAIN="$hostname_upper" \
	VIRUSFILTER_USER_NAME="nobody" \
	VIRUSFILTER_VERSION="$T_virusfilter_version" \
	END \
	; do
	read -r env
	test_verbose 3 "Env got:      [$env]"
	test_verbose 3 "Env expected: [$env_expected]"
	if [ X"$env_expected" = X"END" ] && [ -z "$env" ]; then
	  env_ok="yes"
	fi
	case "$env" in
	$env_expected)
	  test_verbose 3 "Env matched"
	  ;;
	*)
	  test_verbose 3 "Env mismatched"
	  cat >/dev/null
	  break
	  ;;
	esac
      done
      test_assert_eq "$env_ok" "yes" "'scan error command' gets VIRUSFILTER_* environment vars: $file"
    fi
  done
}

function tcx_get_virus_file
{
  typeset comment="$1"; shift
  typeset out file size

  typeset opt
  typeset suffix=""
  typeset exclude_files=""
  typeset min_file_size=""
  typeset max_file_size=""
  typeset infected_file_action=""
  typeset infected_file_command_env_out=""
  typeset no_failure=""
  typeset env env_expected env_ok
  typeset hostname=$(hostname |sed 's/\..*//')
  typeset -u hostname_upper="$hostname"
  typeset q_num=0 q_num_prev
  while [ "$#" -gt 0 ]; do
    opt="$1"; shift
    case "$opt" in
    --filename-suffix)
      suffix="$1"; shift
      ;;
    --exclude-files)
      exclude_files="$1"; shift
      ;;
    --min-file-size)
      min_file_size="$1"; shift
      ;;
    --max-file-size)
      max_file_size="$1"; shift
      ;;
    --infected-file-action)
      infected_file_action="$1"; shift
      ;;
    --infected-file-command-env-out)
      infected_file_command_env_out="$1"; shift
      ;;
    --no-failure)
      no_failure="set"
      ;;
    *)
      test_abort "$0: Invalid option: $opt"
      ;;
    esac
  done

  for size in $T_file_size_list; do
    if [ -n "$infected_file_command_env_out" ]; then
      rm -f "$infected_file_command_env_out"
    fi

    file="$T_file_virus.$size$suffix"
    out=$(
      print -r "get \"$file\" /dev/null" \
      |tu_smbclient
    )

    typeset assert_empty=""
    [ -n "$no_failure" ] && assert_empty="set"
    [ -n "$min_file_size" ] && [ "$size" -lt "$min_file_size" ] && assert_empty="set"
    [ -n "$max_file_size" ] && [ "$size" -gt "$max_file_size" ] && assert_empty="set"
    [ -n "$exclude_files" ] && [ "$file" != "${file#$exclude_files}" ] && assert_empty="set"
    if [ -n "$assert_empty" ]; then
      test_assert_empty "$out" \
	"Getting VIRUS file is OK${comment:+ ($comment)}: $file"
      continue
    fi

    test_assert_match "$out" 'NT_STATUS_ACCESS_DENIED *' \
      "Getting VIRUS file is DENIED${comment:+ ($comment)}: $file"

    if [ -n "$infected_file_action" ]; then
      case "$infected_file_action" in
      quarantine|delete)
	[ -f "$T_samba_share_dir/$file" ]
	test_assert_not_zero "$?" \
	  "VIRUS file is DISAPPEARED${comment:+ ($comment)}: $file"
	;;
      nothing)
	[ -f "$T_samba_share_dir/$file" ]
	test_assert_zero "$?" \
	  "VIRUS file is NOT DISAPPEARED${comment:+ ($comment)}: $file"
	;;
      *)
	test_abort "Invalid infected file action: $infected_file_action"
	;;
      esac

      q_num_prev="$q_num"
      q_num=$(test_exec ls "$T_quarantine_dir/" 2>/dev/null |wc -l)
      case "$infected_file_action" in
      quarantine)
	test_assert_eq "$q_num" $((q_num_prev + 1)) \
	  "VIRUS file is QUARANTINED${comment:+ ($comment)}: $file"
	;;
      nothing|delete)
	test_assert_eq "$q_num" "$q_num_prev" \
	  "VIRUS file is NOT QUARANTINED${comment:+ ($comment)}: $file"
	;;
      *)
	test_abort "Invalid infected file action: $infected_file_action"
	;;
      esac
    fi

    if [ -n "$infected_file_command_env_out" ]; then
      [ -f "$infected_file_command_env_out" ]
      test_assert_zero "$?" \
	"VIRUS file triggers external command${comment:+ ($comment)}: $file"

      env_ok=
      sed -n '/^VIRUSFILTER_/p' "$infected_file_command_env_out" \
      |sort \
      |for env_expected in \
	VIRUSFILTER_CLIENT_IP="127.0.0.1" \
	VIRUSFILTER_CLIENT_NAME="127.0.0.1" \
	VIRUSFILTER_CLIENT_NETBIOS_NAME="$hostname" \
	VIRUSFILTER_INFECTED_FILE_ACTION="${infected_file_action:-nothing}" \
	VIRUSFILTER_INFECTED_FILE_REPORT="*" \
	VIRUSFILTER_INFECTED_SERVICE_FILE_PATH="$file" \
	VIRUSFILTER_MODULE_NAME="$T_virusfilter_module_name" \
	VIRUSFILTER_SERVER_IP="127.0.0.1" \
	VIRUSFILTER_SERVER_NAME="$hostname" \
	VIRUSFILTER_SERVER_NETBIOS_NAME="127.0.0.1" \
	VIRUSFILTER_SERVER_PID="[0-9]*" \
	VIRUSFILTER_SERVICE_NAME="$T_samba_share_name" \
	VIRUSFILTER_SERVICE_PATH="$T_samba_share_dir" \
	VIRUSFILTER_USER_DOMAIN="$hostname_upper" \
	VIRUSFILTER_USER_NAME="nobody" \
	VIRUSFILTER_VERSION="$T_virusfilter_version" \
	END \
	; do
	read -r env
	test_verbose 3 "Env got:      [$env]"
	test_verbose 3 "Env expected: [$env_expected]"
	if [ X"$env_expected" = X"END" ] && [ -z "$env" ]; then
	  env_ok="yes"
	fi
	case "$env" in
	$env_expected)
	  : OK
	  ;;
	*)
	  cat >/dev/null
	  break
	  ;;
	esac
      done
      test_assert_eq "$env_ok" "yes" "'infected file command' gets VIRUSFILTER_* environment vars: $file"
    fi
  done
}

function tcx_get_safe_files_on_a_session
{
  typeset comment="$1"; shift
  typeset out file size

  typeset opt
  typeset size_list="$T_file_size_list"
  typeset suffix=""
  while [ "$#" -gt 0 ]; do
    opt="$1"; shift
    case "$opt" in
    --file-size-list)
      size_list="$1"; shift
      ;;
    --filename-suffix)
      suffix="$1"; shift
      ;;
    *)
      test_abort "$0: Invalid option: $opt"
      ;;
    esac
  done

  out=$(
    for size in $size_list; do
      file="$T_file_prefix.$size$suffix"
      print -r "get \"$file\" /dev/null"
    done \
    |tu_smbclient
  )

  test_assert_empty "$out" \
    "Getting MULTIPLE SAFE files is OK on A SESSION${comment:+ ($comment)}: $T_file_prefix.*$suffix"
}

function tcx_get_virus_files_on_a_session
{
  typeset comment="$1"; shift
  typeset out file size
  typeset file_num deneied_num unknown_num

  typeset opt
  typeset size_list="$T_file_size_list"
  typeset suffix=""
  typeset exclude_files=""
  typeset min_file_size=""
  typeset max_file_size=""
  typeset infected_file_action=""
  while [ "$#" -gt 0 ]; do
    opt="$1"; shift
    case "$opt" in
    --file-size-list)
      size_list="$1"; shift
      ;;
    --filename-suffix)
      suffix="$1"; shift
      ;;
    --exclude-files)
      exclude_files="$1"; shift
      ;;
    --min-file-size)
      min_file_size="$1"; shift
      ;;
    --max-file-size)
      max_file_size="$1"; shift
      ;;
    --infected-file-action)
      infected_file_action="$1"; shift
      ;;
    *)
      test_abort "$0: Invalid option: $opt"
      ;;
    esac
  done

  out=$(
    for size in $size_list; do
      file="$T_file_virus.$size$suffix"
      print -r "get \"$file\" /dev/null"
    done \
    |tu_smbclient
  )

  typeset excluded_num=0
  for size in $size_list; do
    file="$T_file_virus.$size$suffix"
    typeset excluded=
    [ -n "$min_file_size" ] && [ "$size" -lt "$min_file_size" ] && excluded="yes"
    [ -n "$max_file_size" ] && [ "$size" -gt "$max_file_size" ] && excluded="yes"
    [ -n "$exclude_files" ] && [ "$file" != "${file#$exclude_files}" ] && excluded="yes"
    if [ -n "$excluded" ]; then
      let excluded_num+=1
    fi
  done

  file_num=$(set -- $size_list; echo $#)
  deneied_num=$(print -nr "$out" |grep '^NT_STATUS_ACCESS_DENIED ' |wc -l)
  unknown_num=$(print -nr "$out" |grep -v '^NT_STATUS_ACCESS_DENIED ' |wc -l)
  [ "$deneied_num" -eq $((file_num - excluded_num)) ] && [ "$unknown_num" -eq 0 ]
  test_assert_zero "$?" "Getting MULTIPLE VIRUS files is DENIED on A SESSION${comment:+ ($comment)}: $T_file_virus.*$suffix"
}

