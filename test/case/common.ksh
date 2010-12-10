#!/bin/ksh

function tc_common
{
  tc_basic
  tc_option_exclude_files
  tc_option_minmax_file_size
  tc_option_infected_file_action_nothing
  tc_option_infected_file_action_delete
  tc_option_infected_file_action_quarantine
  tc_option_infected_file_command
}

function tc_basic
{
  typeset tc=""

  test_verbose 0 "Testing basic function"
  t_reset
  tc_connect_share "$tc"
  tc_get_safe_file "$tc"
  tc_get_safe_file "$tc" --filename-suffix "$T_file_excluded_suffix"
  tc_get_virus_file "$tc"
  tc_get_virus_file "$tc" --filename-suffix "$T_file_excluded_suffix"
  tc_get_safe_files_on_a_session "$tc"
  tc_get_safe_files_on_a_session "$tc" --filename-suffix "$T_file_excluded_suffix"
  tc_get_virus_files_on_a_session "$tc"
  tc_get_virus_files_on_a_session "$tc" --filename-suffix "$T_file_excluded_suffix"
}

function tc_option_exclude_files
{
  typeset tc="exclude files"

  test_verbose 0 "Testing 'exclude files' option"
  t_reset
  t_smb_conf_append_svf_option "exclude files = /dummy.*/*$T_file_excluded_suffix/dummy.*/"
  tc_connect_share "$tc"
  tc_get_safe_file "$tc"
  tc_get_safe_file "$tc" --filename-suffix "$T_file_excluded_suffix"
  tc_get_virus_file "$tc" --exclude-files "*$T_file_excluded_suffix"
  tc_get_virus_file "$tc" --exclude-files "*$T_file_excluded_suffix" --filename-suffix "$T_file_excluded_suffix"
  tc_get_safe_files_on_a_session "$tc"
  tc_get_safe_files_on_a_session "$tc" --filename-suffix "$T_file_excluded_suffix"
  tc_get_virus_files_on_a_session "$tc" --exclude-files "*$T_file_excluded_suffix"
  tc_get_virus_files_on_a_session "$tc" --exclude-files "*$T_file_excluded_suffix" --filename-suffix "$T_file_excluded_suffix"
}

function tc_option_minmax_file_size
{
  typeset tc="min/max file size"

  test_verbose 0 "Testing 'min/max file size' option"
  t_reset
  t_smb_conf_append_svf_option "min file size = $T_min_file_size"
  t_smb_conf_append_svf_option "max file size = $T_max_file_size"
  tc_connect_share "$tc"
  tc_get_safe_file "$tc"
  tc_get_safe_file "$tc" --filename-suffix "$T_file_excluded_suffix"
  tc_get_virus_file "$tc" --min-file-size "$T_min_file_size" --max-file-size "$T_max_file_size"
  tc_get_virus_file "$tc" --min-file-size "$T_min_file_size" --max-file-size "$T_max_file_size" --filename-suffix "$T_file_excluded_suffix"
  tc_get_safe_files_on_a_session "$tc"
  tc_get_safe_files_on_a_session "$tc" --filename-suffix "$T_file_excluded_suffix"
  tc_get_virus_files_on_a_session "$tc" --min-file-size "$T_min_file_size" --max-file-size "$T_max_file_size"
  tc_get_virus_files_on_a_session "$tc" --min-file-size "$T_min_file_size" --max-file-size "$T_max_file_size" --filename-suffix "$T_file_excluded_suffix"
}

function tc_option_infected_file_action_nothing
{
  typeset tc="infected file action = nothing"

  test_verbose 0 "Testing 'infected file action = none' option"
  t_reset
  t_smb_conf_append_svf_option "infected file action = nothing"
  tc_get_virus_file "$tc" --infected-file-action nothing
  tc_get_virus_files_on_a_session "$tc" --infected-file-action nothing
}

function tc_option_infected_file_action_delete
{
  typeset tc="infected file action = delete"

  test_verbose 0 "Testing 'infected file action = delete' option"
  t_reset
  t_smb_conf_append_svf_option "infected file action = delete"
  tc_get_virus_file "$tc" --infected-file-action delete
  t_reset
  t_smb_conf_append_svf_option "infected file action = delete"
  tc_get_virus_files_on_a_session "$tc" --infected-file-action delete
}

function tc_option_infected_file_action_quarantine
{
  typeset tc="infected file action = quarantine"

  test_verbose 0 "Testing 'infected file action = quarantine' option"
  t_reset
  t_smb_conf_append_svf_option "infected file action = quarantine"
  tc_get_virus_file "$tc" --infected-file-action quarantine
  t_reset
  t_smb_conf_append_svf_option "infected file action = quarantine"
  tc_get_virus_files_on_a_session "$tc" --infected-file-action quarantine
}

function tc_option_infected_file_command
{
  typeset tc="infected file command"

  test_verbose 0 "Testing 'infected file command' option"
  t_reset
  typeset command_out="$TEST_tmp_dir/command.out"
  t_smb_conf_append_svf_option "infected file command = sh -c 'env >>$command_out'"
  tc_get_virus_file "$tc" --infected-file-command-env-out "$command_out"
}

function tc_scan_limit
{
  typeset tc="scan limit"

  test_verbose 0 "Testing 'scan limit' option"
  t_reset
  t_smb_conf_append_svf_option "scan limit = 2"
  tc_get_safe_files_on_a_session "$tc"
  tc_get_virus_files_on_a_session "$tc"
}

## ======================================================================

function tc_connect_share
{
  typeset comment="$1"; shift
  typeset out

  out=$(
    print -r "ls \"$T_file_marker\"" \
    |t_smbclient
  )
  test_assert_match "$out" "*$T_file_marker*" "Connecting to share${comment:+ ($comment)}"
}

function tc_get_safe_file
{
  typeset comment="$1"; shift
  typeset out file size

  typeset opt
  typeset suffix=""
  while [ "$#" -gt 0 ]; do
    opt="$1"; shift
    case "$opt" in
    --filename-suffix)
      suffix="$1"; shift
      ;;
    *)
      test_abort "$0: Invalid option: $opt"
      ;;
    esac
  done

  for size in $T_file_size_list; do
    file="$T_file_prefix.$size$suffix"
    out=$(
      print -r "get \"$file\" /dev/null" \
      |t_smbclient
      )
      test_assert_empty "$out" "Getting SAFE file is OK${comment:+ ($comment)}: $file"
  done
}

function tc_get_virus_file
{
  typeset comment="$1"; shift
  typeset out file size

  typeset opt
  typeset suffix=""
  typeset excluded
  typeset exclude_files=""
  typeset min_file_size=""
  typeset max_file_size=""
  typeset infected_file_action=""
  typeset infected_file_command_env_out=""
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
      |t_smbclient
    )

    excluded=
    [ -n "$min_file_size" ] && [ "$size" -lt "$min_file_size" ] && excluded="yes"
    [ -n "$max_file_size" ] && [ "$size" -gt "$max_file_size" ] && excluded="yes"
    [ -n "$exclude_files" ] && [ "$file" != "${file#$exclude_files}" ] && excluded="yes"
    if [ -n "$excluded" ]; then
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
      sed -n 's/^SVF_//p' "$infected_file_command_env_out" \
      |sort \
      |for env_expected in \
	COMMAND_CLIENT_IP="127.0.0.1" \
	COMMAND_CLIENT_NAME="127.0.0.1" \
	COMMAND_CLIENT_NETBIOS_NAME="$hostname" \
	COMMAND_SERVER_IP="127.0.0.1" \
	COMMAND_SERVER_NAME="$hostname" \
	COMMAND_SERVER_NETBIOS_NAME="127.0.0.1" \
	COMMAND_SERVER_PID="[0-9]*" \
	COMMAND_SERVICE_NAME="$T_samba_share_name" \
	COMMAND_SERVICE_PATH="$T_samba_share_dir" \
	COMMAND_USER_DOMAIN="$hostname_upper" \
	COMMAND_USER_NAME="nobody" \
	INFECTED_FILE_ACTION="${infected_file_action:-nothing}" \
	INFECTED_FILE_REPORT="*" \
	INFECTED_SERVICE_FILE_PATH="$file" \
	MODULE_NAME="$T_svf_module_name" \
	VERSION="$T_svf_version" \
	END \
	; do
	if ! read -r env; then
	  if [ X"$env_expected" = X"END" ]; then
	    env_ok="yes"
	  fi
	  break
	fi
	if [ X"$env_expected" = X"END" ]; then
	  break
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
      test_assert_eq "$env_ok" "yes" "The infected file command gets SVF_* environment vars: $file"
    fi
  done
}

function tc_get_safe_files_on_a_session
{
  typeset comment="$1"; shift
  typeset out file size

  typeset opt
  typeset suffix=""
  while [ "$#" -gt 0 ]; do
    opt="$1"; shift
    case "$opt" in
    --filename-suffix)
      suffix="$1"; shift
      ;;
    *)
      test_abort "$0: Invalid option: $opt"
      ;;
    esac
  done

  out=$(
    for size in $T_file_size_list; do
      file="$T_file_prefix.$size$suffix"
      print -r "get \"$file\" /dev/null"
    done \
    |t_smbclient
  )

  test_assert_empty "$out" \
    "Getting MULTIPLE SAFE files is OK on A SESSION${comment:+ ($comment)}: $T_file_prefix.*$suffix"
}

function tc_get_virus_files_on_a_session
{
  typeset comment="$1"; shift
  typeset out file size
  typeset file_num deneied_num unknown_num

  typeset opt
  typeset suffix=""
  typeset exclude_files=""
  typeset min_file_size=""
  typeset max_file_size=""
  typeset infected_file_action=""
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
    *)
      test_abort "$0: Invalid option: $opt"
      ;;
    esac
  done

  out=$(
    for size in $T_file_size_list; do
      file="$T_file_virus.$size$suffix"
      print -r "get \"$file\" /dev/null"
    done \
    |t_smbclient
  )

  typeset excluded_num=0
  for size in $T_file_size_list; do
    file="$T_file_virus.$size$suffix"
    typeset excluded=
    [ -n "$min_file_size" ] && [ "$size" -lt "$min_file_size" ] && excluded="yes"
    [ -n "$max_file_size" ] && [ "$size" -gt "$max_file_size" ] && excluded="yes"
    [ -n "$exclude_files" ] && [ "$file" != "${file#$exclude_files}" ] && excluded="yes"
    if [ -n "$excluded" ]; then
      let excluded_num++
    fi
  done

  file_num=$(set -- $T_file_size_list; echo $#)
  deneied_num=$(print -nr "$out" |grep '^NT_STATUS_ACCESS_DENIED ' |wc -l)
  unknown_num=$(print -nr "$out" |grep -v '^NT_STATUS_ACCESS_DENIED ' |wc -l)
  [ "$deneied_num" -eq $((file_num - excluded_num)) ] && [ "$unknown_num" -eq 0 ]
  test_assert_zero "$?" "Getting MULTIPLE VIRUS files is DENIED on A SESSION${comment:+ ($comment)}: $T_file_virus.*$suffix"
}

