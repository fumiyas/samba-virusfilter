#!/bin/ksh
##
## test.ksh: Provides a simple framework for writing test scripts
##           (Perl Test::More clone)
##
## Copyright (C) 2010-2011 SATOH Fumiyasu @ OSS Technology, Inc.
## Copyright (C) 2003-2004 SATOH Fumiyasu @ MIRACLE LINUX Corporation
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.
##

## Global variables
## ======================================================================

TEST_output="${TEST_OUTPUT:-}"
TEST_verbose_level="${TEST_VERBOSE_LEVEL:-0}"
TEST_sysconf_dir="${TEST_BIN_DIR:-$PWD/etc}"
TEST_bin_dir="${TEST_BIN_DIR:-$PWD/bin}"
TEST_log_dir="${TEST_LOG_DIR:-$PWD/log}"
TEST_tmp_dir="${TEST_TMP_DIR:-$PWD/tmp}"

##	FD	Purpose
##	==	=======
##	 0	standard input
##	 1	standard output (but redirected to stderr)
##	 2	standard error output
##	 3	free
##	 4	free
##	 5	free
##	 6	free
##	 7	free
##	 8	test output
##	 9	test verbose output (/dev/null by default)
TEST_fd_output=8
TEST_fd_error=9

TEST_configure_args=0

TEST_count=0
TEST_count_ok=0
TEST_count_ng=0
TEST_count_skipped=0

TEST_case_name="all"
TEST_list_case=""

TEST_at_exit=""

## Functions
## ======================================================================

function test_configure
{
  typeset opt

  while [ "$#" -gt 0 ]; do
    opt="$1"; shift
    case "$opt" in
    -v|--verbose)
      if [ "$#" -lt 1 ]; then
	test_abort "Option requires an argument: $opt"
      fi
      TEST_verbose_level="$1"; shift
      ;;
    -c|--case)
      if [ "$#" -lt 1 ]; then
	test_abort "Option requires an argument: $opt"
      fi
      TEST_case_name="$1"; shift
      ;;
    -l|--list-case)
      TEST_list_case="yes"
      ;;
    --)
      break
      ;;
    -*)
      test_abort "Invalid option: $opt"
      ;;
    *)
      set -- "$opt" ${1+"$@"}
      break
      ;;
    esac
  done

  if [ $# -lt 1 ]; then
    test_abort "No test case file specified"
  fi

  TEST_case_file="$1"; shift
  if [ ! -e "$TEST_case_file" ]; then
    test_abort "Test case file not found: $TEST_case_file"
  fi
}

function test_init
{
  TEST_count=0
  TEST_count_ok=0
  TEST_count_ng=0
  TEST_count_skipped=0

  export TMP="$TEST_tmp_dir"
  export TMPDIR="$TEST_tmp_dir"
  export TEMP="$TEST_tmp_dir"

  if type t_init >/dev/null 2>&1; then
    t_init
  fi
}

function test_stats
{
  test_output "Statistics: OK: $TEST_count_ok"
  test_output "Statistics: Not OK: $TEST_count_ng"
  test_output "Statistics: Skipped: $TEST_count_skipped"
  test_output "Statistics: Total: $TEST_count"
}

function test_end
{
  if type t_end >/dev/null 2>&1; then
    t_end
  fi

  test_do_exit

  if [ "$TEST_count_ng" -gt 0 ]; then
    exit 100
  fi

  exit 0
}

function test_at_exit
{
  TEST_at_exit="${TEST_at_exit:+$TEST_at_exit; }$1"
}

function test_do_exit
{
  test_verbose 2 "test_do_exit: $TEST_at_exit"
  $TEST_at_exit
}

## Output error messages
function test_error
{
  eval print -r '"Error: $@"' "1>&$TEST_fd_error"
}

function test_abort
{
  eval print -r '"Abort: $@"' "1>&$TEST_fd_error"

  test_do_exit

  exit 100
}

## Output test results
function test_output
{
  if [ $# -gt 0 ]; then
    eval print -r '"$@"' "1>&$TEST_fd_output"
  else
    eval cat "1>&$TEST_fd_output"
  fi
}

## Output verbose messages
function test_verbose
{
  typeset level="$1"; shift

  if [ "$TEST_verbose_level" -lt "$level" ]; then
    if [ $# -eq 0 ]; then
      cat >/dev/null
    fi
    return
  fi

  if [ $# -gt 0 ]; then
    print -r "$@" |sed 's/^/## /' |test_output
  else
    sed 's/^/## /' |test_output
  fi
}

## Create a temporary file securely and return filename
function test_mktemp
{
  typeset basename="$TEST_tmp_dir/test${1:+.$1}.$$"

  if type mktemp >/dev/null 2>&1; then
    mktemp "$basename.XXXXXX"
  elif type perl >/dev/null 2>&1; then
    perl -e '
      use IO::File;
      for my $try (1..100) {
	my $temp = "$ARGV[0].$try." . sprintf("%x",rand(99999999));
	if (defined(IO::File->new($temp, O_WRONLY|O_CREAT|O_EXCL))) {
	  print "$temp\n";
	  exit(0);
	}
      }
      exit(1);
    ' "$basename"
  else
    test_abort "Cannot find mktemp(1) and perl(1)"
  fi
}

function test_exec
{
  test_verbose 1 "test_exec: exec: $@"

  ## Create a file, redirect FDs from/to the file and remove the file
  ## STDOUT
  typeset stdout_file=$(test_mktemp stdout)
  typeset stderr_file=$(test_mktemp stderr)

  ## Execute the given command-line
  "$@" 1>"$stdout_file" 2>"$stderr_file"
  typeset exec_status=$?

  ## Output the data generated by command
  cat "$stdout_file"
  cat "$stderr_file" 1>&2

  ## Log the data generated by command
  if [ -s "$stdout_file" ]; then
    cat "$stdout_file" |sed 's/^/test_exec: stdout: [/;s/$/]/' |test_verbose 2
  fi
  if [ -s "$stderr_file" ]; then
    cat "$stderr_file" |sed 's/^/test_exec: stderr: [/;s/$/]/' |test_verbose 2
  fi

  rm "$stdout_file" "$stderr_file"

  test_verbose 1 "test_exec: status: $exec_status"

  return "$exec_status"
}

function test_sleep
{
  typeset sec="$1"; shift

  test_verbose 1 "Sleeping $sec second(s) ..."
  while [ "$sec" -gt 0 ]; do
    sleep 1
    let sec--
  done
}

function test_result
{
  typeset result="$1"; shift
  typeset name="$1"; shift

  let TEST_count++

  case "$result" in
  OK)
    let TEST_count_ok++
    ;;
  Skip)
    let TEST_count_skipped++
    ;;
  *)
    let TEST_count_ng++
    ;;
  esac

  test_output "Test $(printf '%4d' $TEST_count): $result: $name"
}

## Skip test(s)
function test_skip
{
  typeset count="$1"; shift
  typeset why="$1"; shift

  while [ $count -gt 0 ]; do
    test_result "skip" "$why"
    let count--
  done
}

## Test if "$1" is qeual to 0
function test_assert_zero
{
  typeset got="$1"; shift
  typeset name="$1"; shift

  if [ x"$got" = x"0" ]; then
    test_result "OK" "$name"
  else
    test_result "Not OK" "$name"
  fi
}

## Test if "$1" is NOT qeual to 0
function test_assert_not_zero
{
  typeset got="$1"; shift
  typeset name="$1"; shift

  if [ x"$got" != x"0" ]; then
    test_result "OK" "$name"
  else
    test_result "Not OK" "$name"
  fi
}

function test_assert_empty
{
  typeset got="$1"; shift
  typeset name="$1"; shift

  if [ x"$got" = x"" ]; then
    test_result "OK" "$name"
  else
    test_result "Not OK" "$name"
  fi
}

## Test if "$1" is equal to "$2"
function test_assert_eq
{
  typeset got="$1"; shift
  typeset expected="$1"; shift
  typeset name="$1"; shift

  if [ x"$got" = x"$expected" ]; then
    test_result "OK" "$name"
  else
    test_result "Not OK" "$name"
  fi
}

## Test if "$1" is NOT equal to "$2"
function test_assert_not_eq
{
  typeset got="$1"; shift
  typeset not_expected="$1"; shift
  typeset name="$1"; shift

  if [ x"$got" != x"not_expected" ]; then
    test_result "OK" "$name"
  else
    test_result "Not OK" "$name"
  fi
}

function test_assert_match
{
  typeset got="$1"; shift
  typeset expected="$1"; shift
  typeset name="$1"; shift

  case X"$got" in
  X$expected)
    test_result "OK" "$name"
    ;;
  *)
    test_result "Not OK" "$name"
    ;;
  esac
}

function test_assert_not_match
{
  typeset got="$1"; shift
  typeset expected="$1"; shift
  typeset name="$1"; shift

  case X"$got" in
  X$expected)
    test_result "Not OK" "$name"
    ;;
  *)
    test_result "OK" "$name"
    ;;
  esac
}

function test_case_configure
{
  if type tc_configure >/dev/null 2>&1; then
    tc_configure "$@"
  fi
}

function test_case_init
{
  if type tc_init >/dev/null 2>&1; then
    tc_init
  fi
}

function test_case_run
{
  typeset test_case_func="tc_$TEST_case_name"

  type "$test_case_func" >/dev/null 2>&1 \
    || test_abort "test_case_run: No such test case name: $TEST_case_name"

  "$test_case_func"
}

function test_case_end
{
  if type tc_end >/dev/null 2>&1; then
    tc_end
  fi
}

## ======================================================================

function wc
{
  typeset line
  command wc ${1+"$@"} |read -r line
  ## Remove heading spaces
  echo $line
}

## Initialize
## ======================================================================

## Copy stdout/stderr to $TEST_fd_output/error
eval exec "$TEST_fd_output>&1"
eval exec "$TEST_fd_error>&2"
## Redirect stdout to stderr to prevent odd output mixing with test result
exec 1>&2

trap 'test_do_exit; exit 1' INT

