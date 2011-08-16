#!/bin/sh
##
## Setup a supervised Sophos Anti-Virus fsavd service
## Copyright (c) 2010-2011 SATOH Fumiyasu @ OSS Technology, Inc.
##               <http://www.osstech.co.jp/>
##
## License: GNU General Public License version 3
## Date: 2010-10-28, since 2010-10-28
##

set -u
umask 0022

## Options
## ======================================================================

sv_cmd="@FSAVD_COMMAND@"
sv_env="
  WORKINGDIR
  NICE
  IONICE
  MEMORYLIMIT
  DATALIMIT
  STACKLIMIT
  OPENFILELIMIT
  COREFILELIMIT
  COMMAND
  OPTIONS
  CONFIG
  SOCKET
"

if [ $# -ne 1 ]; then
  echo "Usage: $0 /SVDIR" 1>&2
  exit 1
fi

sv_dir="$1"; shift

## Create service directory
## ======================================================================

mkdir "$sv_dir" || exit 1
mkdir "$sv_dir/env" || exit 1

## The "once" is an OSSTech-specific file and is used by
## /etc/init.d/svinit, not for supervise(8).
touch "$sv_dir/down" "$sv_dir/once" || exit 1

for env in $sv_env; do
  touch "$sv_dir/env/$env" || exit 1
done
echo "$sv_cmd" >"$sv_dir/env/COMMAND" || exit 1

## NOTE: $OPENFDLIMIT is for backward compatibility
cat <<'EOT_SV_RUN' >"$sv_dir/run" || exit 1
#!/bin/sh
exec 2>&1
exec envdir ./env sh -c '
  ${WORKINGDIR:+cd} ${WORKINGDIR:+"$WORKINGDIR"}
  echo "PID: $$"
  env |sort |sed "s/^/Environment: /"
  set -- \
    ${NICE:+nice} ${NICE:+-n} ${NICE:+"$NICE"} \
    ${IONICE:+ionice} ${IONICE:+-n} ${IONICE:+"$IONICE"} \
    softlimit \
      ${MEMORYLIMIT:+"-m$MEMORYLIMIT"} \
      ${DATALIMIT:+"-d$DATALIMIT"} \
      ${STACKLIMIT:+"-s$STACKLIMIT"} \
      ${OPENFILELIMIT:+"-o$OPENFILELIMIT"} \
      ${OPENFDLIMIT:+"-o$OPENFDLIMIT"} \
      ${COREFILELIMIT:+"-c$COREFILELIMIT"} \
    "$COMMAND" \
      --nodaemon \
      ${CONFIG:+"--config=$CONFIG"} \
      ${SOCKET:+"--socketname=$SOCKET"} \
      $OPTIONS \
    ;
  ## ksh: Ensure that all commands in the pipeline are terminated
  wait
  echo "Execute: $@"
  exec "$@"
'
EOT_SV_RUN
chmod 0755 "$sv_dir/run" || exit 1

exit 0

