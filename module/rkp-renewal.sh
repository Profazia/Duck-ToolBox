#!/system/bin/sh
# Background check for automatic RKP keybox renewal. It runs only while a renewal plan
# exists: boot-completed.sh starts it when one was saved, and `duckd rkp-renewal enable`
# starts it right away. It exits when renewal is turned off or stops, so nothing stays
# running, and no state is created, for anyone who never turns renewal on.
#
# `sleep` counts only awake time, which is also the only time a renewal could run.

umask 077
MODPATH=${0%/*}
case "$MODPATH" in /*) ;; *) MODPATH=$(CDPATH='' cd -- "$MODPATH" && pwd) || exit 1 ;; esac

# shellcheck source=util_functions.sh
. "$MODPATH/util_functions.sh" || exit 1
DUCKCTL="$MODPATH/bin/duckctl.sh"
STATE_DIR="$VAR_DIR/rkp-renewal"
PLAN="$STATE_DIR/plan.json"
PIDFILE="$STATE_DIR/check.pid"

[ -f "$PLAN" ] || exit 0

# One check per plan. The PID file is trusted only while its process is this script.
if [ -f "$PIDFILE" ]; then
  running=$(cat "$PIDFILE" 2>/dev/null)
  case "$running" in
    ''|*[!0-9]*) ;;
    *)
      if tr '\0' ' ' <"/proc/$running/cmdline" 2>/dev/null | grep -q 'rkp-renewal\.sh'; then
        exit 0
      fi
      ;;
  esac
fi
echo "$$" >"$PIDFILE" || exit 1
trap '[ "$(cat "$PIDFILE" 2>/dev/null)" = "$$" ] && rm -f "$PIDFILE"' EXIT

still_wanted() {
  [ -d "$MODPATH" ] && [ ! -e "$MODPATH/disable" ] && [ ! -e "$MODPATH/remove" ] \
    && [ -f "$PLAN" ] && [ "$(cat "$PIDFILE" 2>/dev/null)" = "$$" ]
}

# Waits in one-minute steps so turning renewal or the module off ends the check promptly.
wait_minutes() {
  minutes=$1
  while [ "$minutes" -gt 0 ]; do
    sleep 60
    still_wanted || exit 0
    minutes=$((minutes - 1))
  done
}

# After boot, give the network time to come up before the first check.
[ "${1:-}" = "boot" ] && wait_minutes 5

while still_wanted; do
  result=$("$DUCKCTL" rkp-renewal tick 2>/dev/null)
  case "$result" in
    *'"action":"disabled"'* | *'"action":"stopped"'* | *'"action":"superseded"'* \
      | *'"code":"usage_error"'* | *'"code":"binary_not_found"'*)
      exit 0
      ;;
  esac
  wait_minutes 15
done
