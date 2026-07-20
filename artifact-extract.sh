#!/bin/sh
# Artifact-extract - native, dependency-free DFIR artifact collector (Linux).
# Collects triage artifacts using only POSIX sh + coreutils/procfs and writes a
# self-describing collection ([root]/ filesystem layout + NDJSON manifest with a full
# chain of custody). See README.md for the output contract.
#
# POSIX sh (no bashisms) so it runs on busybox/dash appliances too.
# Run as root for full coverage; degrades gracefully otherwise.

COLLECTOR_VERSION='0.1.0'

# --- Defaults / flag parsing (categories additive; default = disk only) -------------
DISK=0; VOLATILE=0; MEMORY=0; PROFILE='quick'; OUTPUT='.'; KEEP_FOLDER=0

usage() {
    cat <<EOF
Artifact-extract $COLLECTOR_VERSION - native DFIR collector (Linux)

Usage: sh artifact-extract.sh [--disk] [--volatile] [--memory] [--all]
                              [--profile quick|full] [--output <path>] [--keep-folder]

  (no flags)     disk only ([root]/)          --volatile     live captures
  --disk         disk artifacts, explicit      --memory       memory image (stub in v1)
  --all          disk + volatile + memory      --profile      collection depth
  --output       destination root (default .)  --keep-folder  keep uncompressed folder
  --help         this message

Output is packed into <host>_linux_<UTC>.tar.gz (+ .sha256) in the destination root.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --disk) DISK=1 ;;
        --volatile) VOLATILE=1 ;;
        --memory) MEMORY=1 ;;
        --all) DISK=1; VOLATILE=1; MEMORY=1 ;;
        --profile) shift; PROFILE="$1" ;;
        --output) shift; OUTPUT="$1" ;;
        --keep-folder) KEEP_FOLDER=1 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
    shift
done
[ "$DISK" = 0 ] && [ "$VOLATILE" = 0 ] && [ "$MEMORY" = 0 ] && DISK=1
case "$PROFILE" in quick|full) ;; *) echo "Invalid profile: $PROFILE" >&2; exit 2 ;; esac

# --- Environment / clock ------------------------------------------------------------
HOSTNAME_V=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown)
START_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
STAMP=$(date -u '+%Y%m%dT%H%M%SZ')
UTC_OFFSET=$(date '+%z' 2>/dev/null || echo '?')
TZ_NAME=$(date '+%Z' 2>/dev/null || echo '?')
if [ "$(id -u 2>/dev/null)" = "0" ]; then IS_ROOT=1; else IS_ROOT=0; fi

# --- Tool fallback resolution -------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
sha256_of() {
    if have sha256sum; then sha256sum "$1" 2>/dev/null | awk '{print $1}';
    elif have shasum; then shasum -a 256 "$1" 2>/dev/null | awk '{print $1}';
    else echo ''; fi
}

# --- Output layout ------------------------------------------------------------------
OUT_ROOT="$OUTPUT/${HOSTNAME_V}_linux_${STAMP}"
mkdir -p "$OUT_ROOT" || { echo "Cannot create $OUT_ROOT" >&2; exit 1; }
OUT_ROOT=$(cd "$OUT_ROOT" && pwd)   # absolutize
MANIFEST="$OUT_ROOT/collection_manifest.ndjson"
LOGFILE="$OUT_ROOT/collection.log"
: > "$MANIFEST"; : > "$LOGFILE"

C_OK=0; C_ERR=0; C_SKIP=0; C_DEGRADED=0; C_BYTES=0

# --- Logging helpers ----------------------------------------------------------------
log() {
    _lvl="${2:-INFO}"
    _line="$(date -u '+%Y-%m-%dT%H:%M:%SZ') [$_lvl] $1"
    printf '%s\n' "$_line" | tee -a "$LOGFILE"
}

json_escape() {   # escape a string for embedding in JSON
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' | tr -d '\n\r'
}

# manifest <action> <command> <target-abs|-> <category> <exit|-> <bytes> <sha> <ms> <status> [message]
# NOTE: POSIX sh has no local scope, so every variable here is namespaced (_j*) to avoid
# clobbering the caller's variables (run_step/copy_artifact reuse _msg, _exit, ...).
manifest() {
    _jt="$3"
    if [ "$_jt" = "-" ] || [ -z "$_jt" ]; then _jrel='null'
    else _jrel="\"$(json_escape "$(printf '%s' "$_jt" | sed "s#^$OUT_ROOT/##")")\""; fi
    _jexit="$5"; [ "$_jexit" = "-" ] && _jexit='null'
    _jsha="$7"; if [ -z "$_jsha" ]; then _jsha='null'; else _jsha="\"$_jsha\""; fi
    _jmsg=''
    [ -n "${10}" ] && _jmsg=",\"message\":\"$(json_escape "${10}")\""
    printf '{"ts_utc":"%s","action":"%s","command":"%s","target":%s,"category":"%s","exit_code":%s,"bytes":%s,"sha256":%s,"duration_ms":%s,"status":"%s"%s}\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        "$(json_escape "$1")" "$(json_escape "$2")" "$_jrel" "$4" "$_jexit" "${6:-0}" "$_jsha" "${8:-0}" "$9" "$_jmsg" \
        >> "$MANIFEST"
    case "$9" in
        ok) C_OK=$((C_OK+1)) ;; error) C_ERR=$((C_ERR+1)) ;;
        skipped) C_SKIP=$((C_SKIP+1)) ;; degraded) C_DEGRADED=$((C_DEGRADED+1)) ;;
    esac
    C_BYTES=$((C_BYTES + ${6:-0}))
}

# run_step <action> <command-display> <target-abs> <category> : runs $CMD producing target
# The command to execute is passed as remaining args after a '--' marker.
run_step() {
    _action="$1"; _disp="$2"; _target="$3"; _cat="$4"; shift 4
    _dir=$(dirname "$_target"); [ -d "$_dir" ] || mkdir -p "$_dir" 2>/dev/null
    _t0=$(date '+%s'); _status='ok'; _msg=''; _exit=0
    "$@" >"$_target" 2>>"$LOGFILE" || { _exit=$?; if [ "$IS_ROOT" = 1 ]; then _status='error'; else _status='degraded'; fi; _msg="exit code $_exit"; }
    _t1=$(date '+%s'); _ms=$(( (_t1 - _t0) * 1000 ))
    _bytes=0; _sha=''
    if [ -f "$_target" ]; then
        _bytes=$(wc -c < "$_target" 2>/dev/null | tr -d ' ')
        [ -z "$_bytes" ] && _bytes=0
        [ "$_bytes" -gt 0 ] && _sha=$(sha256_of "$_target")
        if [ "$_bytes" = 0 ] && [ "$_status" = ok ]; then _status='degraded'; _msg='no output produced'; fi
    elif [ "$_status" = ok ]; then _status='degraded'; _msg='no output produced'; fi
    manifest "$_action" "$_disp" "$_target" "$_cat" "$_exit" "$_bytes" "$_sha" "$_ms" "$_status" "$_msg"
    [ "$_status" != ok ] && log "  $_action -> $_status${_msg:+: $_msg}" WARN
    return 0
}

# copy_artifact <source-abs> : copy a file into [root]/ preserving its absolute path
copy_artifact() {
    _src="$1"
    [ -e "$_src" ] || return 0
    _target="$OUT_ROOT/[root]${_src}"
    _dir=$(dirname "$_target"); mkdir -p "$_dir" 2>/dev/null
    _status='ok'; _msg=''; _exit=0
    cp -p "$_src" "$_target" 2>>"$LOGFILE" || { _exit=$?; if [ "$IS_ROOT" = 1 ]; then _status='error'; else _status='degraded'; fi; _msg="cp exit $_exit"; }
    _bytes=0; _sha=''
    if [ -f "$_target" ]; then
        _bytes=$(wc -c < "$_target" 2>/dev/null | tr -d ' '); [ -z "$_bytes" ] && _bytes=0
        [ "$_bytes" -gt 0 ] && _sha=$(sha256_of "$_target")
    fi
    manifest 'file_copy' "cp $_src" "$_target" 'disk' "$_exit" "$_bytes" "$_sha" 0 "$_status" "$_msg"
    [ "$_status" != ok ] && log "  file_copy $_src -> $_status" WARN
}

# ==================================================================================
#  Collection modules
# ==================================================================================
collect_disk() {
    log "Collecting disk artifacts ([root]/ filesystem layout) [profile=$PROFILE]"
    # Identity / config
    for f in /etc/hostname /etc/os-release /etc/passwd /etc/group /etc/hosts \
             /etc/crontab /etc/sudoers /etc/ssh/sshd_config; do
        copy_artifact "$f"
    done
    [ "$IS_ROOT" = 1 ] && copy_artifact /etc/shadow
    # Auth / login logs and accounting (raw - parsed by the Engine)
    for f in /var/log/auth.log /var/log/secure /var/log/wtmp /var/log/btmp \
             /var/log/lastlog /var/log/syslog /var/log/messages /var/log/cron; do
        copy_artifact "$f"
    done
    # Persistence: cron dirs, systemd units, shell profiles
    for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron; do
        [ -d "$d" ] && find "$d" -type f 2>/dev/null | while IFS= read -r f; do copy_artifact "$f"; done
    done
    if [ "$PROFILE" = full ]; then
        for d in /etc/systemd/system /lib/systemd/system; do
            [ -d "$d" ] && find "$d" -maxdepth 1 -type f -name '*.service' 2>/dev/null | while IFS= read -r f; do copy_artifact "$f"; done
        done
    fi
    # NOTE: full-disk timeline artifacts deferred; v1 is targeted triage.
}

collect_volatile() {
    log 'Collecting volatile artifacts (live captures)'
    LR="$OUT_ROOT/live_response"

    run_step system_info 'uname -a' "$LR/system/uname.txt" volatile uname -a
    run_step date_utc 'date -u' "$LR/system/date_utc.txt" volatile sh -c "date -u; echo \"tz=$TZ_NAME offset=$UTC_OFFSET\""
    run_step processes 'ps -ef' "$LR/process/ps.txt" volatile ps -ef
    run_step process_tree 'ps auxww' "$LR/process/ps_auxww.txt" volatile ps auxww

    if have ss; then run_step network 'ss -tunap' "$LR/network/connections.txt" volatile ss -tunap
    elif have netstat; then run_step network 'netstat -tunap' "$LR/network/connections.txt" volatile netstat -tunap
    else manifest network 'ss|netstat' - volatile - 0 '' 0 skipped 'no ss/netstat available'; fi

    if have ip; then run_step interfaces 'ip addr' "$LR/network/interfaces.txt" volatile ip addr
    elif have ifconfig; then run_step interfaces 'ifconfig -a' "$LR/network/interfaces.txt" volatile ifconfig -a; fi

    run_step logins 'last' "$LR/system/last.txt" volatile sh -c 'last 2>/dev/null || true'
    run_step who 'who -a' "$LR/system/who.txt" volatile sh -c 'who -a 2>/dev/null || who'
    run_step listening 'lsof -nP -iTCP -sTCP:LISTEN' "$LR/network/listening.txt" volatile sh -c 'command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP -sTCP:LISTEN || echo "lsof not available"'

    if [ "$PROFILE" = full ]; then
        run_step modules 'lsmod' "$LR/system/lsmod.txt" volatile sh -c 'lsmod 2>/dev/null || cat /proc/modules'
        run_step mounts 'mount' "$LR/system/mounts.txt" volatile sh -c 'mount; echo; cat /proc/mounts'
        have systemctl && run_step services 'systemctl list-units' "$LR/system/services.txt" volatile systemctl list-units --type=service --no-pager
        have journalctl && run_step journal 'journalctl -n 5000' "$LR/system/journal.txt" volatile journalctl --no-pager -n 5000
    fi
}

collect_memory() {
    log 'Memory acquisition requested'
    mkdir -p "$OUT_ROOT/memory"
    _m='memory acquisition not implemented in v1 (no reliable native-only path; requires kernel access - out of scope)'
    manifest memory_acquire 'n/a' - memory - 0 '' 0 skipped "$_m"
    log "  memory -> skipped: $_m" WARN
}

# Pack the collection into a single .tar.gz and hash it (outer chain-of-custody seal).
compress_collection() {
    _parent=$(dirname "$OUT_ROOT"); _leaf=$(basename "$OUT_ROOT")
    _archive="$OUT_ROOT.tar.gz"
    log "Compressing collection -> $_leaf.tar.gz"
    _ok=0
    if tar czf "$_archive" -C "$_parent" "$_leaf" 2>>"$LOGFILE"; then _ok=1
    elif tar cf - -C "$_parent" "$_leaf" 2>>"$LOGFILE" | gzip -c > "$_archive" 2>>"$LOGFILE"; then _ok=1; fi
    if [ "$_ok" = 1 ] && [ -s "$_archive" ]; then
        _asha=$(sha256_of "$_archive")
        [ -n "$_asha" ] && printf '%s  %s\n' "$_asha" "$_leaf.tar.gz" > "$_archive.sha256"
        _amb=$(( $(wc -c < "$_archive" | tr -d ' ') / 1048576 ))
        log "  archive: $_leaf.tar.gz (${_amb} MB) sha256=$_asha"
        FINAL_ARTIFACT="$_archive"
        if [ "$KEEP_FOLDER" = 0 ]; then
            log '  removing working folder (use --keep-folder to retain it)'
            rm -rf "$OUT_ROOT"
        fi
    else
        log '  compression failed - keeping uncompressed folder' WARN
        FINAL_ARTIFACT="$OUT_ROOT"
    fi
}

# ==================================================================================
#  Main
# ==================================================================================
SELECTED=''
[ "$DISK" = 1 ] && SELECTED="disk"
[ "$VOLATILE" = 1 ] && SELECTED="$SELECTED volatile"
[ "$MEMORY" = 1 ] && SELECTED="$SELECTED memory"

log "Artifact-extract $COLLECTOR_VERSION starting on $HOSTNAME_V"
log "Root: $IS_ROOT | Profile: $PROFILE | Categories:$SELECTED"
log "Output: $OUT_ROOT"
[ "$IS_ROOT" = 0 ] && log 'Not root - disk collection will be partial (steps marked degraded).' WARN

# Collection metadata
SCRIPT_SHA=$(sha256_of "$0")
KERNEL=$(uname -r 2>/dev/null); OSNAME=$(uname -s 2>/dev/null)
cat > "$OUT_ROOT/metadata.json" <<EOF
{
  "collector": "artifact-extract",
  "collector_version": "$COLLECTOR_VERSION",
  "collector_sha256": "$SCRIPT_SHA",
  "host": "$(json_escape "$HOSTNAME_V")",
  "os_name": "$OSNAME",
  "kernel": "$KERNEL",
  "user": "$(id -un 2>/dev/null)",
  "root": $([ "$IS_ROOT" = 1 ] && echo true || echo false),
  "timezone": "$TZ_NAME",
  "utc_offset": "$UTC_OFFSET",
  "started_utc": "$START_UTC",
  "profile": "$PROFILE",
  "categories": "$(echo "$SELECTED" | sed 's/^ //')"
}
EOF

[ "$DISK" = 1 ] && collect_disk
[ "$VOLATILE" = 1 ] && collect_volatile
[ "$MEMORY" = 1 ] && collect_memory

# Seal the manifest, then pack everything into a single archive.
MANIFEST_SHA=$(sha256_of "$MANIFEST")
[ -n "$MANIFEST_SHA" ] && printf '%s  collection_manifest.ndjson\n' "$MANIFEST_SHA" > "$OUT_ROOT/manifest.sha256"

MB=$(( C_BYTES / 1048576 ))
log "Done | ok=$C_OK degraded=$C_DEGRADED error=$C_ERR skipped=$C_SKIP | ${MB} MB"

FINAL_ARTIFACT="$OUT_ROOT"
compress_collection

printf '\nCollection written to: %s\n' "$FINAL_ARTIFACT"
exit 0
