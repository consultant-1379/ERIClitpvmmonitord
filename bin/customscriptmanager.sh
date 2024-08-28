#!/bin/bash
#######################################################
#
# Expected arguments
# ------------------
# $1 - IPv4 of the Management Server belonging to
#      a network reachable from inside the VM
#
# $2 - comma separted list of script names that
#      should be stored at the repository defined
#      by CSMANAGER_REPOSITORY_URL
#

#
# PROLOGUE definitions
#
CSMANAGER_VMMONITORD_BIN=/opt/ericsson/vmmonitord/bin
CSMANAGER_VMMONITORD_ETC=/etc/opt/ericsson/vmmonitord
CSMANAGER_NAME="`basename $0 .sh`"
CSMANAGER_RUN_DIR="$CSMANAGER_VMMONITORD_BIN"
CSMANAGER_INI="$CSMANAGER_VMMONITORD_ETC/${CSMANAGER_NAME}.ini"
CSMANAGER_SPAWNER="$CSMANAGER_RUN_DIR/${CSMANAGER_NAME}_spawner.sh"
CSMANAGER_TIMEOUT_KILL_PATTERN="${CSMANAGER_NAME}.*Killed.*timeout.*KILL"
CSMANAGER_TIMEOUT_KILL_RC=137

exec > >(logger -i -t "$CSMANAGER_NAME") 2>&1
trap _finish EXIT

#
# FUNCTIONS
#
_error() {
    echo "!!!> ERROR: $1 <!!!"
    exit 99
} >&2

_abort() {
    echo "###> ABORT: $1"
    exit ${2:-1}
}

_warn() {
    $CSMANAGER_MUTE_WARNING || echo "+++> WARNING: $*"
}

_info() {
    $CSMANAGER_MUTE_INFO || echo "---> INFO: $*"
}

_pre_start_settings() {
    _load_parameters() {
        if [[ ! -f "$1" ]]; then
            _error "Missing '$1'"
        fi
        source "$1"
    }

    _check_parameters() {
        for p in $@; do
            [[ -z "${!p}" ]] && _error "Missing parameter '$p'"
        done
    }

    _load_parameters "$CSMANAGER_INI"

    _check_parameters CSMANAGER_TIMEOUT CSMANAGER_MUTE_INFO\
             CSMANAGER_MUTE_WARNING CSMANAGER_MUTE_SCRIPT_OUTPUT\
             CSMANAGER_REPOSITORY_PATH CSMANAGER_VAR_DIR\
             CSMANAGER_SCRIPT_PERMISSION CSMANAGER_SCRIPT_NAME_REGEX\
             CSMANAGER_SCRIPT_LIST_REGEX

    # Dependent definitions
    CSMANAGER_DEST_DIR="$CSMANAGER_VAR_DIR/${CSMANAGER_NAME}.d"
    CSMANAGER_LOCKFILE="$CSMANAGER_VAR_DIR/${CSMANAGER_NAME}.lock"

    # Pre-start actions
    mkdir -p "$CSMANAGER_DEST_DIR" ||\
                _error "Failed to create '$CSMANAGER_DEST_DIR'"
}

_tag_time() {
    awk '
        /^real/ {print "TIME: " substr($0,6,8); next}
        ! /^user|^sys|^$/ {print $0}
    '
}

_tag_result() {
    local ret=$?
    if (( $ret == 0 )); then
        echo "RESULT: [SUCCESS]"
    else
        echo "RESULT: [FAILED] Code($ret)"
    fi
    return $ret
}

# Just a very simple check on IP format
_valid_ip() {
    eval local -i ip_a=( ${1//./ } )
    if (( ${#ip_a[@]} != 4 )); then
        return 1
    fi
    local -i count_ok=0
    for ((i=0; i<4; i++)); do
        if [[ -z "${ip_a[$i]//[0-9]}" ]] &&\
            (( ${ip_a[$i]} >= 0 && ${ip_a[$i]} <= 255 )); then
            let count_ok++
        fi
    done
    (( $count_ok == 4 ))
}

_valid_list() {
    _no_repetition() {
        local -a script_A=$(echo $1 | tr "," "\n" | sort -u)
        local unique_elements
        for i in ${script_A[@]}
        do
            unique_elements=$((unique_elements+1))
        done
        local -i num_scripts=$(($(echo $1| tr -dc ',' | wc -c) + 1))

        (( $unique_elements == $num_scripts ))
    }

    [[ -n "$(echo $1 | grep -E $CSMANAGER_SCRIPT_LIST_REGEX)" ]] &&\
        _no_repetition "$1"
}

_time_spawning() {
    eval timeout -s KILL $CSMANAGER_TIMEOUT "'$CSMANAGER_SPAWNER'"
    if (( $? == $CSMANAGER_TIMEOUT_KILL_RC )); then
        _abort "[TIMEOUT]" $CSMANAGER_TIMEOUT_KILL_RC
    fi
}

_filter_output() {
    local ret=$?
    grep -vE --line-buffered "$CSMANAGER_TIMEOUT_KILL_PATTERN"
    return $ret
}

_process_list() {
    if (( $# != 2 )); then
        _error "Usage: $0 <MS IP> <comma separated list>"
    elif ! _valid_ip "$1"; then
        _error "Invalid MS IP: '$1'"
    elif ! _valid_list "$2"; then
        _error "Invalid comma separated list: '$2'"
    fi

    CSMANAGER_REPOSITORY_URL="http://$1/$CSMANAGER_REPOSITORY_PATH"
    CSMANAGER_SCRIPT_LIST="$2"

    export -f _info _warn _abort _tag_time _tag_result
    export CSMANAGER_REPOSITORY_URL CSMANAGER_DEST_DIR CSMANAGER_SCRIPT_LIST
    export CSMANAGER_TIMEOUT CSMANAGER_MUTE_INFO CSMANAGER_MUTE_WARNING
    export CSMANAGER_SCRIPT_PERMISSION CSMANAGER_MUTE_SCRIPT_OUTPUT

    _time_spawning 2>&1 | _filter_output
}

_start() {
    _info "Starting $CSMANAGER_NAME"

    _protect_execution _process_list "$@"
}

_finish() {
    _info "Finishing $CSMANAGER_NAME"
}

_protect_execution() {
    if [[ -e "$CSMANAGER_LOCKFILE" ]]; then
        _abort "$CSMANAGER_NAME already executed!"
    else
        (
            flock -noe 9 || _abort "$CSMANAGER_NAME already running!"
            $@
        ) 9>"$CSMANAGER_LOCKFILE"
    fi
}

#
# ENTRY-POINT
#
_pre_start_settings
_start "$@"
