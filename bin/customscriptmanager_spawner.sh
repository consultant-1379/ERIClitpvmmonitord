#!/bin/bash
#######################################################
#
# This script is part of the customscriptmanager.sh
# and should not be used as stand-alone
#

# Just some minor check, but assuming the variables
# are well formed, so no validation in place
# Normally it should happen if this script is run
# as stand-alone
_check_env() {
    _=${CSMANAGER_REPOSITORY_URL:?Missing repository URL!}
    _=${CSMANAGER_SCRIPT_LIST:?Missing script list!}
    _=${CSMANAGER_DEST_DIR:?Missing destination dir!}
    _=${CSMANAGER_TIMEOUT:?Missing timeout value!}
    _=${CSMANAGER_SCRIPT_PERMISSION:?Missing script permission!}
    _=${CSMANAGER_MUTE_SCRIPT_OUTPUT:?Missing mute script setting!}
    unset _
}

# The timeout here is just keep it safer
# and avoid any unexpected external side-effect
# that could interfere in our main managed timeout.
# Any HTTP error (like 404 - file not found) are
# not logged here as a remind that we are suposing
# the list has valid scripts. It's up to the HTTP
# server to log. Any correct linked symlink are
# fetched and the created file has the same content
# as the linked one.
_fetch_scripts() {
    _info "Downloading from '$CSMANAGER_REPOSITORY_URL'"
    _info "Script list: '$CSMANAGER_SCRIPT_LIST'"

    _time_execution curl\
         -sSf "'$CSMANAGER_REPOSITORY_URL/{$CSMANAGER_SCRIPT_LIST}'"\
         -m "'$CSMANAGER_TIMEOUT'"\
         -o "'$CSMANAGER_DEST_DIR/#1'"

    if (( $? > 0 )); then
        _warn "Fail to fetch all or some of the scripts"
    fi
}

_set_permissions() {
    _info "Setting scripts permissions"

    if [[ "${CSMANAGER_SCRIPT_LIST//,}" == "$CSMANAGER_SCRIPT_LIST" ]]; then
       local list_pattern="$CSMANAGER_SCRIPT_LIST"
    else
       local list_pattern="{$CSMANAGER_SCRIPT_LIST}"
    fi

    _time_execution chmod $CSMANAGER_SCRIPT_PERMISSION\
                          "$CSMANAGER_DEST_DIR/${list_pattern}"

    if (( $? > 0 )); then
        _warn "Fail to set permissions to all or some of the scripts"
    fi
}

_execute_script() {
    # Just a small security precaution
    unset CSMANAGER_REPOSITORY_URL
    unset CSMANAGER_SCRIPT_LIST
    unset CSMANAGER_DEST_DIR
    unset CSMANAGER_TIMEOUT

    $CSMANAGER_MUTE_SCRIPT_OUTPUT || unset CSMANAGER_MUTE_SCRIPT_OUTPUT

    _time_execution "$1" ${CSMANAGER_MUTE_SCRIPT_OUTPUT:+>/dev/null 2>&1}
}

_tag_execution() {
    echo "Starting"
    _execute_script "$1"
    _tag_result
}

_process_script_execution() {
    _tag_execution "$1" |
        while read line; do
            echo "`basename \"$1\"`] $line"
        done
}

# Just to skip any mal-formed
# file as a result of the fetch
_is_executable_file() {
    if [ ! -x "$1" ]; then
        _warn "Executable script '`basename $1`' not found"
        return 1
    fi
}

_time_execution() {
    (
        set -o pipefail
        eval time "$@" 2>&1 | _tag_time
    )
}

_main() {
    _check_env
    _fetch_scripts
    _set_permissions

    for script in ${CSMANAGER_SCRIPT_LIST//,/ }; do
        script=$CSMANAGER_DEST_DIR/$script
        if _is_executable_file "$script"; then
            _process_script_execution "$script"
        fi
    done
}

#
# ENTRY-POINT
#
_main
