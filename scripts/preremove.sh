if [ "$1" == "0" ]; then # uninstall
    if [ $(/sbin/pidof systemd) ] ; then
       /bin/systemctl stop vmmonitord.service
       /bin/systemctl disable vmmonitord.service
    elif [ $(/sbin/pidof init) ] ; then
       /sbin/service vmmonitord stop
       /sbin/chkconfig --del vmmonitord
    else
       echo "Error: Failed to find any services system."
    fi

  # Section related to customscriptmanager.sh
    rm -fr /var/opt/ericsson/vmmonitord/customscriptmanager.d
    rm -f /var/opt/ericsson/vmmonitord/customscriptmanager.lock
fi

exit 0
