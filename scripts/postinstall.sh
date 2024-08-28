# always needs to be done as the file is overriden
chmod 755 /opt/ericsson/vmmonitord/bin/ocf_monitor.py

# Session related to customscriptmanager.sh - idempotent
if [ ! -d /var/opt/ericsson/vmmonitord/customscriptmanager.d ] ; then
	mkdir -p /var/opt/ericsson/vmmonitord/customscriptmanager.d
	chown root:root /var/opt/ericsson/vmmonitord/customscriptmanager.d
	chmod 755 /var/opt/ericsson/vmmonitord/customscriptmanager.d
fi

if [ "$1" == "1" ] ; then #first install
    
    if [ $(/sbin/pidof systemd) ] ; then
        /bin/systemctl enable vmmonitord.service
    elif [ $(/sbin/pidof init) ] ; then
        /sbin/chkconfig --add vmmonitord
    else
        echo "Error: Failed to find any services system."
    fi
fi

if [ "$1" == "2" ]; then # upgrade
	if [ $(/sbin/pidof systemd) ] ; then
		/bin/systemctl stop vmmonitord.service
		# make sure everything is cleaned up
		OCFP=$(ps ax | grep 'ocf_monitor.py' | grep python | awk '{print $1}');
		if [ -n "$OCFP" ]; then
			kill $OCFP
		fi
		# update systemd daemon 
		/bin/systemctl daemon-reload
		/bin/systemctl enable vmmonitord.service
		rm -f /var/run/vmmonitor.pid /var/lock/subsys/vmmonitord 
	elif [ $(/sbin/pidof init) ] ; then
		/sbin/service vmmonitord stop
		# make sure everything is cleaned up
		OCFP=$(ps ax | grep 'ocf_monitor.py' | grep python | awk '{print $1}');
		if [ -n "$OCFP" ]; then
			kill $OCFP
		fi
		# update rc.d priority
		/sbin/chkconfig --del vmmonitord
		/sbin/chkconfig --add vmmonitord
	  	rm -f /var/run/vmmonitor.pid /var/lock/subsys/vmmonitord
  	else
    		echo "Error: Failed to find any services system."
  	fi
fi

#Start service
if [ $(/sbin/pidof systemd) ] ; then
	/bin/systemctl start vmmonitord.service
elif [ $(/sbin/pidof init) ] ; then
	/sbin/service vmmonitord start
else
    	echo "Error: Failed to find any services system."
fi
exit 0
