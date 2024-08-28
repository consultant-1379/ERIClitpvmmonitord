#set( $symbol_pound = '#' )
#set( $symbol_dollar = '$' )
#set( $symbol_escape = '\' )
Any "*.conf" files in the "etc/plugins" directory will be included in the
RPM, and installed in /opt/ericsson/nms/litp/etc/plugins.  This behaviour
is triggered by the existence of this README.txt file; deleting or renaming
this file will mean that files in "etc/plugins" are no longer included in
the RPM.
