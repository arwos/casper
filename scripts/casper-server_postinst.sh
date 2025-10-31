#!/bin/bash
set -e

USERNAME="casper"
GROUPNAME="casper"

do_configure(){
	if [ -f "/etc/systemd/system/casper-server.service" ]; then
		systemctl start casper-server
		systemctl enable casper-server
		systemctl daemon-reload
	fi

	mkdir -p /var/lib/casper-server
  chown $USERNAME:$GROUPNAME -R /var/lib/casper-server
  chmod 600 -R /var/lib/casper-server
  chmod 700 /var/lib/casper-server
}

case "$1" in
  configure)
    do_configure
    ;;
  *)
    echo "No ACTION"
    ;;
esac
