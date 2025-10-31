#!/bin/bash
set -e


do_remove(){
	if [ -f "/etc/systemd/system/casper-server.service" ]; then
		systemctl stop casper-server
		systemctl disable casper-server
		systemctl daemon-reload
	fi
}

do_upgrade(){
	if [ -f "/etc/systemd/system/casper-server.service" ]; then
		systemctl stop casper-server
		systemctl disable casper-server
		systemctl daemon-reload
	fi
}

case "$1" in
  remove)
    do_remove
    ;;
  upgrade)
    do_upgrade
    ;;
  *)
    echo "No ACTION"
    ;;
esac
