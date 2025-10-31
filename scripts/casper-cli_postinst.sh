#!/bin/bash
set -e


do_configure(){
	if [ -f "/etc/systemd/system/casper-cli.service" ]; then
		systemctl start casper-cli
		systemctl enable casper-cli
		systemctl daemon-reload
	fi
}

case "$1" in
  configure)
    do_configure
    ;;
  *)
    echo "No ACTION"
    ;;
esac
