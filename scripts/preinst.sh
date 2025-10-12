#!/bin/bash

if ! [ -d /var/lib/casper-server/ ]; then
    mkdir /var/lib/casper-server
fi

if [ -f "/etc/systemd/system/casper-server.service" ]; then
    systemctl stop casper-server
    systemctl disable casper-server
    systemctl daemon-reload
fi
