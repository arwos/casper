#!/bin/bash

if [ -f "/etc/systemd/system/casper-server.service" ]; then
    systemctl stop casper-server
    systemctl disable casper-server
    systemctl daemon-reload
fi
