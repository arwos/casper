#!/bin/bash

if [ -f "/etc/systemd/system/casper-server.service" ]; then
    systemctl start casper-server
    systemctl enable casper-server
    systemctl daemon-reload
fi
