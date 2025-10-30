#!/bin/bash

if [ -f "/etc/systemd/system/casper.service" ]; then
    systemctl start casper
    systemctl enable casper
    systemctl daemon-reload
fi
