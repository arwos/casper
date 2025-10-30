#!/bin/bash

if [ -f "/etc/systemd/system/casper.service" ]; then
    systemctl stop casper
    systemctl disable casper
    systemctl daemon-reload
fi
