#!/bin/bash

USERNAME="casper"
GROUPNAME="casper"

log_message() {
    echo ">> $1"
}

#-----------------------------------------------------------------

if getent group "$GROUPNAME" > /dev/null 2>&1; then
    log_message "Group $GROUPNAME exist"
else
    if groupadd -r "$GROUPNAME"; then
        log_message "Group $GROUPNAME created"
    else
        log_message "Failed create group $GROUPNAME"
        exit 1
    fi
fi

#-----------------------------------------------------------------

if id "$USERNAME" > /dev/null 2>&1; then
    log_message "User $USERNAME exist"
    if id -nG "$USERNAME" | grep -qw "$GROUPNAME"; then
        log_message "User $USERNAME contain group $GROUPNAME"
    else
        if usermod -a -G "$GROUPNAME" "$USERNAME"; then
            log_message "Add $USERNAME to group $GROUPNAME"
        else
            log_message "Failed add $USERNAME to group $GROUPNAME"
            exit 1
        fi
    fi
else
    if useradd -r -s /bin/false -g "$GROUPNAME" "$USERNAME"; then
        log_message "Created user $USERNAME with group $GROUPNAME"
    else
        log_message "Failed create user $USERNAME"
        exit 1
    fi
fi

#-----------------------------------------------------------------

if ! [ -d /var/lib/casper-server/ ]; then
    mkdir /var/lib/casper-server
    chown $USERNAME:$GROUPNAME -R /var/lib/casper-server
    chmod 640 -R /var/lib/casper-server
fi

#-----------------------------------------------------------------

if [ -f "/etc/systemd/system/casper-server.service" ]; then
    systemctl stop casper-server
    systemctl disable casper-server
    systemctl daemon-reload
fi
