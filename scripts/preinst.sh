#!/bin/bash

USERNAME="casper"
GROUPNAME="casper"

log_message() {
    echo ">> $1"
}

#-----------------------------------------------------------------

if [ -f "/etc/systemd/system/casper.service" ]; then
    systemctl stop casper
    systemctl disable casper
    systemctl daemon-reload
fi

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

mkdir -p /var/lib/casper-server
chown $USERNAME:$GROUPNAME -R /var/lib/casper-server
chmod 600 -R /var/lib/casper-server
