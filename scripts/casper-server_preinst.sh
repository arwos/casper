#!/bin/bash
set -e

USERNAME="casper"
GROUPNAME="casper"

_log() {
    echo "[*] $1"
}

do_install(){
  if getent group "$GROUPNAME" > /dev/null 2>&1; then
      _log "Group $GROUPNAME exist"
  else
      if groupadd -r "$GROUPNAME"; then
          _log "Group $GROUPNAME created"
      else
          _log "Failed create group $GROUPNAME"
          exit 1
      fi
  fi
  
  if id "$USERNAME" > /dev/null 2>&1; then
      _log "User $USERNAME exist"
      if id -nG "$USERNAME" | grep -qw "$GROUPNAME"; then
          _log "User $USERNAME contain group $GROUPNAME"
      else
          if usermod -a -G "$GROUPNAME" "$USERNAME"; then
              _log "Add $USERNAME to group $GROUPNAME"
          else
              _log "Failed add $USERNAME to group $GROUPNAME"
              exit 1
          fi
      fi
  else
      if useradd -r -s /bin/false -g "$GROUPNAME" "$USERNAME"; then
          _log "Created user $USERNAME with group $GROUPNAME"
      else
          _log "Failed create user $USERNAME"
          exit 1
      fi
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
  install)
    do_install
    ;;
  upgrade)
    do_upgrade
    ;;
  *)
    echo "No ACTION"
    ;;
esac
