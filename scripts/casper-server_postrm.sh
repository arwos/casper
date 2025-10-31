#!/bin/bash
set -e

do_purge(){
	rm -rf /var/lib/casper
}

case "$1" in
  remove)
    echo "No ACTION"
    ;;
  purge)
    do_purge
    ;;
  *)
    echo "No ACTION"
    ;;
esac
