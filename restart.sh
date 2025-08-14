#!/bin/bash
# Restarting script
source .integrations_vars.sh

APP_NAME=run.py
IOC_NAME=ioc_manager.py

VIRTUAL_ENV=.venv
INTEGRATIONS_CONFIG=integrations.yml
COMPANIES_CONFIG=companies.yml
IOC_DB_PATH=${IOC_DB_PATH:-$PWD/ioc.db}

echo "[*] Lumu integration Restarting script"

RESTART_OPTION=$1
case $RESTART_OPTION in

  ioc*)
    echo "[*] Stage: IOC Management."
    ps -ax | grep -i $PWD | grep -i $IOC_NAME | grep -v grep |  awk '{ print $1 }' | xargs kill -9 2>/dev/null
    sleep 1
    cd $PWD && $PWD/$VIRTUAL_ENV/bin/python $PWD/$IOC_NAME --config $PWD/$COMPANIES_CONFIG -l file &
  ;;
  all|both)
    echo "[*] Stage: IOC Management and App Integration."
    ps -ax | grep -i $PWD | grep -i $APP_NAME | grep -v grep |  awk '{ print $1 }' | xargs kill -9 2>/dev/null
    ps -ax | grep -i $PWD | grep -i $IOC_NAME | grep -v grep |  awk '{ print $1 }' | xargs kill -9 2>/dev/null
    sleep 1
    cd $PWD && $PWD/$VIRTUAL_ENV/bin/python $PWD/$IOC_NAME --config $PWD/$COMPANIES_CONFIG -l file &
    cd $PWD && $PWD/$VIRTUAL_ENV/bin/python $PWD/$APP_NAME --config $PWD/$INTEGRATIONS_CONFIG --ioc-manager-db-path $IOC_DB_PATH -l file &
  ;;
  help|-h|--help|-help)
    echo "[*] Showing Restarting help reference."
        cat <<EOF
./restart.sh help
./restart.sh app      -> restart the integration, stop and start the process
./restart.sh ioc      -> restart only a IOC Manage, , stop and start the process
./restart.sh all      -> restart both at once, IOC Manager and The integration in one application.
./restart.sh both     -> restart both at once, IOC Manager and The integration in one application.
EOF
  ;;
  app|*)
    echo "[*] Stage: App Integration."
    ps -ax | grep -i $PWD | grep -i $APP_NAME | grep -v grep |  awk '{ print $1 }' | xargs kill -9 2>/dev/null
    sleep 1
    cd $PWD && $PWD/$VIRTUAL_ENV/bin/python $PWD/$APP_NAME --config $PWD/$INTEGRATIONS_CONFIG --ioc-manager-db-path $IOC_DB_PATH -l file &

  ;;
esac

echo -e "[*] Restarting process finished. Check your process."