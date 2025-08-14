#!/bin/bash
# Uninstallation script

VIRTUAL_ENV=.venv
APP_NAME=run.py
IOC_NAME=ioc_manager.py

echo "[*] Lumu integration uninstallation script"

UNINSTALL_OPTION=$1
case $UNINSTALL_OPTION in

  ioc*)
    echo "[*] Stage: IOC Management."
    ps -ax | grep -i $PWD | grep -i $IOC_NAME | grep -v grep |  awk '{ print $1 }' | xargs kill -9 2>/dev/null
    crontab -l | sed  "\|$PWD/$IOC_NAME|d" | crontab -
  ;;
  all|both)
    echo "[*] Stage: IOC Management and App Integration."
    ps -ax | grep -i $PWD | grep -i $APP_NAME | grep -v grep |  awk '{ print $1 }' | xargs kill -9 2>/dev/null
    ps -ax | grep -i $PWD | grep -i $IOC_NAME | grep -v grep |  awk '{ print $1 }' | xargs kill -9 2>/dev/null
    crontab -l | sed  "\|$PWD|d" | crontab -
    echo "[*] - Cleaning Integration, go get a cup of Coffe ..."
    cd $PWD && $PWD/$VIRTUAL_ENV/bin/python $PWD/${APP_NAME} --clean
    echo -e "[!] The Cleaning process has completed."

    rm -rf $PWD/lumu.log $PWD/errors.log $PWD/$VIRTUAL_ENV

  ;;
  help|-h|--help|-help)
    echo "[*] Showing installation help reference."
        cat <<EOF
./uninstall.sh help
./uninstall.sh app      -> uninstall the integration, stop and kill the process
./uninstall.sh ioc      -> uninstall only a IOC Manage, , stop and kill the process
./uninstall.sh all      -> uninstall both at once, IOC Manager and The integration in one application, remove virtual env as well
./uninstall.sh both     -> uninstall both at once, IOC Manager and The integration in one application, remove virtual env as well
EOF
  ;;
  app|*)
    echo "[*] Stage: App Integration."
    ps -ax | grep -i $PWD | grep -i $APP_NAME | grep -v grep |  awk '{ print $1 }' | xargs kill -9 2>/dev/null
    crontab -l | sed  "\|$PWD/$APP_NAME|d" | crontab -
    echo "[*] - Cleaning Integration, go get a cup of Coffe ..."
    cd $PWD && $PWD/$VIRTUAL_ENV/bin/python $PWD/${APP_NAME} --clean
    echo -e "[!] The Cleaning process has completed."
  ;;
esac

echo -e "[*] Uninstallation process finished. Check your cron job list to check there are no traces of scheduled tasks."