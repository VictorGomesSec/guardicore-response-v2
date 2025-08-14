#!/bin/bash

# Installation script

PYTHON_VERSION_REQUIRED=3.13.1
VIRTUAL_ENV=.venv
APP_NAME=run.py
IOC_NAME=ioc_manager.py

INTEGRATIONS_CONFIG=integrations.yml
COMPANIES_CONFIG=companies.yml
IOC_DB_PATH=$PWD/ioc.db

check_prerequisites() {
  echo "[*] - APT UPDATE."
  sudo apt update -y

  echo "[*] - Checking prerequisites."

  echo "[!] - Checking CURL CMD"
  curl --help &>/dev/null || sudo apt install -y curl

  echo "[!] - Checking CRON JOB"
  crontab -l &>/dev/null || sudo apt install -y cron

  echo "[!] - Checking UV prerequisites."
  uv help &>/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh
  source $HOME/.local/bin/env

  uv python install $PYTHON_VERSION_REQUIRED
  uv venv --seed --python $PYTHON_VERSION_REQUIRED $VIRTUAL_ENV
  source $VIRTUAL_ENV/bin/activate

  versions=$(compgen -c | grep -E -i  '^python[\.0-9]{0,4}$' | sort | uniq | xargs which)

  echo "[*]   - Checking Python version"
  for ver in $versions
  do
      eval "$ver --version" 2>/dev/null | grep -i -E '3\.1[2-3]' 1>/dev/null
      if [[ $? -eq 0 ]]
      then
          PYTHON_VER=$ver
          break
      fi
  done

  if [[ -v PYTHON_VER ]];
  then
    echo "[!]     Python found $PYTHON_VER"
  else
    echo "[!]     ERROR: No supported Python version found. 3.13+."
    exit 1
  fi

  echo "[!] PYTHON SUITE: $PYTHON_VER - `$PYTHON_VER --version` - $VIRTUAL_ENV "

  set -e
  echo "[*] - Installing requirements"
  uv sync
  set +e


  echo "[*]   - Backing up current cron jobs"
  if [ -s "$PWD"/crontab.bck ]
  then
    echo " file exists and is not empty " &> /dev/null
  else
    echo " file does not exist, or is empty " &> /dev/null
    crontab -l > crontab.bck
  fi

}

echo "[*] Lumu Integration installation script"

INSTALL_OPTION=$1
case $INSTALL_OPTION in

  ioc*)
    echo "[*] Stage: IOC Management."
    check_prerequisites
    echo "[*] - Installing"
    echo "[*]   - Checking configuration files."
    if ! [ -s $PWD/$COMPANIES_CONFIG ]
    then
      echo "[!]   ERROR: File $PWD/$COMPANIES_CONFIG not found. Make sure it exists and it's configured properly to start the IOC Manager."
      exit 1
    fi
    echo "[*]   - Adding cron job for IOC Management."
    cron_line_ioc="1*/5 1* 1* 1* 1* cd $PWD && `which python` $PWD/$IOC_NAME --config $PWD/$COMPANIES_CONFIG -l file"
    (crontab -l; echo  -e $cron_line_ioc | sed 's/1\*/\*/g' -) | sort | uniq | crontab -
    echo "[*] - Running IOC Management"
    cd $PWD && `which python` $PWD/$IOC_NAME --config $PWD/$COMPANIES_CONFIG -l file &
    echo -e "[!] The installation process has completed."
  ;;
  all|both)
    echo "[*] Stage: IOC Management and App Integration."
    check_prerequisites
    echo "[*] - Installing"
    echo "[*]   - Checking configuration files."
    if ! [ -s $PWD/$COMPANIES_CONFIG ]
    then
      echo "[!]   ERROR: File $PWD/$COMPANIES_CONFIG not found. Make sure it exists and it's configured properly to start the IOC Manager."
      exit 1
    fi
    if ! [ -s $PWD/$INTEGRATIONS_CONFIG ]
    then
      echo "[!]   ERROR: File $PWD/$INTEGRATIONS_CONFIG not found. Make sure it exists and it's configured properly to start the integration."
      exit 1
    fi
    echo "[*]   - Adding cron job for App integration."
    cron_line_app="1*/5 1* 1* 1* 1* cd $PWD && `which python` $PWD/$APP_NAME --config $PWD/$INTEGRATIONS_CONFIG --ioc-manager-db-path $IOC_DB_PATH -l file"
    echo "[*]   - Adding cron job for IOC Manager."
    cron_line_ioc="1*/5 1* 1* 1* 1* cd $PWD && `which python` $PWD/$IOC_NAME --config $PWD/$COMPANIES_CONFIG -l file"
    (crontab -l; echo  -e $cron_line_ioc | sed 's/1\*/\*/g' -; echo  -e $cron_line_app | sed 's/1\*/\*/g' -) | sort | uniq | crontab -
    echo "[*] - Running IOC Management"
    cd $PWD && `which python` $PWD/$IOC_NAME --config $PWD/$COMPANIES_CONFIG -l file &
    echo -e "[!] The installation process has completed."
  ;;
  help|-h|--help|-help)
    echo "[*] Showing installation help reference."
    cat <<EOF
./install.sh help
./install.sh app [IOC_DB_PATH] -> install the integration pointing to the IOC_DB_PATH full path as a source of the LUMU IOC, default: ./ioc.db
./install.sh ioc               -> install only a IOC Manager dumping the Lumu IOC in ./ioc.db
./install.sh all               -> install both at once, IOC Manager and The integration in one application
./install.sh both              -> install both at once, IOC Manager and The integration in one application
EOF
  ;;
  app)
    echo "[*] Stage: App Integration."
    check_prerequisites
    echo "[*] Installing"
    echo "[*]   - Checking configuration files."
    if ! [ -s $PWD/$INTEGRATIONS_CONFIG ]
    then
      echo "[!]   ERROR: File $PWD/$INTEGRATIONS_CONFIG not found. Make sure it exists and it's configured properly to start the Integration"
      exit 1
    fi
    if [[ -s $2 ]];
    then
      IOC_DB_PATH=$2
    fi
    echo "[*]   - Adding cron job for App integration."
    cron_line_app="1*/5 1* 1* 1* 1* cd $PWD && `which python` $PWD/$APP_NAME --config $PWD/$INTEGRATIONS_CONFIG --ioc-manager-db-path $IOC_DB_PATH -l file"
    (crontab -l; echo  -e $cron_line_app | sed 's/1\*/\*/g' -) | sort | uniq | crontab -
    echo -e "[!]   The installation process has completed."
  ;;
  *)
    echo -e "[!] ERROR: No valid option, use \"./install --help\" for help"
    exit 1
  ;;
esac

cat << EOF > .integrations_vars.sh
IOC_DB_PATH=$IOC_DB_PATH
EOF