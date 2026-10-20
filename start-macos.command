#!/bin/zsh
cd "${0:A:h}"

if ! command -v python3 >/dev/null 2>&1; then
  osascript -e 'display dialog "Python 3 was not found. Install Python 3 from python.org and start the wizard again." buttons {"OK"} default button "OK" with icon stop'
  exit 1
fi

exec python3 webos_root_wizard.py
