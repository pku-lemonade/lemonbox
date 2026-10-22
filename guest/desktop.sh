#!/bin/bash
set -euo pipefail
password_file="$HOME/.config/lemonbox/vnc-password"
if [[ ! -s "$password_file" ]]; then
  echo 'VNC password is not configured; start the desktop with lemonbox desktop on the host.' >&2
  exit 1
fi
export DISPLAY=:0
Xvfb :0 -screen 0 1440x900x24 -nolisten tcp &
xvfb_pid=$!
trap 'kill "$xvfb_pid" 2>/dev/null || true' EXIT
for _ in {1..50}; do
  if xdpyinfo -display :0 >/dev/null 2>&1; then break; fi
  sleep 0.1
done
xdpyinfo -display :0 >/dev/null
x11vnc -norc -display :0 -localhost -passwdfile "$password_file" -forever -shared -rfbport 5900 -quiet &
exec dbus-run-session -- startxfce4
