#!/bin/sh
set -e
export DISPLAY="${DISPLAY:-:99}"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/ms-playwright}"
export DASTDAY_HOME="${DASTDAY_HOME:-/data}"
export KERF_DOCKER=1
mkdir -p "$DASTDAY_HOME"

Xvfb "$DISPLAY" -screen 0 1400x900x24 -ac +extension RANDR >/tmp/xvfb.log 2>&1 &
sleep 1
x11vnc -display "$DISPLAY" -forever -shared -nopw -listen 127.0.0.1 -rfbport 5900 >/tmp/x11vnc.log 2>&1 &
cat > /usr/share/novnc/index.html <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0; url=vnc.html?autoconnect=1&resize=scale">
<title>Kerf browser</title>
<script>location.replace("vnc.html?autoconnect=1&resize=scale")</script>
</head>
<body>
<p><a href="vnc.html?autoconnect=1&resize=scale">Open the Kerf browser</a></p>
</body>
</html>
EOF
if command -v websockify >/dev/null 2>&1; then
  websockify --web /usr/share/novnc 6080 127.0.0.1:5900 >/tmp/novnc.log 2>&1 &
elif [ -x /usr/share/novnc/utils/novnc_proxy ]; then
  /usr/share/novnc/utils/novnc_proxy --vnc 127.0.0.1:5900 --listen 6080 >/tmp/novnc.log 2>&1 &
fi

exec python main.py \
  --proxy-host 0.0.0.0 \
  --ui-host 0.0.0.0 \
  --db /data/dastday.db
