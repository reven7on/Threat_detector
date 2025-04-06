#!/bin/sh
# Отладочный скрипт для диагностики проблем на Render

echo "=== SYSTEM INFORMATION ==="
uname -a
echo

echo "=== ENVIRONMENT VARIABLES ==="
env
echo

echo "=== FILE SYSTEM ==="
echo "Root directory:"
ls -la /
echo

echo "App directory:"
ls -la /app
echo

echo "=== PROCESSES ==="
ps aux
echo

echo "=== NETWORK ==="
netstat -tulpn
echo

echo "=== NGINX STATUS ==="
service nginx status || echo "Nginx status command failed"
echo

echo "=== NGINX CONFIG ==="
nginx -T || echo "Nginx config test failed"
echo

echo "=== START SERVICES SCRIPT ==="
if [ -f /start-services.sh ]; then
    echo "Content of /start-services.sh:"
    cat /start-services.sh
    echo "Permissions:"
    ls -la /start-services.sh
else
    echo "File /start-services.sh NOT FOUND!"
fi
echo

if [ -f /app/start-services.sh ]; then
    echo "Content of /app/start-services.sh:"
    cat /app/start-services.sh
    echo "Permissions:"
    ls -la /app/start-services.sh
else
    echo "File /app/start-services.sh NOT FOUND!"
fi
echo

echo "=== TRYING TO RUN SCRIPT ==="
if [ -f /start-services.sh ]; then
    echo "Trying to run /start-services.sh (as sh script):"
    sh -x /start-services.sh || echo "Failed to run as sh script"
fi
echo 