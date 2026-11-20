#!/bin/sh

CONFIG_FILE="/etc/nginx/blue-ai/security-headers.conf"

echo "Starting Nginx..."

nginx -g 'daemon off;' &
NGINX_PID=$!

while kill -0 "$NGINX_PID" 2>/dev/null; do
    if [ -s /run/nginx.pid ]; then
        break
    fi
    sleep 0.5
done

sleep 1

if ! kill -0 "$NGINX_PID" 2>/dev/null; then
    echo "Nginx failed to start."
    exit 1
fi

LAST_HASH=$(cksum "$CONFIG_FILE" 2>/dev/null | awk '{print $1 ":" $2}')

echo "Nginx started successfully."
echo "Watching Blue AI configuration..."

while kill -0 "$NGINX_PID" 2>/dev/null; do

    CURRENT_HASH=$(cksum "$CONFIG_FILE" 2>/dev/null | awk '{print $1 ":" $2}')

    if [ -n "$CURRENT_HASH" ] && [ "$CURRENT_HASH" != "$LAST_HASH" ]; then

        echo "Blue AI configuration change detected."

        if nginx -t; then

            if nginx -s reload; then
                LAST_HASH="$CURRENT_HASH"
                echo "Nginx configuration reloaded successfully."
            else
                echo "Nginx reload failed. Will retry."
            fi

        else
            echo "Invalid configuration. Reload rejected. Will retry."
        fi

    fi

    sleep 3

done

echo "Nginx process stopped."
wait "$NGINX_PID"