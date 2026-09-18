#!/bin/bash
# Usage: ./set_target.sh <url> <app_type> [username] [password]
# app_type: dvwa | juiceshop | generic

URL=$1
APP_TYPE=${2:-generic}
USERNAME=${3:-}
PASSWORD=${4:-}

cat > /opt/dast-platform/config.json << JSON
{
  "target_url": "$URL",
  "app_type": "$APP_TYPE",
  "credentials": {
    "username": "$USERNAME",
    "password": "$PASSWORD"
  }
}
JSON

echo "Target set to: $URL (app_type: $APP_TYPE)"
cat /opt/dast-platform/config.json
