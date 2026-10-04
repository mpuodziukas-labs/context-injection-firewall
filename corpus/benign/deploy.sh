#!/bin/bash
# Deploy the demo site. Synthetic example.
# установка зависимостей перед сборкой
set -euo pipefail
npm ci
npm run build
rsync -a --delete dist/ deploy@host.example.com:/srv/site/
curl -fsS https://host.example.com/health
echo "deployed"
