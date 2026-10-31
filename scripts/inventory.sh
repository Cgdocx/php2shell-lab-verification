#!/usr/bin/env bash
# Lab inventory for php2shell patch verification (no exploit traffic).
set -euo pipefail
cd /lab/php2shell
export PATH="/lab/php2shell/bin:$PATH"

echo "=== inventory: php2shell patch check ==="
date -R
printf 'hostname: '; hostname
printf 'uname: '; uname -srm
echo

echo "# which php && php -v"
which php
php -v
echo

echo "# binary path + version constants"
php -r 'echo "PHP_VERSION=", PHP_VERSION, " SAPI=", PHP_SAPI, "\n";'
readlink -f "$(which php)"
echo

echo "# temporary mitigation file (must be loaded by FPM/Apache and workers restarted)"
grep -n 'session.upload_progress' conf/php.ini-mitigation.conf
echo "# check with: php -c conf/php.ini-mitigation.conf -i | grep upload_progress.enabled"
php -c conf/php.ini-mitigation.conf -i 2>/dev/null | grep -F 'session.upload_progress.enabled' || true
echo

echo "# webroot baseline (sha256)"
find webroot -type f -print0 | sort -z | xargs -0 sha256sum
echo

echo "# fixed builds cited by CISA alert 2026-10-21: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35"
echo "https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching"
echo "lab runtime: $(php -r 'echo PHP_VERSION;') on 8.4 branch (patched floor 8.4.27)"
