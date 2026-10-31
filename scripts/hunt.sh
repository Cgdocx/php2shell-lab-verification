#!/usr/bin/env bash
# Defensive hunt helpers after php2shell disclosure. No exploit traffic.
set -euo pipefail
cd /lab/php2shell
export PATH="/lab/php2shell/bin:$PATH"

echo "=== hunt: worker / webroot / crash signals ==="
date -R
hostname
echo

echo "# confirm patched binary still first on PATH"
php -v | head -1
readlink -f "$(which php)"
echo

echo "# php / httpd / fpm processes"
ps -eo pid,ppid,user,cmd --sort=pid | grep -E '[p]hp-fpm|[p]hp-cgi|[a]pache2|[h]ttpd|[f]rankenphp' \
  || echo "(no web SAPI processes on this lab host)"
echo

echo "# children of php-fpm/httpd that look like shells or downloaders"
mapfile -t parents < <(ps -eo pid=,cmd= | awk '/php-fpm: pool|apache2|httpd|php-cgi/ {print $1}')
if ((${#parents[@]}==0)); then
  echo "(no php/httpd parents - skip child shell check)"
else
  found=0
  while read -r pid ppid user cmd; do
    for p in "${parents[@]}"; do
      if [[ "$ppid" == "$p" ]]; then
        if echo "$cmd" | grep -Eq '(^|/)(sh|bash|dash|curl|wget|python|perl|ncat|nc)( |$)'; then
          echo "ALERT parent=$ppid pid=$pid user=$user cmd=$cmd"
          found=1
        fi
      fi
    done
  done < <(ps -eo pid=,ppid=,user=,cmd=)
  if ((found==0)); then
    echo "(no shell/downloader children under php/httpd)"
  fi
fi
echo

echo "# webroot mtime + hash"
find webroot -type f -printf '%T+ %p\n' | sort
find webroot -type f -print0 | sort -z | xargs -0 sha256sum
echo

echo "# crash / OOM breadcrumbs"
if command -v journalctl >/dev/null; then
  journalctl -k -b --no-pager 2>/dev/null | grep -Ei 'php|segfault|oom|out of memory' | tail -n 20 || true
fi
dmesg -T 2>/dev/null | grep -Ei 'php|segfault|oom' | tail -n 10 || true
echo "(end kernel breadcrumbs)"
echo

echo "# mitigation file in lab"
cat conf/php.ini-mitigation.conf
echo
echo "hunt done - if ALERT lines or unexpected webroot files: image before clean."
