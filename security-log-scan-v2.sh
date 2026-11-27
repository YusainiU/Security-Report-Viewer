#!/usr/bin/env bash
set -u -o pipefail
umask 077
ROOT=${LOG_ROOT:-/var/log}
THRESHOLD=${THRESHOLD:-20}
[[ $THRESHOLD =~ ^[1-9][0-9]*$ ]] || { echo 'Invalid THRESHOLD'; exit 1; }
[[ -d $ROOT ]] || { echo "Missing log directory: $ROOT"; exit 1; }
work=$(mktemp -d) || exit 1
trap 'rm -rf -- "$work"' EXIT
report=$(mktemp "$PWD/security-report-$(date +%Y%m%d-%H%M%S)-XXXXXX.txt") || exit 1
read_logs() {
  local f
  while IFS= read -r -d '' f; do
    if [[ $f == *.gz ]]; then gzip -cd -- "$f"; else cat -- "$f"; fi
  done < <(find "$ROOT" -type f "$@" -print0)
}
read_logs \( -name 'auth.log*' -o -name 'secure' \) > "$work/auth"
if [[ ! -s $work/auth ]] && command -v journalctl >/dev/null; then
  journalctl --since '24 hours ago' -u ssh.service -u sshd.service --no-pager > "$work/auth"
  journalctl --since '24 hours ago' SYSLOG_IDENTIFIER=sudo --no-pager >> "$work/auth"
fi
read_logs -iname '*access*log*' > "$work/access"
read_logs \( -name 'ufw.log*' -o -name 'kern.log*' \) > "$work/firewall"
read_logs \( -path '*/mysql/*error*' -o -path '*/clamav/*log*' \) > "$work/other"
scan() {
  local label=$1 file=$2 pattern=$3 count
  printf '\n=== %s ===\n' "$label"
  count=$(grep -Eic -- "$pattern" "$file" || true)
  printf 'Matching lines: %s\n' "$count"
  grep -Ei -- "$pattern" "$file" | tail -n 15 | cut -c1-1000 | tr -d '\000-\010\013-\037\177' || true
}
{
  echo "SECURITY LOG SCAN v2.0 — $(date -Is)"
  echo "Source: $ROOT (all retained matching logs; journal fallback: 24 hours)"
  echo 'Heuristic findings only; verify before blocking addresses.'
  for f in auth access firewall other; do printf '%s input lines: ' "$f"; wc -l < "$work/$f"; done
  scan 'SSH failures / invalid users' "$work/auth" 'Failed password|Invalid user|authentication failure|Failed publickey'
  scan 'Successful SSH logins — review' "$work/auth" 'Accepted (password|publickey|keyboard-interactive)'
  scan 'Sudo failures' "$work/auth" 'sudo.*(authentication failure|incorrect password|NOT in sudoers)'
  scan 'Sensitive file / exploit probes' "$work/access" '(\.env|%2eenv|\.git/|%2egit|wp-login\.php|xmlrpc\.php|phpmyadmin|/vendor/phpunit|/cgi-bin/)'
  scan 'Possible SQL injection' "$work/access" '(union(%20|\+| )+(all(%20|\+| )+)?select|sleep(%28|\()|information_schema|%27(%20|\+)+or)'
  scan 'Possible XSS / traversal' "$work/access" '(<script|%3cscript|javascript%3a|\.\./|%2e%2e|%252e%252e|/etc/passwd)'
  scan 'HTTP errors — review' "$work/access" '" (403|404|500|502|503) '
  scan 'Firewall blocks — review' "$work/firewall" 'UFW BLOCK'
  scan 'Database authentication / malware' "$work/other" 'Access denied for user| FOUND$'
  printf '\n=== IPs with repeated SSH failures (at least %s) ===\n' "$THRESHOLD"
  awk '/Failed password|Failed publickey|Invalid user/ {for(i=1;i<NF;i++) if($i=="from") {print $(i+1);break}}' "$work/auth" | sort | uniq -c | sort -nr | awk -v n="$THRESHOLD" '$1>=n' | head -30
  printf '\n=== IPs with repeated HTTP 403/404 responses (at least %s) ===\n' "$THRESHOLD"
  awk -F '"' '$3 ~ /^ (403|404) / {split($1,a," ");print a[1]}' "$work/access" | sort | uniq -c | sort -nr | awk -v n="$THRESHOLD" '$1>=n' | head -30
  printf '\n=== Most frequent HTTP clients (all scanned logs) ===\n'
  awk '{print $1}' "$work/access" | sort | uniq -c | sort -nr | head -20
  printf '\n=== Correlated threat analysis by IP ===\n'
  awk -v threshold="$THRESHOLD" '
  FILENAME==ARGV[1] {
    if ($0 !~ /sshd/) next
    ip=""; for(i=1;i<NF;i++) if($i=="from") {ip=$(i+1);break}
    if(ip !~ /^[0-9a-fA-F:.]+$/) next
    if($0 ~ /Failed password|Failed publickey|Invalid user/) {fail[ip]++; seen[ip]=1; prior[ip]=1}
    if($0 ~ /Accepted (password|publickey|keyboard-interactive)/) {ok[ip]++; seen[ip]=1; if(prior[ip]) after[ip]++}
    next
  }
  FILENAME==ARGV[2] {
    ip=$1; if(ip !~ /^[0-9a-fA-F:.]+$/) next
    split($0,q,"\""); req=tolower(q[2]); split(q[3],a," "); status=a[1]
    total[ip]++
    if(status ~ /^(403|404)$/) errors[ip]++
    if(status ~ /^5[0-9][0-9]$/) server[ip]++
    hit=0
    if(req ~ /(union(%20|\+| )+(all(%20|\+| )+)?select|sleep(%28|\()|information_schema|%27(%20|\+)+or)/) {sql[ip]++; hit=1}
    if(req ~ /(\.env|%2eenv|\.git\/|%2egit|wp-login\.php|xmlrpc\.php|phpmyadmin|\/vendor\/phpunit|\/cgi-bin\/)/) {probe[ip]++; hit=1}
    if(req ~ /(<script|%3cscript|javascript%3a|\.\.\/|%2e%2e|%252e%252e|\/etc\/passwd)/) {xss[ip]++; hit=1}
    if(hit) {attacks[ip]++; seen[ip]=1; if(status ~ /^2[0-9][0-9]$/) success[ip]++; else if(status ~ /^5[0-9][0-9]$/) attack5[ip]++; else if(status ~ /^(403|404)$/) denied[ip]++; else other[ip]++}
    if(errors[ip]>=threshold || server[ip]) seen[ip]=1
    next
  }
  FILENAME==ARGV[3] && /UFW BLOCK/ {
    for(i=1;i<=NF;i++) if($i ~ /^SRC=/) {ip=substr($i,5); if(ip ~ /^[0-9a-fA-F:.]+$/) {fw[ip]++;seen[ip]=1};break}
  }
  END {
    for(ip in seen) {
      rank=1; level="INFO"
      if(fw[ip] || errors[ip] || server[ip]) {rank=2;level="LOW"}
      if(attacks[ip] || fail[ip] || errors[ip]>=threshold) {rank=3;level="MEDIUM"}
      if(success[ip] || attack5[ip] || (fail[ip] && ok[ip]) || attacks[ip]>=threshold || fail[ip]>=threshold) {rank=4;level="HIGH"}
      printf "%d %s IP=%s probes=%d SQL=%d sensitive=%d XSS/traversal=%d suspicious_2xx=%d suspicious_5xx=%d suspicious_403/404=%d other_status=%d SSH_fail=%d SSH_ok=%d SSH_ok_after_failure_in_input=%d HTTP_total=%d HTTP_403/404=%d HTTP_5xx=%d firewall=%d\n",rank,level,ip,attacks[ip],sql[ip],probe[ip],xss[ip],success[ip],attack5[ip],denied[ip],other[ip],fail[ip],ok[ip],after[ip],total[ip],errors[ip],server[ip],fw[ip]
    }
  }' "$work/auth" "$work/access" "$work/firewall" | sort -k1,1nr -k3,3 | cut -d' ' -f2-
  echo 'Counts are log entries, not unique incidents. Categories can overlap.'
  echo 'SSH correlation is within retained logs; input order is not reliable chronology.'
  echo '2xx/5xx indicators require investigation; no compromise is established by status alone.'
  printf '\n=== CRITICAL: recorded malware detections (not IP attributed) ===\n'
  scan 'Malware detection records' "$work/other" ' FOUND$'
} | tee "$report" || exit 1
printf '\nReport saved: %s\n' "$report"
