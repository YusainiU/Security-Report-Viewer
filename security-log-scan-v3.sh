#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT=${LOG_ROOT:-/var/log}
THRESHOLD=${THRESHOLD:-20}
days=all
from=
to=
format=both
output="$PWD"
max_bytes=67108864
verbose=0
while (($#)); do
 case "$1" in
 --help) echo 'Usage: security-log-scan-v3.sh [--all | --days N | --from YYYY-MM-DD --to YYYY-MM-DD] [--format text|json|both] [--output DIR] [--threshold N] [--max-bytes N] [--verbose]'; exit 0;;
 --all) days=all; from=; to=; shift;;
 --verbose) verbose=1; shift;;
 --days|--from|--to|--format|--output|--threshold|--max-bytes)
 (($# >= 2)) || { echo "Missing value for $1" >&2; exit 2; }
 case "$1" in
 --days) days=$2;; --from) from=$2;; --to) to=$2;; --format) format=$2;; --output) output=$2;; --threshold) THRESHOLD=$2;; --max-bytes) max_bytes=$2;;
 esac; shift 2;;
 *) echo "Unknown option: $1" >&2; exit 2;;
 esac
done
[[ $THRESHOLD =~ ^[1-9][0-9]{0,8}$ && $max_bytes =~ ^[1-9][0-9]{0,9}$ ]] || exit 2
[[ $format == text || $format == json || $format == both ]] || exit 2
[[ -d $ROOT && -d $output ]] || { echo 'Log or output directory missing' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'Python 3 is required' >&2; exit 2; }
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 - "$ROOT" "$work" "$days" "$from" "$to" "$max_bytes" "$verbose" <<'PY'
import sys, os, gzip, json, re, fnmatch, stat, datetime as dt, time
root, work, days, start, end, limit, verbose = sys.argv[1:]
limit=int(limit)
now=dt.datetime.now().astimezone()
def date(s): return dt.date.fromisoformat(s)
try:
    if days!='all':
        if start or end or not days.isdecimal() or not 1<=int(days)<=36500: raise ValueError('invalid date options')
        lower=now-dt.timedelta(days=int(days)); upper=now
    elif start or end:
        if not start or not end or date(start)>date(end): raise ValueError('invalid date range')
        lower=dt.datetime.combine(date(start),dt.time.min).astimezone()
        upper=dt.datetime.combine(date(end)+dt.timedelta(days=1),dt.time.min).astimezone()
    else: lower=upper=None
except (ValueError, OverflowError) as e: sys.exit(str(e))
def timestamp(line):
    m=re.search(r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]',line[:512])
    try:
        if m: return dt.datetime.strptime(m[1],'%d/%b/%Y:%H:%M:%S %z')
        m=re.match(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?',line)
        if m: return dt.datetime.fromisoformat(m[0].replace('Z','+00:00')).astimezone()
        # Yearless syslog timestamps cannot be reliably dated in rotated logs.
    except ValueError: pass
    return None
groups={k:dict(files=0,read=0,failed=0,unknown_dates=0,lines=0) for k in ('auth','access','firewall','other')}
outs={k:open(os.path.join(work,k),'wb') for k in groups}
errors=[]; used=0; truncated=False; deadline=time.monotonic()+120
def error(e):
    if len(errors)<100: errors.append(str(e))
def category(path):
    n=os.path.basename(path).lower()
    if n.startswith('auth.log') or n=='secure': return 'auth'
    if 'access' in n and 'log' in n: return 'access'
    if n.startswith(('ufw.log','kern.log')): return 'firewall'
    if ('/mysql/' in path and 'error' in n) or ('/clamav/' in path and 'log' in n): return 'other'
for base, dirs, files in os.walk(root,onerror=error,followlinks=False):
    if truncated: break
    for name in files:
        path=os.path.join(base,name); k=category(path)
        if not k: continue
        g=groups[k]; g['files']+=1
        try:
            if not stat.S_ISREG(os.lstat(path).st_mode): raise OSError('not a regular file or symbolic link')
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as raw:
                if not stat.S_ISREG(os.fstat(raw.fileno()).st_mode): raise OSError('not a regular file')
                stream=gzip.GzipFile(fileobj=raw) if name.endswith('.gz') else raw
                while True:
                    if used>=limit or time.monotonic()>deadline: truncated=True; break
                    b=stream.readline(min(65537,limit-used))
                    if not b: break
                    used+=len(b)
                    if len(b)>65536 or not b.endswith(b'\n'):
                        # Discard incomplete/oversized records, including remaining fragments.
                        while b and not b.endswith(b'\n') and used<limit and time.monotonic()<deadline:
                            b=stream.readline(min(65537,limit-used)); used+=len(b)
                        g['failed']+=1; continue
                    if lower:
                        t=timestamp(b.decode('utf-8','replace'))
                        if t is None: g['unknown_dates']+=1; continue
                        if not lower<=t<upper: continue
                    outs[k].write(b); g['lines']+=1
                if not truncated: g['read']+=1
        except (OSError, EOFError, ValueError) as e: g['failed']+=1; error(f'{path}: {e}')
        if truncated: break
for f in outs.values(): f.close()
meta=dict(scanner_version='3.0.0',schema_version=3,started_at=now.isoformat(),hostname=os.uname().nodename,source=root,range_start=lower.isoformat() if lower else None,range_end_exclusive=upper.isoformat() if upper else None,bytes_read=used,max_bytes=limit,truncated=truncated,coverage=groups,errors=errors)
meta['scan_status']='partial' if truncated or errors or any(g['failed'] or g['unknown_dates'] or not g['read'] for g in groups.values()) else 'complete'
with open(os.path.join(work,'metadata.json'),'w') as f: json.dump(meta,f,ensure_ascii=True)
if verbose=='1': print(json.dumps(meta,indent=2),file=sys.stderr)
PY
report=$(mktemp "$output/security-report-$(date +%Y%m%d-%H%M%S)-XXXXXX.txt")
scan() {
  local label=$1 file=$2 pattern=$3 count
  printf '\n=== %s ===\n' "$label"
  count=$(grep -Eic -- "$pattern" "$file" || true)
  printf 'Matching lines: %s\n' "$count"
  grep -Ei -- "$pattern" "$file" | tail -n 15 | cut -c1-1000 | tr -d '\000-\010\013-\037\177' || true
}
{
  echo "SECURITY LOG SCAN v3.0 — $(date -Is)"
  echo "Source: $ROOT (see scan coverage and date range)"
  echo 'Heuristic findings only; verify before blocking addresses.'
  printf '\n=== Scan coverage and metadata ===\n'
  python3 -m json.tool "$work/metadata.json"
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
  awk '/Failed password|Failed publickey|Invalid user/ {for(i=1;i<NF;i++) if($i=="from") {print $(i+1);break}}' "$work/auth" | sort | uniq -c | sort -nr | awk -v n="$THRESHOLD" '$1>=n' | sed -n '1,30p'
  printf '\n=== IPs with repeated HTTP 403/404 responses (at least %s) ===\n' "$THRESHOLD"
  awk -F '"' '$3 ~ /^ (403|404) / {split($1,a," ");print a[1]}' "$work/access" | sort | uniq -c | sort -nr | awk -v n="$THRESHOLD" '$1>=n' | sed -n '1,30p'
  printf '\n=== Most frequent HTTP clients (all scanned logs) ===\n'
  awk '{print $1}' "$work/access" | sort | uniq -c | sort -nr | sed -n '1,20p'
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
} > "$report" || exit 1

if [[ $format != text ]]; then
 json_report=${report%.txt}.json
 python3 - "$work/metadata.json" "$report" "$json_report" <<'PY'
import json,sys,os
with open(sys.argv[1]) as f: data=json.load(f)
with open(sys.argv[2],encoding='utf-8',errors='replace') as f: data['report_text']=f.read()
data['threats']=[]
in_threats=False
for line in data['report_text'].splitlines():
    if line.startswith('=== '): in_threats=line=='=== Correlated threat analysis by IP ==='
    if in_threats and ' IP=' in line:
        fields=line.split()
        counts={}
        for field in fields[2:]:
            key, value=field.split('=',1)
            counts[key]=int(value)
        data['threats'].append(dict(severity=fields[0],ip=fields[1][3:],counts=counts))
with open(sys.argv[3],'x') as f: json.dump(data,f,ensure_ascii=True,indent=2)
PY
 printf 'Report saved: %s\n' "$json_report"
fi
if [[ $format == json ]]; then rm -- "$report"; else printf 'Report saved: %s\n' "$report"; fi
