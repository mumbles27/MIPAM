#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then
  printf '%s\n' 'Run this installer as root after verifying the archive checksum.' >&2
  exit 1
fi
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
for command in systemctl install useradd getent runuser; do
  command -v "$command" >/dev/null || { printf 'Required command missing: %s\n' "$command" >&2; exit 1; }
done
[[ -f "$HERE/mipam" && -f "$HERE/mipam.service" ]] || { printf '%s\n' 'Extract the complete release archive first.' >&2; exit 1; }
if [[ -e /opt/mipam/mipam || -e /var/lib/mipam/mipam.db ]]; then
  printf '%s\n' 'Existing installation detected. Follow the backup/upgrade procedure in README.md; this installer never overwrites an installation.' >&2
  exit 1
fi
if ! getent passwd mipam >/dev/null; then
  useradd --system --user-group --home-dir /var/lib/mipam --shell /usr/sbin/nologin mipam
fi
install -d -m 0755 /opt/mipam
install -d -m 0750 -o root -g mipam /etc/mipam
install -d -m 0700 -o mipam -g mipam /var/lib/mipam
install -m 0755 "$HERE/mipam" /opt/mipam/mipam
if [[ ! -e /etc/mipam/mipam.json ]]; then
  install -m 0640 -o root -g mipam /dev/null /etc/mipam/mipam.json
  cat > /etc/mipam/mipam.json <<'JSON'
{
  "listen": "127.0.0.1:8080",
  "public_url": "http://127.0.0.1:8080",
  "database": "/var/lib/mipam/mipam.db",
  "backup_dir": "/var/lib/mipam/backups",
  "backup_key_file": "/var/lib/mipam/backup.key",
  "backup_hours": 24,
  "backup_keep": 14
}
JSON
fi
if [[ ! -e /etc/mipam/secrets.env ]]; then
  install -m 0600 -o root -g root /dev/null /etc/mipam/secrets.env
fi
runuser -u mipam -- /opt/mipam/mipam -config /etc/mipam/mipam.json bootstrap
install -m 0644 "$HERE/mipam.service" /etc/systemd/system/mipam.service
systemctl daemon-reload
printf '%s\n' 'Installed; service has NOT been enabled or started.' \
  'Review /etc/mipam/mipam.json, preserve a separate copy of backup.key, then run:' \
  '  systemctl enable --now mipam' \
  'Loopback URL: http://127.0.0.1:8080. Configure TLS before exposing remotely.'
