#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID} -eq 0 ]] || { printf '%s\n' 'Run as root.' >&2; exit 1; }
systemctl disable --now mipam
rm -f /etc/systemd/system/mipam.service
systemctl daemon-reload
printf '%s\n' 'Service removed. Binaries, configuration, account, backup key and all data were retained.' \
  'Paths: /opt/mipam, /etc/mipam, /var/lib/mipam'
