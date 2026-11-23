# MIPAM
Go-based, single-node IP address management with an embedded web interface and SQLite. No Node.js or external database is needed at runtime.

**0.1.0 is an evaluation build, not a production-certified release.** The SAML dependency is flagged by [GO-2026-6909](https://pkg.go.dev/vuln/GO-2026-6909), with no fixed version listed. Keep SAML disabled in production; local login, OIDC and LDAPS are alternatives. The vulnerability CI job intentionally fails rather than suppressing this advisory. Source inspection and a namespace regression test do not constitute advisory clearance.

## Implemented capabilities
- Subnet/address CRUD, VRFs, sites, VLANs, IPv4 grids, sparse IPv6, optimistic concurrency and overlap validation.
- Separate inventory allocation, ping reachability and linked DHCP observations. Unknown is not free; stale DHCP data never silently becomes available.
- Local authentication, OIDC with PKCE, LDAPS direct-group authentication, and an implemented but security-review-blocked SAML SP.
- Administrator/operator/viewer/auditor roles with explicit site grants. Provider operations, global audit, backups and user administration are administrator-only.
- Preview/confirm jobs for Windows DNS/DHCP, PowerDNS, BIND and Kea operations; authorization and before-state rechecked at execution.
- On-demand bounded ping scans and SNMPv3 authPriv raw LLDP/CDP neighbor collection.
- CSV/JSON subnet import preview and atomic create-only apply, scoped JSON inventory export, encrypted backups and offline staged restore.
- Structured operational logs, application audit trail, durable HTTPS/Splunk HEC/TLS-syslog delivery with retries.

## Run locally
From source, use Go 1.26.11 or newer:

```sh
go build -o dist/mipam ./cmd/mipam
cp config.example.json mipam.json
./dist/mipam -config mipam.json bootstrap
./dist/mipam -config mipam.json serve
```

Open **http://127.0.0.1:8080** and sign in as `admin` with the password entered at bootstrap. The password prompt is hidden; there is no default password. Passwords must be 14–72 bytes. For automation, inject `MIPAM_BOOTSTRAP_PASSWORD` using your secret manager and remove it afterward. Do not put passwords in command arguments or source files.

For an extracted binary package, use `./mipam` (Linux) or `.\mipam.exe` (Windows) instead of `./dist/mipam`. All flags precede the command. Relative config paths are resolved from the configuration file's directory. Bootstrap initializes a separate 32-byte backup encryption key. Escrow that key securely outside the host.

Only one process may open a database. Stop the service before CLI bootstrap or backup; the web backup action works while the service is running. Keep SQLite on local storage, not NFS/SMB. Do not run multiple replicas against it.

## Deployment packages
From the repository root:

```sh
go run ./tools/package
```

Produces unsigned archives under `dist/release/`:
- `mipam-0.1.0-linux-amd64.tar.gz`
- `mipam-0.1.0-linux-arm64.tar.gz`
- `mipam-0.1.0-windows-amd64.zip` (includes the Windows connector)
- `SHA256SUMS`

Each archive includes configuration examples, install/uninstall scripts, a CSV template and a CycloneDX 1.5 component inventory generated from each binary's linked Go modules. This is a basic SBOM, not a license audit, provenance attestation or full dependency graph. Checksums detect corruption; these artifacts are **not signed**.

### Linux/systemd
Verify the downloaded checksum against a trusted copy, extract the correct architecture archive, then run `sudo bash install.sh` from the extracted directory. The installer creates an unprivileged `mipam` account, prompts for the initial administrator password, and leaves the service stopped for review.

Paths:
- Binary: `/opt/mipam/mipam`
- Configuration: `/etc/mipam/mipam.json`
- Environment secret references: `/etc/mipam/secrets.env` (root-owned, mode 0600)
- Database, backup key and backups: `/var/lib/mipam`

After reviewing configuration: `sudo systemctl enable --now mipam`. Logs: `journalctl -u mipam`. The service's systemd sandbox only permits writes under `/var/lib/mipam`; adjust it explicitly if storage paths change. `sudo bash uninstall.sh` removes the service registration but preserves binaries, accounts, configuration and data.

Ping scanning requires the OS `ping` utility. With `NoNewPrivileges=true`, use kernel unprivileged ping sockets and configure `net.ipv4.ping_group_range` for the service group if required by your distribution; do not run the web service as root to make ping work.

### Windows
Extract the ZIP to a local folder and run `.\Install.ps1` in an elevated PowerShell session after reviewing the script. Follow your organization's script-signing policy; no execution-policy bypass is required or recommended. Defaults:
- Binary: `%ProgramFiles%\MIPAM\mipam.exe`
- Configuration: `%ProgramData%\MIPAM\mipam.json`
- State: `%ProgramData%\MIPAM\data`
- Service: `MIPAM`, running as `NT AUTHORITY\LocalService`

The installer secures the state directory with Windows ACLs, prompts for bootstrap, and leaves the service stopped. After review, use `Set-Service MIPAM -StartupType Automatic; Start-Service MIPAM`. `.\Uninstall.ps1` removes the service only and preserves data. Installer execution and real Windows service operation still require native acceptance testing; cross-compilation is not proof of runtime compatibility.

Inject environment secrets into the service environment through your approved provisioning mechanism; interactive-shell variables are not automatically inherited by SCM services. Restrict registry/config/key access to administrators and the service identity. The Windows installer sets `log_file` to the protected data directory's `mipam.log`; console stderr logging remains enabled. Arrange external retention/rotation and restart after moving the file.

### TLS and network access
The default listener is loopback only. For remote access:
- Set `public_url` to the exact external HTTPS origin (no application subpath).
- Either keep the loopback listener behind a local HTTPS reverse proxy, or set `tls_cert`/`tls_key` and a non-loopback `listen` address.
- Restrict inbound firewall access. No installer opens firewall ports.
- Keep certificates/private keys readable only by administrators and the service account.
- Trust private CA roots through the OS trust store; provider connections additionally support `ca_file`. TLS verification is never disabled.

`/healthz` reports HTTP liveness and `/readyz` tests database connectivity. They do not certify upstream IdP, DNS, DHCP, SNMP or SIEM health. Behind a proxy, client login throttling currently sees the proxy address, not an untrusted forwarded header.

## Inventory and imports
Create a subnet from **Subnets & addresses**, including its site, VRF and optional VLAN. Click a grid cell to edit an address. New addresses default to unknown; explicitly mark available only according to your allocation policy. Deleting an inventory object does not delete external DNS/DHCP resources.

Use **Import & export** to preview CSV or a JSON array of subnet objects, then apply. CSV requires `name,cidr,site`; optional columns are `vrf,vlan,description` (see `examples/subnets.csv` in source or `subnets.example.csv` in a release archive). Imports are limited to 1,000 subnets and a 2 MiB request. Duplicates/overlaps reject the whole batch. This is create-only: no merge/update or arbitrary column-mapping wizard.

Provider scope reads can populate subnet import candidates. Select the intended site/VRF before applying. Inventory creation never provisions DHCP implicitly. JSON inventory export includes addresses, but the subnet importer does not reimport the entire export; use encrypted backup/restore for full recovery.

## Identity and RBAC
Use `integrations.example.json` as a reference and copy only the integrations you need into your real configuration. Its example endpoints are not runnable credentials.

- **OIDC:** register redirect URI `https://YOUR-HOST/auth/oidc/callback`; set issuer, client ID, secret environment-variable name, group claim and group-to-role/site mappings. Discovery and token validation require HTTPS. The IdP must issue the configured group claim; OIDC group overage/directory expansion is not implemented.
- **AD/LDAP:** set `ldap.url` to `ldaps://dc.example.test:636`, a read-only bind DN, base DN, bind-password environment variable and exact group DN mappings. Uses `sAMAccountName` and direct `memberOf`; nested groups and StartTLS are not implemented. Certificate validation uses the OS trust store.
- **SAML, isolated evaluation only:** set IdP metadata, SP certificate/key files, group attribute and mappings. Metadata endpoint: `/saml/metadata`; ACS: `/saml/acs`; login: `/auth/saml/login`. SP-initiated redirect login, signed requests, request correlation and persistent replay checking are implemented. IdP-initiated login and SAML single logout are disabled. Resolve the advisory above before any production enablement.

Unmapped external groups grant no access. Non-admin users need explicit site grants. Highest mapped role wins; only sites associated with that role are granted, avoiding elevation through lower-role groups. An externally disabled MIPAM account stays disabled. Membership refresh happens at login, not through continuous directory synchronization.

Administrators have global access. Operators can modify granted sites; viewers and auditors can read granted sites. The auditor role does **not** grant global audit access. Per-zone/per-scope DNS/DHCP delegation is not implemented. Keep at least one protected local administrator for IdP outages; there is no unattended password-reset recovery wizard.

## DNS, DHCP and AD connector
All provider writes default off. To enable them, set the provider's `allow_writes` and, for Windows, the connector's `allow_writes`. Use a read-only integration first.

The web provider editor accepts typed JSON requests. Read, inspect the result, preview a proposed write, then explicitly confirm its job ID. Preview expires after 10 minutes. Workers recheck user/provider permission and before-state before execution. These checks reduce stale writes but cannot provide atomic transactions across independent network servers. A timeout can mean an uncertain external outcome: inspect the server before retrying. Interrupted running jobs are not blindly replayed.

Example Windows reservation request:

```json
{"kind":"reservation","action":"create","scope_id":"192.0.2.0","ip":"192.0.2.10","mac":"00:11:22:33:44:55","name":"printer"}
```

### Windows connector setup
The connector is an **inbound mTLS HTTPS listener**, not an outbound polling agent. Place it on a management domain member with Windows PowerShell and the `DnsServer`, `DhcpServer` and/or `ActiveDirectory` modules. It targets exactly one configured server; use separate connectors for different target servers.

1. Copy `mipam-connector.exe` and `connector.example.json` into an administrator-controlled directory. Create `connector.json`, configure `listen`, fixed `server`, server TLS certificate/key and client CA. Set `log_file` to a protected, service-writable log path for persistent service logs.
2. Populate `client_fingerprints` with lowercase hex SHA-256 fingerprints of authorized client certificates (DER certificate bytes), plus allowed DNS zones and DHCP scope network addresses. Defaults deny access. Set `allow_directory` separately for computer reads.
3. Configure the MIPAM `windows` provider with the connector HTTPS URL and client certificate/key. Restrict connector inbound access to the MIPAM server through a reviewed firewall rule.
4. Test read-only console operation using `.\mipam-connector.exe -config C:\MIPAMConnector\connector.json serve`.
5. Register with `.\mipam-connector.exe -config C:\MIPAMConnector\connector.json service-install`. It is installed with manual startup and remains stopped. Before starting, configure the `MIPAMConnector` service's Log On identity to a delegated domain account or provisioned gMSA using standard Windows service administration. Grant only required DNS/DHCP/directory rights and local key-read rights. Never leave it running as LocalSystem or grant Domain Admin merely to make it work.
6. Validate reads, preview and writes in a test zone/scope before enabling production changes. Service commands also include `service-start`, `service-stop`, `service-uninstall`.

The connector runs a fixed embedded PowerShell script with JSON on stdin, never interpolated executable input. Operations are serialized, allowlisted, size-limited and time-bounded.

### Current provider boundaries
- **Windows DNS:** read records; create/update/delete A, AAAA, CNAME and PTR. Writes require a single matching record. MX/TXT/SRV writes and zone provisioning are not implemented. Use relative owner names as returned by Windows (`@` for apex).
- **Windows DHCPv4:** scope create/read/rename/delete, reservation CRUD and lease reads. New scopes start inactive. Scope create needs matching `scope_id` and canonical `cidr`, plus `start`, `end`, `name`. Scope activation, exclusions, options, pool changes, lease mutations and DHCPv6 are not implemented.
- **AD computers:** read-only, at most 1,000 results; no scheduled directory sync or automatic asset correlation.
- **Kea DHCPv4:** sanitized subnet/pool inventory, reservation CRUD when the required commands/hooks are exposed, and bounded lease pages filtered by `subnet_id`. `url` must accept direct DHCPv4 JSON commands; a legacy Control Agent requiring a service selector needs an appropriately configured gateway. No scope configuration writes or automatic full lease pagination. Use the returned `next` cursor as the next request's `ip`.
- **PowerDNS Authoritative:** record CRUD via API, using `server` (usually `localhost`) and API key environment reference. Multi-record RRsets are read-only to avoid deleting unrelated records.
- **BIND:** `kind: "bind"`, `url: "dns-host:53"`, `server` as TSIG key name, `secret_env` referencing the base64 key. Explicit name/type queries and RFC2136 updates with HMAC-SHA256 TSIG. TSIG authenticates but does not encrypt DNS traffic; use a trusted network or tunnel. No AXFR, zone creation or multi-record RRset editing.

To display DHCP leases/reservations in a subnet grid, explicitly select the inventory subnet while reading that provider's DHCP data. Observations are separate from inventory, with a 15-minute freshness threshold. Refresh manually. A snapshot or one Kea page is not proof of complete scope coverage.

## Discovery
Enable scanning per subnet, then request a bounded scan. Maximum 1,024 targets per job, eight workers and 20 launches per second. IPv6 requires an explicit starting address and is never exhaustively enumerated. No-response does not free an address. Cancellation applies to pending jobs; running jobs are bounded but have no interactive cancellation yet.

SNMP devices must be configured explicitly with SNMPv3 SHA256/AES credentials supplied by environment variables. LLDP/CDP results are timestamped raw MIB entries, not a correlated topology map. No automatic FDB/ARP/ND correlation, scheduled scanning or automatic provider refresh exists yet.

## Audit and SIEM
Operational logs are JSON on stderr. Audit records persist in SQLite and are exported when `siem_url` is configured:
- `https://collector.example.test/events`: JSON POST, optional Bearer token from `siem_token_env`.
- `https://splunk.example.test:8088/services/collector/event`: HEC envelope and Splunk authorization.
- `tls://collector.example.test:6514`: RFC5424 messages carrying JSON with octet-counted framing.

The collector must acknowledge HTTP events with a 2xx response; HEC must also return `{"code":0}`. Redirects are rejected. Delivery is at-least-once; deduplicate using event `id`. TLS syslog confirms the socket write, not durable downstream ingestion. A bounded durable outbox retries failures; a full queue rejects new audited mutations instead of silently dropping audit events. Configure a collector before expecting historical events to be delivered: events created while SIEM was disabled are not retroactively enqueued.

For Sentinel/Elastic, route these supported formats through your collector/ingestion pipeline; this is not a native cloud API integration. CEF formatting is not implemented. SQLite audit is append-only through application APIs, not tamper-proof against host/database administrators. Database audit/job retention and Windows log rotation need an operational policy; automatic pruning is not provided.

## Backup, restore and upgrades
Backups use a consistent SQLite snapshot plus configuration encrypted with AES-GCM. Schedule with `backup_hours` (0 disables) and `backup_keep`, or use the administration screen. CLI backup requires stopping the service first. Built-in backup supports snapshots up to **128 MiB**; larger installations require a separately designed offline backup process.

Backups do not contain environment secret values, external certificate/key files, or the backup encryption key. Escrow these separately. Without the original key the backup is not recoverable. Copy encrypted backups off-host; S3 destinations are not built in.

Restore into a **new, nonexistent** staging directory whose parent exists:

```sh
./mipam -config mipam.json -file /secure/mipam-backup.mipambak -destination /secure/restore-staging restore
```

Restore verifies authenticated encryption, checksum, schema and SQLite integrity, clears application sessions/login flows, and marks pending/running/preview jobs interrupted. The staged `config.reference.json` is reference material, not a ready-to-start config: it may still refer to original absolute paths.

For promotion or upgrade:
1. Create and test a pre-change backup; retain the current binary, key, config and external secrets.
2. Stop the service and confirm no process owns the database.
3. For restore, prepare a reviewed config pointing to the staged database, grant the service identity access, and keep external writes disabled. Never overwrite live DB/WAL files while running.
4. For upgrade, replace only the binary after backup, preserving config/data and permissions. Install scripts deliberately refuse existing installations. Schema migrations/rollback beyond schema v1 are not yet provided.
5. Start, check readiness, log in, inspect inventory and reconcile external DNS/DHCP state. Re-enable provider writes only after reconciliation.

Restoring MIPAM does not restore AD/DNS/DHCP. No cross-service rollback is implied.

## Development validation
```sh
go test -timeout 180s ./...
go vet ./...
go test -race -timeout 180s ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go run github.com/mxschmitt/playwright-go/cmd/playwright@v0.6401.0 install chromium
go test -tags browser -run TestBrowserWorkflow -timeout 120s ./internal/app
```

Browser tests exercise login, subnet creation, address editing, import preview/apply, responsive layout and logout. Screenshots are written to `dist/verification/`. Provider tests use mock HTTP servers; they are not live AD/Kea/PowerDNS/BIND certification. CI defines native Linux/Windows unit tests and Linux browser/race/build jobs, but must be run on the repository host before claiming CI success.

## Remaining release work
Besides the boundaries above: resolve the SAML advisory, live IdP/AD/DNS/DHCP/SNMP/SIEM certification, native installer/service acceptance, fine-grained provider RBAC, full DHCP options/exclusions, topology correlation, complete import/recovery UX, load testing, retention and secret-rotation operations. DEB/RPM/MSI, container deployment, signed artifacts and automated upgrade orchestration are not included in this build.
