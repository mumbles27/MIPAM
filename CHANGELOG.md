# Changelog
All notable changes to MIPAM are recorded here. Versions follow [semantic versioning](https://semver.org/). Dates are ISO-8601.

Every release so far is an **unsigned evaluation build**. None has been certified for production use. See [ROADMAP.md](ROADMAP.md) for what has to be true before that claim can be made.

## [0.2.0] — 2026-11-23
Bug-fix release. The headline item is a defect that made a shipped feature fail completely on a default Linux host.

### Fixed
- **Ping scanning failed entirely under the packaged systemd unit.** Every probe returned `probe errors` instead of reachability results, so the feature produced no usable data on an installed service. `NoNewPrivileges=true` strips `ping`'s `cap_net_raw` file capability, and distributions such as Ubuntu Server ship an empty `net.ipv4.ping_group_range`, leaving no unprivileged ICMP socket either. The unit now grants `AmbientCapabilities=CAP_NET_RAW` with a matching `CapabilityBoundingSet`, which leaves the rest of the sandbox intact; `systemd-analyze security` still rates the unit MEDIUM.

  This was only reproducible through the service. Interactive `ping` in a shell works normally on an affected host, which is why the gap survived earlier review.

### Changed
- The release version was hard-coded separately in the CLI, the service status API and the packaging tool. All three now read a single `internal/version` constant, removing the drift that this release had to reconcile by hand.
- The web UI footer label moved from `MIPAM 0.1` to `MIPAM 0.2`.
- Deployment documentation corrected. It previously advised relying on kernel unprivileged ping sockets, which is precisely what is unavailable by default; it now describes the capability grant, names the `probe errors` symptom, and records the `ping_group_range` alternative for sites whose policy forbids granting capabilities.
- Release archives are rebuilt at 0.2.0 and the superseded 0.1.0 archives were removed from `main`. The `v0.1.0` tag retains its own copies, so existing download links still resolve.

### Verified
Dashboard walkthrough against an installed service on a Linux VM, exercising authentication, subnet and address CRUD, optimistic-locking conflicts, CSV import preview and atomic apply, provider and observation pages, jobs, audit, user administration, encrypted backup, inventory export, and the CSRF, cross-origin and RBAC controls. Ping scanning was re-tested after the fix and correctly distinguished reachable from no-response targets.

### Upgrading from 0.1.0
`install.sh` refuses existing installations and never rewrites a deployed unit, so replacing the binary alone does **not** fix scanning. Add the two capability lines to `/etc/systemd/system/mipam.service` under `[Service]`, then reload and restart:

```sh
sudo systemctl daemon-reload && sudo systemctl restart mipam
```

No data or configuration change is required.

## [0.1.0] — 2026-11-22
Initial evaluation release.

### Added
- Subnet and address inventory with VRFs, sites, VLANs, IPv4 address grids, sparse IPv6, optimistic concurrency and overlap validation.
- Allocation state tracked separately from ping reachability and from linked DHCP observations, so unknown is never treated as free and stale DHCP data never silently becomes available.
- Local authentication, OIDC with PKCE, LDAPS direct-group authentication, and a SAML SP that is implemented but blocked from production use by a dependency advisory.
- Administrator, operator, viewer and auditor roles with explicit site grants. Provider operations, global audit, backups and user administration are administrator-only.
- Preview-and-confirm jobs for Windows DNS/DHCP, PowerDNS, BIND and Kea, rechecking authorization and before-state at execution time.
- Bounded on-demand ping scans and SNMPv3 authPriv raw LLDP/CDP neighbor collection.
- CSV/JSON subnet import with preview and atomic create-only apply, scoped JSON inventory export, AES-GCM encrypted backups and offline staged restore.
- Structured operational logs, a persisted audit trail, and durable HTTPS, Splunk HEC and TLS-syslog delivery with retries and a bounded outbox.
- Unsigned Linux amd64/arm64 and Windows amd64 packages with install/uninstall scripts, CycloneDX component inventories and SHA-256 checksums.

### Known issues
- Ping scanning is broken in the Linux archives for this version. Fixed in 0.2.0; see the upgrade note above.

[0.2.0]: https://github.com/mumbles27/MIPAM/releases/tag/v0.2.0
[0.1.0]: https://github.com/mumbles27/MIPAM/releases/tag/v0.1.0
