# Roadmap
What is planned for MIPAM after [0.2.0](CHANGELOG.md), in priority order. This is a statement of intent, not a commitment; there are no dates.

Items are listed under the release that is expected to carry them. Anything not listed here is not planned. A capability is only described as working once it has been exercised against the thing it claims to support — a passing unit test is not evidence that a packaged installer works, and a cross-compiled binary is not evidence of runtime compatibility.

## Production-readiness gate
MIPAM is an evaluation build and will keep saying so until all of the following are true. These are tracked across the milestones below rather than as a separate workstream.

- The SAML dependency advisory [GO-2026-6909](https://pkg.go.dev/vuln/GO-2026-6909) is resolved, or the SAML SP is removed. There is no published fix; source inspection is not clearance.
- Both installers have been run end to end on their native platforms, including service startup, health, upgrade and uninstall.
- Each integration has been certified against a live system, not a mock: IdP, Active Directory, DNS, DHCP, SNMP and a SIEM collector.
- Capacity and failure behaviour are measured rather than assumed.

## 0.3.0 — Deployment acceptance and release integrity
The focus of the next cycle. 0.2.0 shipped a defect that only appeared in the packaged service, and the published archives had drifted from the fixed source. Both are process problems, and they are worth more than new features right now.

- **Linux installer acceptance test.** Run `install.sh` on a clean VM from a downloaded archive: checksum verification, account creation, bootstrap, enable and start, health and readiness, a ping scan performed through the service, then `uninstall.sh` with data preserved and a documented reinstall.
- **Windows installer and service acceptance test.** The equivalent for `Install.ps1` under the SCM as `LocalService`. This has never been executed; only cross-compilation has been verified.
- **Determine whether Windows has the same ICMP restriction.** The Linux fix does not transfer. `LocalService` is a low-privilege identity and its ability to open ICMP handles is untested, so Windows ping scanning may be broken in exactly the way Linux was.
- **Regression guard for the packaged unit.** A test that asserts the shipped `mipam.service` still carries the directives scanning depends on, so the 0.2.0 defect cannot silently return.
- **Build release artifacts from the tag in CI.** Archives are currently built locally and committed, which is how they fell out of sync with the source. Publishing from a tagged pipeline removes the possibility.
- **Sign release artifacts** and document verification. Checksums only detect corruption; they say nothing about origin.

Done when both installers have a recorded end-to-end pass on native platforms and release archives are produced by an automated pipeline rather than by hand.

## 0.4.0 — Provider completeness
Closing the gaps between what the provider abstraction implies and what it actually does. Each item needs certification against a live server before it is described as supported.

- **Windows DHCPv4:** scope activation, exclusion ranges, scope options, pool modification. Currently new scopes start inactive and these operations are absent.
- **DHCPv6** for the Windows connector.
- **Kea:** scope configuration writes and automatic lease pagination, replacing the current cursor-driven partial reads.
- **DNS:** MX, TXT and SRV writes; multi-record RRset editing, which is read-only today to avoid deleting unrelated records; zone provisioning.
- **Scheduled synchronization** for directory and provider data. Everything is manually refreshed today, and no automatic polling is implied anywhere in the UI.
- **Per-zone and per-scope delegation** so provider rights can be granted narrowly instead of administrator-only.
- **Interactive cancellation of running jobs.** Running jobs are bounded but cannot currently be stopped once started.

Done when the provider boundary list in the README no longer needs a "not implemented" column for the mainstream DNS and DHCP operations.

## 0.5.0 — Identity, scale and operations
Work needed before a larger or more regulated deployment is plausible.

- **Directory depth:** nested LDAP group membership, StartTLS, and OIDC group overage handling for large directories. Membership is direct-only today and refreshes at login rather than continuously.
- **Backups beyond the 128 MiB snapshot limit**, plus object-storage destinations and an automated retention policy. Audit and job tables also have no pruning.
- **Proxy-aware login throttling.** Throttling currently keys on the proxy address behind a reverse proxy, which weakens it; this needs explicit trusted-forwarded-header configuration rather than blind trust.
- **CEF output** and documented Sentinel/Elastic ingestion paths.
- **Schema migrations beyond v1**, with rollback, so upgrades stop depending on the schema never changing.
- **Load and capacity testing** to establish real limits for subnet count, address volume, scan throughput and SIEM queue depth.
- **Secret rotation procedures** for the backup key, provider credentials and SIEM tokens.
- **Topology correlation.** LLDP/CDP results are raw timestamped MIB entries; correlating them with FDB, ARP and ND data into a usable topology view is a substantial piece of work.

## Under consideration
Wanted, but not scheduled and not started.

- Native DEB, RPM and MSI packages alongside the current archives.
- Container images and a documented container deployment.
- Automated upgrade orchestration.
- A richer import and recovery UX, including merge and update imports rather than create-only.

## Not planned
- Multi-node, clustered or highly available deployment. MIPAM is a single-node application with an exclusive SQLite lock, and nothing in the current design anticipates replication.
- Replacing SQLite with an external database server.

## Contributing to this roadmap
Open an issue describing the operational problem rather than a preferred implementation. Items move onto a milestone when the behaviour and its acceptance criteria are clear enough to verify.
