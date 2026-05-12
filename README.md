# BIND 9.16 Authoritative DNS (Primary + Secondaries) — DISA STIG Hardened Deployment

> **A complete, production-tested DISA STIG hardening guide for an authoritative DNS infrastructure built on BIND 9.16 on Oracle Linux 8. Covers hidden-primary + secondaries topology, TSIG-protected zone transfers (hmac-sha384), DNSSEC signing with the four approved algorithms, federated-tolerant SOA timers, systemd hardening, and SIEM forwarding — with every OL8-specific pitfall documented.**

![BIND](https://img.shields.io/badge/BIND-9.16-005A9C)
![OL8](https://img.shields.io/badge/Oracle_Linux-8-red)
![STIG](https://img.shields.io/badge/DISA_STIG-Oracle_Linux_8_V2R7-green)
![License](https://img.shields.io/badge/license-MIT-blue)

> **Air-gapped / disconnected network?** See [README-airgapped.md](README-airgapped.md).

---

## Features

- **Authoritative only** — recursion fully disabled on every host; no cache responses served; `dnssec-validation no` (this is not a resolver)
- **Hidden-primary topology** — primary answers normal DNS queries only from a tight management ACL; secondaries are the public answer surface
- **TSIG-protected zone transfers** — hmac-sha384 mandatory; `transfer_peers` ACL combines IP filter + key requirement; same key installed identically on both ends
- **NOTIFY-driven propagation** — primary sends NOTIFY on every zone change; secondaries trigger fast AXFR/IXFR rather than waiting for SOA refresh
- **Unicast source addressing** — `query-source`, `notify-source`, `transfer-source` all pinned to a single unicast IP; no anycast on the outbound path
- **DNSSEC via dnssec-policy** — automated KSK/ZSK rollover, automatic re-signing on zone modification, signature expiry, and key boundary events. Algorithm set restricted to RSASHA256, RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384
- **Federated-tolerant SOA timers** — short refresh (1 h) for fast propagation; long expire (60 d) so a disconnected secondary remains usable for two months
- **Country-code TLD support (.nation)** — example zone demonstrates `example.nation` as a `cc` TLD with matching reverse zone on a full /24 (8-bit) boundary
- **Referral payload ≤ 512 octets** — minimal-responses, conservative NS RRset, glue A records matching the authoritative A records
- **Structured logging** — separate channels for zone transfers, NOTIFY, dynamic updates, DNSSEC events, security denials, query errors; all categories forwarded to a SIEM via rsyslog (facility `local5`)
- **systemd hardening drop-in** — capabilities reduced to `CAP_NET_BIND_SERVICE`, core dumps disabled, ReadWritePaths pinned to actual zone/log paths; OL8/systemd-239 compatible
- **Documented pitfalls** — every non-obvious OL8/BIND-9.16 failure mode explained and solved

---

## Architecture

```
                      Recursive resolvers (Internet / enterprise)
                      Public-facing DNS clients
                                 │  UDP/TCP 53
                                 ▼
              ┌──────────────────────────────────────────┐
              │  SECONDARY ns1  192.0.2.20    (public)   │
              │  SECONDARY ns2  192.0.2.21    (public)   │
              │  -----                                   │
              │  - allow-query { any; }                  │
              │  - allow-notify { primary_peers; }       │ ◄─── NOTIFY (TSIG)
              │  - SOA refresh 1h / expire 60d           │
              │  - listen on unicast IP only             │
              │  - response source IP = query dest IP    │
              └─────────────────┬────────────────────────┘
                                │  AXFR / IXFR  (TCP 53, TSIG hmac-sha384)
                                ▼
              ┌──────────────────────────────────────────┐
              │  HIDDEN PRIMARY  192.0.2.10              │
              │  -----                                   │
              │  - allow-query { trusted_query; }        │  (mgmt only)
              │  - allow-transfer { transfer_peers; }    │  (TSIG-gated)
              │  - notify yes; also-notify { ns1; ns2; } │
              │  - dnssec-policy "stig-default"          │
              │  - inline-signing yes                    │
              │  - ECDSAP256SHA256 KSK + ZSK             │
              └──────────────────────────────────────────┘
                                │
                                ├── rsyslog (facility local5)
                                │    TLS 6514 (production / CUI)
                                │    UDP 514  (lab only)
                                ▼
                              SIEM
```

---

## File Structure

```
repository/
├── config/
│   ├── named-primary.conf        # /etc/named.conf  — primary
│   ├── named-secondary.conf      # /etc/named.conf  — secondary
│   ├── acl.conf                  # Shared ACL definitions
│   ├── tsig.key.example          # TSIG key template (regenerate before use)
│   ├── zones-primary.conf        # Zone declarations — primary side
│   ├── zones-secondary.conf      # Zone declarations — secondary side
│   ├── named-hardening.conf      # systemd hardening drop-in
│   ├── rsyslog-named.conf        # rsyslog SIEM forwarding rule
│   └── zones/
│       ├── db.example.nation     # Example forward zone (.nation TLD)
│       └── db.192.0.2            # Example reverse zone (/24, 8-bit boundary)
├── scripts/
│   ├── new-tsig-key.sh           # TSIG key generator (Bash)
│   ├── new-tsig-key.py           # TSIG key generator (Python 3.6+)
│   └── New-TsigKey.ps1           # TSIG key generator (PowerShell)
├── README.md                     # This guide (internet-connected deployment)
└── README-airgapped.md           # Air-gapped deployment variant
```

| File | Install path |
|------|-------------|
| `config/named-primary.conf` *(primary host only)* | `/etc/named.conf` |
| `config/named-secondary.conf` *(secondary hosts only)* | `/etc/named.conf` |
| `config/acl.conf` | `/etc/named/acl.conf` |
| `config/tsig.key.example` → regenerated to `tsig.key` | `/etc/named/keys/tsig.key` |
| `config/zones-primary.conf` *(primary host only)* | `/etc/named/zones-primary.conf` |
| `config/zones-secondary.conf` *(secondary hosts only)* | `/etc/named/zones-secondary.conf` |
| `config/zones/db.example.nation` *(primary host only)* | `/var/named/db.example.nation` |
| `config/zones/db.192.0.2` *(primary host only)* | `/var/named/db.192.0.2` |
| `config/named-hardening.conf` | `/etc/systemd/system/named.service.d/hardening.conf` |
| `config/rsyslog-named.conf` | `/etc/rsyslog.d/named.conf` |
| `scripts/*` | helper scripts — not installed on server |

---

## Prerequisites

### Oracle Linux 8 baseline

Oracle Linux 8 is assumed to be **DISA STIG hardened at install time** using the STIG profile available in the OL8 installer. No additional OS hardening steps are required here.

- `rsyslog` installed and running
- Outbound access to `yum.oracle.com` during installation
- One unicast IP per host. Anycast is permitted on the **service** address only if every backend instance shares the *exact same zone data and TSIG state*; outbound (`query-source`, `transfer-source`, `notify-source`) must always be unicast — see Step 5

### Install BIND 9.16 from Oracle Linux 8 AppStream

OL8 ships two parallel-installable BIND packages. The default `bind` package is BIND 9.11, which is outdated. Install `bind9.16` instead — same service name (`named.service`), same config path (`/etc/named.conf`), but the modern 9.16 codebase (including `dnssec-policy`).

```bash
# Make sure the legacy 9.11 package is not also installed (the two conflict).
dnf remove -y bind bind-utils 2>/dev/null || true

# Install BIND 9.16 and matching utilities
dnf install -y bind9.16 bind9.16-utils

# Verify the version
named -v
# Expected: BIND 9.16.x (...)
```

> The package is literally named `bind9.16` — there is no module stream to enable. If you previously ran `dnf module enable bind:9.16` you will see `missing groups or modules: bind:9.16`; ignore it and use the plain `dnf install bind9.16` command above.

### Verify the service account

The package creates the `named` OS account. Confirm it is locked:

```bash
id named
passwd -l named
passwd -S named    # must show: named L ...
```

---

## Deployment

### Step 1 — Create configuration, key, log, and zone directories

```bash
install -d -o root  -g named -m 0750 /etc/named
install -d -o root  -g named -m 0750 /etc/named/keys

# /var/log/named must be owned by 'named' — the daemon creates xfer.log,
# dnssec.log, security.log, etc. inside it. Owning it root:named with mode
# 0750 makes 'named' use group permissions (r-x) and the daemon fails with
# "isc_stdio_open '/var/log/named/dnssec.log' failed: permission denied".
install -d -o named -g named -m 0750 /var/log/named

install -d -o named -g named -m 0750 /var/named/data
install -d -o named -g named -m 0750 /var/named/dynamic
install -d -o named -g named -m 0750 /var/named/slaves   # secondaries only
```

**SELinux file contexts** — the bind9.16 package's policy covers `/var/named/*` but does not pre-declare `/var/log/named`. Add the type and relabel before starting the service:

```bash
semanage fcontext -a -t named_log_t "/var/log/named(/.*)?"
restorecon -Rv /var/log/named /var/named
```

### Step 2 — Generate the TSIG zone-transfer key (once, on any host)

The key must be **identical** on the primary and every secondary that shares the trust relationship. Generate it once, then transfer the file securely to all servers.

```bash
# Bash
./scripts/new-tsig-key.sh -n zone-transfer-key -a hmac-sha384 -o tsig.key

# Python
python3 scripts/new-tsig-key.py -n zone-transfer-key -a hmac-sha384 -o tsig.key

# PowerShell (Windows / cross-platform)
.\scripts\New-TsigKey.ps1 -Name zone-transfer-key -Algorithm hmac-sha384 -OutFile tsig.key
```

Install identically on **every** primary and secondary:

```bash
install -o root -g named -m 0640 tsig.key /etc/named/keys/tsig.key
```

> The supplied `config/tsig.key.example` is a **template only** — its `secret` value is a placeholder. Never deploy the template; regenerate.

### Step 3 — Install the rndc control key

```bash
rndc-confgen -a -k rndc-key -c /etc/rndc.key -A hmac-sha256 -b 256
chown root:named /etc/rndc.key
chmod 0640 /etc/rndc.key
```

### Step 4 — Install ACLs

```bash
install -o root -g named -m 0640 config/acl.conf /etc/named/acl.conf
```

Edit `/etc/named/acl.conf` and replace:

| Placeholder | What to set |
|-------------|-------------|
| `<<MGMT_SUBNET>>/24` | The operator / monitoring management subnet allowed to query the primary |
| `192.0.2.20/32`, `192.0.2.21/32` (in `transfer_peers`) | Each secondary's IP — primary host only |
| `192.0.2.10/32` (in `primary_peers`) | The primary's IP — secondary hosts only |

### Step 5 — Install the appropriate `named.conf` and zone declarations

On the **primary**:

```bash
install -o root  -g named -m 0640 config/named-primary.conf    /etc/named.conf
install -o root  -g named -m 0640 config/zones-primary.conf    /etc/named/zones-primary.conf

# /var/named is shipped by the bind9.16 package as mode 1770 root:named
# (sticky bit + group rwx), so 'named' group members have full write access
# there — inline-signing can create the .jnl, .jbk, and .signed files next
# to the master file. No need for a writable subdirectory.
install -o named -g named -m 0640 config/zones/db.example.nation /var/named/db.example.nation
install -o named -g named -m 0640 config/zones/db.192.0.2        /var/named/db.192.0.2

# Restore SELinux labels — files copied from a non-/var/named source path
# (e.g., your home directory) carry the source context (default_t or
# user_home_t) instead of named_zone_t and named will fail to load the
# zones despite correct Unix ownership.
restorecon -Rv /var/named
```

On **each secondary**:

```bash
install -o root -g named -m 0640 config/named-secondary.conf  /etc/named.conf
install -o root -g named -m 0640 config/zones-secondary.conf  /etc/named/zones-secondary.conf
```

Edit `/etc/named.conf` on each host and replace:

| Setting | What to set |
|---------|-------------|
| `listen-on` | This host's unicast service address |
| `query-source address` | This host's unicast outbound address (usually the same) |
| `notify-source` | Same as `query-source` |
| `transfer-source` | Same as `query-source` |
| `also-notify { ... }` *(primary only)* | The unicast service IPs of every secondary |
| `server <PRIMARY_IP>` *(secondary only)* | The primary's unicast IP |
| `primaries { <PRIMARY_IP> key ... }` *(secondary, in zones-secondary.conf)* | The primary's unicast IP |

Verify configuration syntax on every host **before** starting the service:

```bash
named-checkconf -z /etc/named.conf
```

`-z` walks every zone — it catches not just syntax errors but also bad SOA timers, missing glue, and signing-policy mismatches.

### Step 6 — Install the systemd hardening drop-in

```bash
install -d -o root -g root -m 0755 \
  /etc/systemd/system/named.service.d

install -o root -g root -m 0644 \
  config/named-hardening.conf \
  /etc/systemd/system/named.service.d/hardening.conf

systemctl daemon-reload
```

### Step 7 — Configure rsyslog forwarding to SIEM

```bash
install -o root -g root -m 0644 \
  config/rsyslog-named.conf /etc/rsyslog.d/named.conf
```

Edit `/etc/rsyslog.d/named.conf` and replace `siem.example.mil` with your SIEM hostname or IP.

```bash
systemctl restart rsyslog
logger -p local5.info "named rsyslog test $(date)"   # verify delivery
```

### Step 8 — Enable and start named

```bash
systemctl enable --now named
systemctl status named
journalctl -u named --no-pager | tail -20
```

Within ~30 s of the primary starting, every secondary should AXFR each zone. Confirm with:

```bash
# On the primary
journalctl -u named --no-pager | grep -E 'AXFR|sending notifies'

# On each secondary
journalctl -u named --no-pager | grep -E 'transferred serial|Transfer status'
ls -la /var/named/slaves/        # zone files must appear here, owner named:named
```

### Step 9 — Configure firewalld

```bash
firewall-cmd --get-active-zones

# Wipe defaults and start clean
for svc in $(firewall-cmd --zone=public --list-services); do
  firewall-cmd --permanent --zone=public --remove-service="$svc"
done

firewall-cmd --permanent --zone=public --add-service=ssh
firewall-cmd --permanent --zone=public --add-service=dns

firewall-cmd --reload
firewall-cmd --zone=public --list-all
```

On the **primary**, tighten DNS ingress to operators + secondaries only:

```bash
firewall-cmd --permanent --zone=public --remove-service=dns
firewall-cmd --permanent --zone=public \
  --add-rich-rule='rule family="ipv4" source address="<<MGMT_SUBNET>>/24" port port="53" protocol="udp" accept'
firewall-cmd --permanent --zone=public \
  --add-rich-rule='rule family="ipv4" source address="<<MGMT_SUBNET>>/24" port port="53" protocol="tcp" accept'
firewall-cmd --permanent --zone=public \
  --add-rich-rule='rule family="ipv4" source address="192.0.2.20/32" port port="53" protocol="tcp" accept'
firewall-cmd --permanent --zone=public \
  --add-rich-rule='rule family="ipv4" source address="192.0.2.21/32" port port="53" protocol="tcp" accept'
firewall-cmd --reload
```

### Step 10 — DNSSEC bootstrap and DS submission

With `dnssec-policy "stig-default"` active and `inline-signing yes`, named generates KSK + ZSK material under `/var/named/keys/` on first load. Wait until the keys are visible (signature publication, ~1 minute):

```bash
ls -la /var/named/keys/
rndc dnssec -status example.nation
```

Extract the DS records to submit to the parent (`.nation` registry):

```bash
dnssec-dsfromkey -2 /var/named/keys/Kexample.nation.+013+*.key
```

Submit the resulting **DS RR** (key tag, algorithm, digest type 2 = SHA-256, digest) to the parent registry exactly as printed. Validation will succeed once:

1. The parent has published the DS RR; and
2. The matching DNSKEY is present in this zone (confirm with `dig @ns1.example.nation. DNSKEY example.nation. +dnssec`).

> If you need RSASHA256 instead of ECDSAP256SHA256 (for example, because the parent registry does not yet accept algorithm 13), switch the zone stanza to `dnssec-policy "stig-rsa";` before first start and re-bootstrap.

---

## Smoke Tests

Run on the **primary**:

```bash
# 1. Service is healthy
systemctl status named
journalctl -u named --no-pager | tail -20

# 2. Recursion really is disabled — must return REFUSED
dig @192.0.2.10 +norec www.iana.org. A | grep status
# Expected: status: REFUSED

# 3. Authoritative answer for our own zone — must return AA flag, NOERROR
dig @192.0.2.10 example.nation. SOA | grep -E 'flags|status'
# Expected: status: NOERROR ; flags: qr aa ...

# 4. NS RRset matches what is delegated in the parent
dig @192.0.2.10 example.nation. NS +short

# 5. Reverse zone responds with matching PTR
dig @192.0.2.10 -x 192.0.2.20 +short

# 6. DNSSEC chain — the zone is signed; expect RRSIG and DNSKEY responses
dig @192.0.2.10 example.nation. DNSKEY +dnssec | grep -E 'DNSKEY|RRSIG'

# 7. Referral payload size for a name in the zone — must be < 512 octets
dig @192.0.2.10 example.nation. NS +noall +answer +authority +additional +nostats \
  | wc -c
# Expected: comfortably under 512
```

Run on **each secondary**:

```bash
# 8. Zone has been transferred from primary
named-checkzone example.nation /var/named/slaves/db.example.nation

# 9. Secondary answers authoritatively for the same SOA serial as the primary
dig @192.0.2.20 example.nation. SOA +short
dig @192.0.2.21 example.nation. SOA +short
# Expected: identical serial number on both, identical to primary

# 10. NS RRset returned by every authority is identical
for ns in 192.0.2.10 192.0.2.20 192.0.2.21; do
  echo "=== $ns ==="
  dig @$ns example.nation. NS +short | sort
done
# Expected: identical, sorted output from all three

# 11. Secondaries refuse recursion
dig @192.0.2.20 +norec www.iana.org. A | grep status
# Expected: status: REFUSED

# 12. Zone-transfer ACL works — unauthenticated AXFR is refused
dig @192.0.2.10 example.nation. AXFR | head -5
# Expected: "Transfer failed." (no TSIG presented)
```

Run on **both** primary and secondaries:

```bash
# 13. Logging — every category has live entries
ls -l /var/log/named/
tail /var/log/named/xfer.log
tail /var/log/named/dnssec.log
tail /var/log/named/security.log

# 14. SIEM receipt — confirm syslog forwarding
journalctl -u rsyslog --no-pager | tail -5
```

---

## Operational Runbooks

### Zone change (static, primary only)

```bash
# 1. Edit the zone file — bump the SOA serial to YYYYMMDDNN
vi /var/named/db.example.nation

# 2. Validate syntax and SOA/glue consistency
named-checkzone example.nation /var/named/db.example.nation

# 3. Reload the zone — re-signs (DNSSEC) and triggers NOTIFY automatically
rndc reload example.nation
journalctl -u named --no-pager | tail -20
```

Within seconds, secondaries should AXFR/IXFR; verify with the smoke tests above.

### Key rollover (KSK or ZSK)

Driven by `dnssec-policy` automatically. Confirm the live state:

```bash
rndc dnssec -status example.nation
```

To force a ZSK roll for testing:

```bash
rndc dnssec -rollover -key <keytag> example.nation
```

When the KSK private key is kept **offline** (recommended): the offline copy must be available on the primary for the duration of any KSK rollover. Reinstall it under `/var/named/keys/` with mode `0600 named:named`, perform the rollover, then re-archive offline.

### Adding a new signed zone

1. Place the unsigned zone file under `/var/named/db.<zone>` (owner `named:named`, mode 0640).
2. Append a stanza to `/etc/named/zones-primary.conf` with `dnssec-policy "stig-default"; inline-signing yes;`.
3. Append a matching stanza to `/etc/named/zones-secondary.conf` on every secondary.
4. `rndc reload` on the primary, then on every secondary.
5. After signing converges (~1 min), extract the DS record and submit to the parent registry.

---

## Maintenance Schedule

| Task | Frequency |
|------|-----------|
| Review `acl.conf` against current network topology | On every network change |
| Verify SOA serial parity across primary + every secondary | Daily (or via monitoring) |
| Inspect `xfer.log` and `dnssec.log` for unexpected failures | Daily (or via SIEM alerting) |
| Confirm `rndc dnssec -status` shows healthy state for every signed zone | Weekly |
| Audit firewalld rules — primary ingress narrow to mgmt + secondaries | Quarterly |
| Rotate TSIG keys — generate, distribute, swap, retire | Annually |
| Check OL8 AppStream for updated `bind` packages | Monthly |
| Run smoke tests after any configuration change | After every change |
| Re-verify offline KSK copy integrity (checksum + restore drill) | Per KSK rollover window (~5 y) |

---

## Key Lessons — What NOT to Do on OL8

These issues are documented here to prevent recurrence.

### `dnssec-enable` — removed in BIND 9.16

`dnssec-enable yes;` is a 9.10/9.11 directive. In 9.16 it is removed; including it produces:

```
unknown option 'dnssec-enable'
```

DNSSEC is unconditionally enabled in 9.16; control is via `dnssec-policy` and `inline-signing`.

### `dnssec-validation` on an authoritative server

Leaving the implicit default (`auto`) makes named try to load the IANA root key and act as a partial validator — pointless on an authoritative-only server, and a permanent source of log noise on isolated networks. Set `dnssec-validation no;` explicitly (the supplied configs do).

### `allow-transfer { 192.0.2.20; };` is **not** TSIG-enforced

An IP-only `allow-transfer` clause allows an unauthenticated peer at that IP to AXFR the zone. The TSIG requirement comes from including a `key` clause inside the ACL or `server` stanza, as in:

```text
acl "transfer_peers" {
    !{ !key "zone-transfer-key"; any; };
    192.0.2.20/32;
};
```

The double-negation `!{ !key ... ; any; };` reads: *refuse anything that does not present the TSIG key*. Without it, the IP filter is the only check — a spoofed source defeats it.

### Identical TSIG secret on both ends, byte for byte

Re-running `new-tsig-key.sh` on each host produces a different secret each time and AXFR fails with `tsig verify failure`. Generate the key **once**, then copy the file to every peer.

### `also-notify` does not bypass `notify-source`

If the firewall path between primary and secondary requires a specific source IP for NOTIFY (most do), `notify-source` must be set explicitly. The supplied primary config pins it to the primary's unicast IP; leaving it as the BIND default lets the kernel pick the routing-table source, which on multi-homed hosts is often the wrong interface.

### Hidden primary still must accept queries from secondaries during diagnostics

`allow-query { trusted_query; };` blocks normal queries from everything outside the management ACL. The `transfer_peers` clause is checked only on the AXFR/IXFR path — so a secondary that runs `dig @primary example.nation.` gets `REFUSED` unless its IP is also in `trusted_query`. The supplied ACL includes the secondaries' IPs there for operational reasons.

### `restorecon -Rv /var/named` is mandatory after `install`

Files copied into `/var/named/` from a non-`/var/named` source path (your home directory, a checked-out repo, an approved-media drop) inherit the *source* SELinux context — typically `default_t` or `user_home_t` — instead of `named_zone_t`. `named_t` cannot read those, and named fails to load the zone with `permission denied` on the master file. Run `restorecon -Rv /var/named` after every `install` into that tree. The OL8 bind9.16 SELinux module already permits `named_t` to write to `named_zone_t` for inline-signing artifacts (`.jnl`, `.jbk`, `.signed`, `.signed.jnl`), so all of those end up correctly labelled too.

### `inline-signing yes` + manual edits to `db.example.nation`

When `inline-signing yes` is active, named maintains the signed copy in `db.example.nation.signed` and a journal in `db.example.nation.jnl`. Editing `db.example.nation` directly is fine **as long as you bump the SOA serial and run `rndc reload`** — never edit the `.signed` file, and never delete the `.jnl` while named is running.

### `query-source address` on a multi-homed primary

If the host has multiple addresses, BIND will (by default) source outbound queries from whichever interface the kernel routes the destination to. Firewalls or peering policies that expect a specific source IP will then drop the response. Always set `query-source address <unicast IP>;` and `transfer-source <unicast IP>;` explicitly — both the supplied configs do.

### Referral payload exceeding 512 octets

A delegation referral that does not fit in 512 octets forces non-EDNS clients to retry over TCP, breaking some legacy resolvers. Keep the NS RRset small (two records is correct), and ensure glue A records match the authoritative A records so the response is compact. Verify with:

```bash
dig +noall +answer +authority +additional example.nation. NS | wc -c
```

### `CapabilityBoundingSet` bounds **root**, not just the post-drop user

The EL stock `named.service` does **not** set `User=named` — named starts as root, binds port 53, then calls `setuid(named)` itself via the `-u named` flag. `CapabilityBoundingSet=` is the *upper bound on capabilities for the entire service lifetime*, including the root startup phase. Restricting it to just `CAP_NET_BIND_SERVICE` strips:

- `CAP_DAC_READ_SEARCH` — root can no longer bypass DAC to read files it doesn't own. The zone files (`named:named` mode `0640`) become unreadable by root, and `ExecStartPre=/usr/sbin/named-checkconf -z` fails with `loading from master file … failed: permission denied`. **No SELinux AVC** is logged — the denial happens at the DAC layer before the LSM is consulted.
- `CAP_SETUID` / `CAP_SETGID` — root can no longer drop to user `named`, so `named -u named` would fail too (you see the DAC error first only because ExecStartPre runs before ExecStart).

The supplied drop-in therefore keeps four caps in the bounding set: `CAP_NET_BIND_SERVICE`, `CAP_SETUID`, `CAP_SETGID`, `CAP_DAC_READ_SEARCH`. Only `CAP_NET_BIND_SERVICE` is in `AmbientCapabilities=`, so after the `setuid(named)` only that one survives — the running daemon has user-level permissions plus the ability to bind privileged ports, nothing more.

### `named.service.d/hardening.conf` — OL8 (systemd 239) constraints

Many hardening directives implicitly force `NoNewPrivileges=true`, which blocks the SELinux domain transition `init_t → named_t` (AVC: `nnp_transition`). Setting `NoNewPrivileges=false` afterwards has no effect — the kernel locks NNP on as soon as any one of these is set:

> `SystemCallFilter=`, `RestrictNamespaces=`, `LockPersonality=`, `RestrictRealtime=`, `ProtectKernelTunables=`, `ProtectKernelModules=`, `MemoryDenyWriteExecute=`, `PrivateDevices=`

The supplied drop-in excludes all of them. SELinux mandatory access control covers the equivalent ground on OL8.

Other OL8 (systemd 239) constraints:

1. **`ProtectSystem=strict` is unsafe on OL8.** It prevents the kernel from exec'ing binaries under `/usr/sbin/`. Use `ProtectSystem=full`.
2. **List-type keys accumulate.** To replace `CapabilityBoundingSet=` or `SystemCallFilter=`, write the empty assignment first, then the new value.
3. **`ProtectHostname=` (240+), `ProtectClock=` (245+), `RestrictSUIDSGID=` (245+), `ProtectKernelLogs=` (253+)** are not available on OL8 — silently ignored or cause parse failure. None are used in the supplied drop-in.
4. **`ReadWritePaths=` requires every listed path to exist at service start**, otherwise `Failed at step NAMESPACE: No such file or directory` is logged with no indication of which path was missing. The supplied drop-in lists only `/var/named` and `/var/log/named`, both created in Step 1.

### Operational: SOA serial discipline

Every zone-file edit on the primary **must** bump the SOA serial. Without a higher serial, secondaries treat the IXFR/AXFR as unchanged and silently skip the transfer. The supplied template uses `YYYYMMDDNN` (RFC 1912 §2.2) — `2026031101`, `2026031102`, etc.

---

## License

MIT — free to use, modify, and distribute.

---

## Author

**Przemysław Pradela**

Built through real production deployment and iterative troubleshooting on Oracle Linux 8.

[![GitHub](https://img.shields.io/badge/GitHub-ppradela-181717?logo=github)](https://github.com/ppradela)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Przemysław%20Pradela-0A66C2?logo=linkedin)](https://www.linkedin.com/in/przemyslaw-pradela)
[![Website](https://img.shields.io/badge/Website-pradela.ovh-4A90D9)](https://pradela.ovh)

Contributions and issue reports welcome.
