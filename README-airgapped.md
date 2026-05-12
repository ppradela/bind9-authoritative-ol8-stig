# BIND 9.16 Authoritative DNS (Primary + Secondaries) — DISA STIG Hardened Deployment (Air-Gapped)

> **Variant for disconnected / air-gapped networks. All packages and files are pre-staged on an internet-connected machine and transferred to the target hosts via approved media.**

![BIND](https://img.shields.io/badge/BIND-9.16-005A9C)
![OL8](https://img.shields.io/badge/Oracle_Linux-8-red)
![STIG](https://img.shields.io/badge/DISA_STIG-Oracle_Linux_8_V2R7-green)
![License](https://img.shields.io/badge/license-MIT-blue)

> **Internet-connected network?** See [README.md](README.md) for the standard deployment guide.

---

## Features

- **Authoritative only** — recursion fully disabled; this enclave is the source-of-truth for its delegated zones, never a resolver for anyone else's
- **Hidden-primary topology** — primary answers normal DNS queries only from a tight management ACL; secondaries are the public answer surface inside the enclave
- **TSIG-protected zone transfers** — hmac-sha384 mandatory; same key installed identically on the primary and every secondary
- **NOTIFY-driven propagation** — primary sends NOTIFY on every zone change; secondaries trigger fast AXFR/IXFR
- **Unicast source addressing** — `query-source`, `notify-source`, `transfer-source` all pinned to a single unicast IP
- **DNSSEC via dnssec-policy** — automated KSK/ZSK rollover; algorithm set restricted to RSASHA256, RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384
- **Federated-tolerant SOA timers** — short refresh (1 h) so a change propagates promptly when the link is up, long expire (60 d) so a disconnected secondary remains usable for two months
- **No forwarders** — secondaries operate without forwarders for zones hosted by other MNPs; every answer comes from data they pulled from the primary
- **Structured logging** — separate channels for zone transfers, NOTIFY, dynamic updates, DNSSEC events, security denials, query errors; forwarded to in-enclave SIEM via rsyslog TLS
- **systemd hardening drop-in** — capabilities reduced to `CAP_NET_BIND_SERVICE`; OL8/systemd-239 compatible
- **Zero runtime internet access required** — all packages pre-staged before transfer to enclave

---

## Architecture

```
                In-enclave clients / recursive resolvers
                                 │  UDP/TCP 53
                                 ▼
              ┌──────────────────────────────────────────┐
              │  SECONDARY ns1  192.0.2.20    (in-enclave) │
              │  SECONDARY ns2  192.0.2.21    (in-enclave) │
              │  -----                                   │
              │  - allow-query { any; }  (enclave only)  │
              │  - allow-notify { primary_peers; }       │ ◄─── NOTIFY (TSIG)
              │  - SOA refresh 1h / expire 60d           │
              │  - no forwarders                         │
              └─────────────────┬────────────────────────┘
                                │  AXFR / IXFR (TCP 53, TSIG hmac-sha384)
                                ▼
              ┌──────────────────────────────────────────┐
              │  HIDDEN PRIMARY  192.0.2.10              │
              │  -----                                   │
              │  - allow-query { trusted_query; }        │  (mgmt only)
              │  - allow-transfer { transfer_peers; }    │  (TSIG-gated)
              │  - dnssec-policy "stig-default"          │
              │  - KSK private — OFFLINE                 │
              │  - ZSK — on host (automated re-signing)  │
              └──────────────────────────────────────────┘
                                │
                                ├── rsyslog (facility local5)
                                │    TLS 6514 (required — no cleartext)
                                ▼
                          In-enclave SIEM
```

> **In-enclave DNSSEC trust anchors:** because the enclave's `.nation` (or other) TLD is rooted inside the enclave rather than at IANA, every recursive resolver in the enclave must be provisioned with the DS records of the apex signed zones as static trust anchors. There is no public chain of trust to validate against.

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
├── README.md                     # Internet-connected deployment guide
└── README-airgapped.md           # This guide (air-gapped deployment)
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

Oracle Linux 8 is assumed to be **DISA STIG hardened at install time** using the STIG profile available in the OL8 installer.

- `rsyslog` installed and running
- Approved removable media or a secure file-transfer path to the air-gapped hosts
- An internet-connected **staging machine** running Oracle Linux 8 to download BIND packages
- A unicast IP per host on the enclave network. The outbound (`query-source`, `transfer-source`, `notify-source`) addresses must always be unicast

### Stage packages on the internet-connected machine

OL8 ships two parallel-installable BIND packages. The default `bind` package is BIND 9.11, which is outdated. The `bind9.16` package provides the modern 9.16 codebase (including `dnssec-policy`) with the same service name (`named.service`) and config path (`/etc/named.conf`).

> The package is literally named `bind9.16` — there is no module stream. `dnf module enable bind:9.16` returns `missing groups or modules: bind:9.16` on OL8; use the plain `dnf install`/`dnf download` commands below.

Run the following on the **staging machine** (must be running Oracle Linux 8):

```bash
# Create a staging directory
mkdir -p ~/bind9-stage

# Download bind9.16 server, utilities, and all dependencies
dnf download --resolve --destdir ~/bind9-stage bind9.16 bind9.16-utils

# Verify what was downloaded — expect bind9.16-*, bind9.16-libs-*, bind9.16-utils-*, etc.
ls ~/bind9-stage/
```

Transfer `~/bind9-stage/` to **every** air-gapped DNS host (primary + each secondary) via approved media.

---

## Deployment

> Perform Step 1 through Step 5 on **every** server (primary + every secondary), then run Step 6 onwards in the order shown. Files installed on the primary differ from files installed on a secondary — see the matrix in [README.md](README.md#file-structure).

### Step 1 — Install the RPM packages

On each **air-gapped target host**, from the transferred staging directory:

```bash
# bind9.16 conflicts with the legacy 9.11 'bind' package — remove it first
dnf remove bind 2>/dev/null || true

dnf install --disablerepo='*' ~/bind9-stage/*.rpm
```

If `dnf` is unavailable or repos are fully disabled, use `rpm` directly:

```bash
rpm -e bind 2>/dev/null || true
rpm -ivh ~/bind9-stage/*.rpm
```

Confirm the installed version:

```bash
named -v
# Expected: BIND 9.16.x (...)
```

### Step 2 — Verify the service account

```bash
id named
passwd -l named
passwd -S named    # must show: named L ...
```

### Step 3 — Create configuration, key, log, and zone directories

```bash
install -d -o root  -g named -m 0750 /etc/named
install -d -o root  -g named -m 0750 /etc/named/keys
install -d -o root  -g named -m 0750 /var/log/named
install -d -o named -g named -m 0750 /var/named/data
install -d -o named -g named -m 0750 /var/named/dynamic
install -d -o named -g named -m 0750 /var/named/slaves   # secondaries only
```

**SELinux file contexts** for any non-default directory:

```bash
semanage fcontext -a -t named_log_t  "/var/log/named(/.*)?"
restorecon -Rv /var/log/named
```

### Step 4 — Generate the TSIG zone-transfer key on the staging machine

Generate **once** on the staging machine; transfer the resulting file to every server. Regenerating on each host produces different secrets and AXFR will fail.

```bash
# Bash
./scripts/new-tsig-key.sh -n zone-transfer-key -a hmac-sha384 -o tsig.key

# Python
python3 scripts/new-tsig-key.py -n zone-transfer-key -a hmac-sha384 -o tsig.key

# PowerShell
.\scripts\New-TsigKey.ps1 -Name zone-transfer-key -Algorithm hmac-sha384 -OutFile tsig.key
```

Transfer `tsig.key` to every server via approved media, then install identically:

```bash
install -o root -g named -m 0640 tsig.key /etc/named/keys/tsig.key
```

> **Approved-media handling:** treat `tsig.key` as a shared cryptographic secret. Sanitise the staging machine and the removable media in line with your ISSM/ISSO's approved procedure after every distribution event.

### Step 5 — Install the rndc control key (per host)

```bash
rndc-confgen -a -k rndc-key -c /etc/rndc.key -A hmac-sha256 -b 256
chown root:named /etc/rndc.key
chmod 0640 /etc/rndc.key
```

### Step 6 — Install ACLs

```bash
install -o root -g named -m 0640 config/acl.conf /etc/named/acl.conf
```

Edit `/etc/named/acl.conf` and replace:

| Placeholder | What to set |
|-------------|-------------|
| `<<MGMT_SUBNET>>/24` | The operator management subnet allowed to query the primary |
| `192.0.2.20/32`, `192.0.2.21/32` (in `transfer_peers`) | Each secondary's enclave IP — primary host only |
| `192.0.2.10/32` (in `primary_peers`) | The primary's enclave IP — secondary hosts only |

### Step 7 — Install the appropriate `named.conf` and zone declarations

On the **primary**:

```bash
install -o root -g named -m 0640 config/named-primary.conf    /etc/named.conf
install -o root -g named -m 0640 config/zones-primary.conf    /etc/named/zones-primary.conf
install -o named -g named -m 0640 config/zones/db.example.nation /var/named/db.example.nation
install -o named -g named -m 0640 config/zones/db.192.0.2     /var/named/db.192.0.2
```

On each **secondary**:

```bash
install -o root -g named -m 0640 config/named-secondary.conf  /etc/named.conf
install -o root -g named -m 0640 config/zones-secondary.conf  /etc/named/zones-secondary.conf
```

Edit `/etc/named.conf` on each host and replace the unicast IPs (`listen-on`, `query-source address`, `notify-source`, `transfer-source`, and on the primary `also-notify { ... }`) to match the enclave's IP plan.

Validate before starting:

```bash
named-checkconf -z /etc/named.conf
```

> **Air-gapped note:** for the enclave's own `.nation` (or other) TLD, the secondaries are the apex authority — there is no parent registry outside the enclave. The DS records produced in Step 11 below must be loaded as static trust anchors on every enclave recursive resolver, not submitted to a public registry.

### Step 8 — Install the systemd hardening drop-in

```bash
install -d -o root -g root -m 0755 \
  /etc/systemd/system/named.service.d

install -o root -g root -m 0644 \
  config/named-hardening.conf \
  /etc/systemd/system/named.service.d/hardening.conf

systemctl daemon-reload
```

### Step 9 — Configure rsyslog forwarding to in-enclave SIEM

```bash
install -o root -g root -m 0644 \
  config/rsyslog-named.conf /etc/rsyslog.d/named.conf
```

Edit `/etc/rsyslog.d/named.conf` and set the in-enclave SIEM address. Use TLS (`@@(o)`) — plain UDP is not acceptable on air-gapped or CUI networks.

```bash
systemctl restart rsyslog
logger -p local5.info "named rsyslog test $(date)"   # verify delivery to in-enclave SIEM
```

> The SIEM's CA certificate must be trusted by every BIND host. Stage the enclave-PKI CA chain alongside the BIND packages and install it via `update-ca-trust extract` or by setting `$DefaultNetstreamDriverCAFile` in `/etc/rsyslog.conf` explicitly.

### Step 10 — Enable and start named

```bash
systemctl enable --now named
systemctl status named
journalctl -u named --no-pager | tail -20
```

Within ~30 s of the primary starting, every secondary should AXFR each zone. Verify:

```bash
# On the primary
journalctl -u named --no-pager | grep -E 'AXFR|sending notifies'

# On each secondary
journalctl -u named --no-pager | grep -E 'transferred serial|Transfer status'
ls -la /var/named/slaves/        # zone files must appear here, owner named:named
```

### Step 11 — DNSSEC bootstrap and enclave-wide trust anchor distribution

With `dnssec-policy "stig-default"` active and `inline-signing yes`, named generates KSK + ZSK under `/var/named/keys/` on first load.

```bash
ls -la /var/named/keys/
rndc dnssec -status example.nation
```

Extract the DS record from the KSK:

```bash
dnssec-dsfromkey -2 /var/named/keys/Kexample.nation.+013+*.key
```

Distribute the resulting **DS RR** (key tag, algorithm, digest type 2 = SHA-256, digest) to every recursive resolver in the enclave as a static trust anchor. On enclaves where the recursive resolvers are built from the companion [pdns-recursor-ol8-stig](https://github.com/ppradela/pdns-recursor-ol8-stig) repository, add one `addTA()` line per signed zone to `/etc/pdns-recursor/recursor.lua` on each resolver.

> **KSK private key — offline custody:** the KSK private file (`Kexample.nation.+013+<keytag>.private`) should be moved to offline media after first signing converges. Restore it under `/var/named/keys/` only during scheduled rollover windows (typical KSK lifetime ~5 years), then re-archive. The ZSK private key remains on-host for automated re-signing (typical ZSK lifetime ~1 year, ~1 month overlap during roll).

### Step 12 — Configure firewalld

```bash
firewall-cmd --get-active-zones

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

---

## Smoke Tests

```bash
# Primary
systemctl status named
dig @192.0.2.10 +norec www.iana.org. A | grep status            # REFUSED
dig @192.0.2.10 example.nation. SOA | grep -E 'flags|status'    # status NOERROR, aa flag
dig @192.0.2.10 example.nation. NS +short
dig @192.0.2.10 -x 192.0.2.20 +short
dig @192.0.2.10 example.nation. DNSKEY +dnssec | grep -E 'DNSKEY|RRSIG'
dig @192.0.2.10 example.nation. NS +noall +answer +authority +additional +nostats | wc -c   # < 512

# Each secondary
named-checkzone example.nation /var/named/slaves/db.example.nation
for ns in 192.0.2.10 192.0.2.20 192.0.2.21; do
  echo "=== $ns ==="
  dig @$ns example.nation. SOA +short
  dig @$ns example.nation. NS +short | sort
done
# Expected: identical SOA serial AND identical, sorted NS RRset on all three

# Zone-transfer ACL — must refuse without TSIG
dig @192.0.2.10 example.nation. AXFR | head -5         # "Transfer failed."

# Logs and SIEM
ls -l /var/log/named/
tail /var/log/named/xfer.log /var/log/named/dnssec.log /var/log/named/security.log
journalctl -u rsyslog --no-pager | tail -5
```

---

## Operational Runbooks

### Zone change (static, primary only)

```bash
# 1. Edit and bump the SOA serial
vi /var/named/db.example.nation

# 2. Syntax + SOA + glue validation
named-checkzone example.nation /var/named/db.example.nation

# 3. Reload — re-signs (DNSSEC) and triggers NOTIFY automatically
rndc reload example.nation
journalctl -u named --no-pager | tail -20
```

### Key rollover (KSK or ZSK)

`dnssec-policy` runs ZSK rollover unattended.

**KSK rollover** requires the offline KSK private key to be temporarily restored on the primary:

```bash
# Stage the KSK private from offline media:
install -o named -g named -m 0600 \
  /media/offline/Kexample.nation.+013+<keytag>.private \
  /var/named/keys/Kexample.nation.+013+<keytag>.private

# Force the rollover
rndc dnssec -rollover -key <keytag> example.nation

# Watch progression
watch -n10 'rndc dnssec -status example.nation'

# After the new DS record has been published to every enclave resolver
# AND the old KSK is fully retired, sanitise the on-host private file
shred -u /var/named/keys/Kexample.nation.+013+<oldkeytag>.private
```

Re-archive the new KSK private to offline media; do **not** leave the private file on-host outside an active rollover window.

### Adding a new signed zone

1. Place the unsigned zone file under `/var/named/db.<zone>` (owner `named:named`, mode 0640).
2. Append a stanza to `/etc/named/zones-primary.conf` with `dnssec-policy "stig-default"; inline-signing yes;`.
3. Append a matching stanza to `/etc/named/zones-secondary.conf` on every secondary.
4. `rndc reload` on the primary, then on every secondary.
5. Extract the DS via `dnssec-dsfromkey` and distribute to every enclave resolver as a new trust anchor.

---

## Maintenance Schedule

| Task | Frequency |
|------|-----------|
| Stage updated `bind` and `bind-utils` RPMs on staging machine; schedule enclave patching | Monthly |
| Review `acl.conf` against current enclave network topology | On every network change |
| Verify SOA serial parity across primary + every secondary | Daily (or via monitoring) |
| Inspect `xfer.log`, `dnssec.log`, `security.log` for unexpected failures | Daily (or via SIEM alerting) |
| Confirm `rndc dnssec -status` shows healthy state for every signed zone | Weekly |
| Re-distribute trust anchors to every enclave resolver after any key rollover | Per rollover |
| Audit firewalld ingress — primary narrow to mgmt + secondaries | Quarterly |
| Rotate TSIG keys — generate on staging, transfer via approved media, swap, retire | Annually |
| Verify offline KSK media integrity (checksum + restore drill) | Annually |
| Run smoke tests after any configuration change | After every change |

---

## Key Lessons — What NOT to Do on OL8

Most of these affect both internet-connected and air-gapped deployments. Air-gapped specifics are flagged.

### `dnssec-enable` — removed in BIND 9.16

`dnssec-enable yes;` is a 9.10/9.11 directive. In 9.16 it is removed; including it produces `unknown option 'dnssec-enable'`. DNSSEC is unconditionally enabled; control is via `dnssec-policy` and `inline-signing`.

### `dnssec-validation` on an authoritative server

Leaving the implicit default (`auto`) makes named try to load the IANA root key — pointless on an authoritative-only server, and a **permanent source of log noise on an air-gapped enclave** that cannot reach root-anchors.xml. Set `dnssec-validation no;` explicitly.

### `allow-transfer { 192.0.2.20; };` is **not** TSIG-enforced

An IP-only `allow-transfer` clause allows an unauthenticated peer at that IP to AXFR the zone. The TSIG requirement comes from including a `key` clause inside the ACL (see `transfer_peers` in `acl.conf`).

### Identical TSIG secret on both ends, byte for byte

Re-running `new-tsig-key.sh` on each host produces a different secret each time and AXFR fails with `tsig verify failure`. Generate the key **once on the staging machine**, then copy the file (via approved media) to every primary and secondary.

### Air-gapped specific — Trust anchors are not free

Public DNSSEC validation depends on IANA's root key. Inside an enclave with no internet path, the chain of trust **starts and ends within the enclave**. Every signed zone published by this infrastructure must be distributed as a DS-record trust anchor to every recursive resolver in the enclave — there is no automatic alternative. Track this as part of every key rollover.

### Air-gapped specific — KSK offline custody operational risk

Storing the KSK private key offline reduces compromise risk but introduces availability risk: if the offline media is lost or corrupted, the KSK can never be rolled out (signatures will expire, the zone goes bogus). Keep **at least two** offline copies on independent media, in physically separated approved storage; verify integrity (sha256) annually with a restore drill on a sandboxed test host.

### `inline-signing yes` + manual edits to the zone file

When `inline-signing yes` is active, named maintains the signed copy in `db.<zone>.signed` and a journal in `db.<zone>.jnl`. Editing the unsigned zone is fine **as long as you bump the SOA serial and run `rndc reload`** — never edit the `.signed` file, never delete the `.jnl` while named is running.

### `query-source address` on a multi-homed primary

If the host has multiple addresses, BIND will (by default) source outbound queries from whichever interface the kernel routes the destination to. Enclave firewalls that expect a specific source IP will then drop the response. Always set `query-source address <unicast IP>;` and `transfer-source <unicast IP>;` explicitly.

### Referral payload exceeding 512 octets

A delegation referral that does not fit in 512 octets forces non-EDNS clients to retry over TCP. Keep the NS RRset small (two records is correct), and ensure glue A records match the authoritative A records. Verify with:

```bash
dig +noall +answer +authority +additional example.nation. NS | wc -c
```

### `named.service.d/hardening.conf` — OL8 (systemd 239) constraints

Several hardening directives implicitly force `NoNewPrivileges=true`, which blocks the SELinux domain transition `init_t → named_t` (AVC: `nnp_transition`). The kernel locks NNP on as soon as any one of these is set:

> `SystemCallFilter=`, `RestrictNamespaces=`, `LockPersonality=`, `RestrictRealtime=`, `ProtectKernelTunables=`, `ProtectKernelModules=`, `MemoryDenyWriteExecute=`, `PrivateDevices=`

The supplied drop-in excludes all of them. SELinux mandatory access control covers the equivalent ground on OL8.

Other OL8 (systemd 239) constraints:

1. **`ProtectSystem=strict` is unsafe on OL8.** Use `ProtectSystem=full`.
2. **List-type keys accumulate.** Empty assignment before redefining `CapabilityBoundingSet=` / `SystemCallFilter=`.
3. **`ProtectHostname=` / `ProtectClock=` / `RestrictSUIDSGID=` / `ProtectKernelLogs=`** are not on systemd 239 — silent parse failures.
4. **`ReadWritePaths=` requires every listed path to exist at service start**, otherwise `Failed at step NAMESPACE: No such file or directory` is logged with no indication of which path was missing. The supplied drop-in lists only `/var/named` and `/var/log/named`, both created in Step 3.

### Air-gapped specific — SIEM CA must be pre-staged

rsyslog TLS forwarding (`@@(o)`) requires the SIEM's CA certificate chain to be trusted by the host. On an air-gapped host with no path to public CAs, the enclave PKI CA must be explicitly configured. If rsyslog logs show TLS handshake failures, check `$DefaultNetstreamDriverCAFile` in `/etc/rsyslog.conf` and confirm the CA file is readable.

### Operational: SOA serial discipline

Every zone-file edit on the primary **must** bump the SOA serial. Without a higher serial, secondaries treat the IXFR/AXFR as unchanged and silently skip the transfer. The supplied template uses `YYYYMMDDNN` (RFC 1912 §2.2).

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
