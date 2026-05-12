; ============================================================================
; /var/named/db.example.com
;
; Forward zone — example.com (illustrative apex; substitute your real
; domain, including country-code TLDs such as .nation, when adapting for
; production)
; Two independent name servers for the delegated zone:
;     ns1.example.com  → 192.0.2.20  (secondary-1)
;     ns2.example.com  → 192.0.2.21  (secondary-2)
;
; Notes
;   - The NS RRset returned to clients matches the delegation expected in the
;     parent zone, and the A glue records match the authoritative A records
;     here — there is no glue/authoritative mismatch.
;   - The referral payload for example.com (SOA omitted, NS set + 1 glue A)
;     fits comfortably within 512 octets, satisfying the non-EDNS UDP limit.
;   - The SOA timers are tuned for federated / austere operation: short
;     refresh (1 h) so a change propagates promptly when the link is up, with
;     a long expire (60 d) so a disconnected secondary remains usable for
;     two months.
;
; SOA serial discipline — YYYYMMDDNN (RFC 1912 §2.2). Increment on every
; edit, otherwise secondaries will not pull the new file.
; ============================================================================

$TTL 3600
$ORIGIN example.com.

@   IN  SOA   ns1.example.com. hostmaster.example.com. (
              2026031101    ; serial    — YYYYMMDDNN, bump on every edit
              3600          ; refresh   — secondaries probe SOA every 1 h
              900           ; retry     — retry every 15 min on failure
              5184000       ; expire    — discard zone after 60 d disconnect
              3600          ; minimum   — negative-cache TTL
              )

; ---- Authoritative name servers (NS RRset) -------------------------------
@   IN  NS    ns1.example.com.
@   IN  NS    ns2.example.com.

; ---- Glue A records — MUST match the authoritative A records below -------
ns1 IN  A     192.0.2.20
ns2 IN  A     192.0.2.21

; ---- Apex address & mail -------------------------------------------------
@         IN  A     192.0.2.30
@         IN  MX 10 mail.example.com.
mail      IN  A     192.0.2.31

; ---- Hosts ---------------------------------------------------------------
www       IN  A     192.0.2.30
ldap      IN  A     192.0.2.32
ntp       IN  A     192.0.2.33

; ---- SRV (RFC 2782) demonstration ----------------------------------------
_ldap._tcp        IN  SRV 0 5 389  ldap.example.com.
_ntp._udp         IN  SRV 0 5 123  ntp.example.com.

; ============================================================================
; END
; ============================================================================
