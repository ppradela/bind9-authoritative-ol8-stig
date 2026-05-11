#!/usr/bin/env bash
# =============================================================================
# new-tsig-key.sh — generate a TSIG key (hmac-sha384 by default) and emit
# both the BIND named.conf 'key { ... };' stanza and a side-by-side rndc-style
# .key file. The same secret must be installed on the primary and every
# secondary that shares the trust relationship.
#
# Usage:
#   ./new-tsig-key.sh [-n NAME] [-a ALGORITHM] [-b BITS] [-o OUTFILE]
#
#   -n NAME       Key name as referenced from named.conf
#                 default: zone-transfer-key
#   -a ALG        Algorithm: hmac-sha256 | hmac-sha384 | hmac-sha512
#                 default: hmac-sha384 (mandatory per deployment requirements)
#   -b BITS       Key length in bits — must be a multiple of 8
#                 default: 384  (matches sha384 output length)
#   -o OUTFILE    Write key stanza to OUTFILE in addition to stdout
#
# Requirements
#   - openssl (RHEL/OL8 default)
#   - tsig-keygen is preferred if available (bind-utils package). This script
#     uses openssl rand so it works even when bind-utils is not installed
#     (e.g. on a staging machine that only stages packages).
# =============================================================================

set -euo pipefail

KEY_NAME="zone-transfer-key"
ALGORITHM="hmac-sha384"
BITS=384
OUTFILE=""

usage() {
    sed -n '2,28p' "$0"
    exit 1
}

while getopts ":n:a:b:o:h" opt; do
    case "$opt" in
        n) KEY_NAME="$OPTARG" ;;
        a) ALGORITHM="$OPTARG" ;;
        b) BITS="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        h|*) usage ;;
    esac
done

case "$ALGORITHM" in
    hmac-sha256|hmac-sha384|hmac-sha512) : ;;
    *) echo "ERROR: unsupported algorithm '$ALGORITHM'" >&2; exit 2 ;;
esac

if (( BITS % 8 != 0 )) || (( BITS < 128 )); then
    echo "ERROR: -b BITS must be a multiple of 8 and >= 128" >&2
    exit 2
fi

BYTES=$(( BITS / 8 ))
SECRET="$(openssl rand -base64 "$BYTES" | tr -d '\n')"

STANZA=$(cat <<EOF
key "${KEY_NAME}" {
    algorithm ${ALGORITHM};
    secret "${SECRET}";
};
EOF
)

echo "$STANZA"

if [[ -n "$OUTFILE" ]]; then
    umask 077
    printf '%s\n' "$STANZA" > "$OUTFILE"
    echo "" >&2
    echo "Wrote key stanza to: $OUTFILE  (mode 0600)" >&2
    echo "Install on primary AND every secondary that shares this trust:" >&2
    echo "  install -d -o root -g named -m 0750 /etc/named/keys" >&2
    echo "  install -o root -g named -m 0640 ${OUTFILE} /etc/named/keys/tsig.key" >&2
fi
