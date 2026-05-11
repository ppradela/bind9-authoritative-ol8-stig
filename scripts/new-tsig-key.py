#!/usr/bin/env python3
# =============================================================================
# new-tsig-key.py — generate a TSIG key stanza (hmac-sha384 by default) for
# inclusion in /etc/named/keys/tsig.key. The same key must be installed on
# the primary and every secondary sharing the trust relationship.
#
# Cross-platform; uses only the standard library (secrets + base64). Suitable
# for staging machines without bind-utils installed.
#
# Usage:
#   python3 new-tsig-key.py [-n NAME] [-a ALG] [-b BITS] [-o OUTFILE]
# =============================================================================

import argparse
import base64
import os
import secrets
import stat
import sys

ALGORITHMS = ("hmac-sha256", "hmac-sha384", "hmac-sha512")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a BIND TSIG key stanza.")
    parser.add_argument("-n", "--name", default="zone-transfer-key",
                        help="key name as referenced from named.conf "
                             "(default: zone-transfer-key)")
    parser.add_argument("-a", "--algorithm", default="hmac-sha384",
                        choices=ALGORITHMS,
                        help="HMAC algorithm (default: hmac-sha384)")
    parser.add_argument("-b", "--bits", type=int, default=384,
                        help="key length in bits, multiple of 8, "
                             ">= 128 (default: 384)")
    parser.add_argument("-o", "--outfile", default=None,
                        help="also write the key stanza to OUTFILE (mode 0600)")
    args = parser.parse_args()

    if args.bits < 128 or args.bits % 8 != 0:
        print("ERROR: --bits must be a multiple of 8 and >= 128",
              file=sys.stderr)
        return 2

    secret = base64.b64encode(secrets.token_bytes(args.bits // 8)).decode("ascii")

    stanza = (
        f'key "{args.name}" {{\n'
        f'    algorithm {args.algorithm};\n'
        f'    secret "{secret}";\n'
        f'}};\n'
    )

    print(stanza, end="")

    if args.outfile:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = stat.S_IRUSR | stat.S_IWUSR  # 0600
        fd = os.open(args.outfile, flags, mode)
        with os.fdopen(fd, "w") as fh:
            fh.write(stanza)
        print(f"\nWrote key stanza to: {args.outfile}  (mode 0600)",
              file=sys.stderr)
        print("Install on primary AND every secondary that shares this trust:",
              file=sys.stderr)
        print("  install -d -o root -g named -m 0750 /etc/named/keys",
              file=sys.stderr)
        print(f"  install -o root -g named -m 0640 {args.outfile} "
              "/etc/named/keys/tsig.key", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
