#!/usr/bin/env bash
# fetch-open-access.sh — Download freely available reference PDFs
#
# Usage: cd doc/references && bash fetch-open-access.sh
#
# This script downloads only references that are freely and legally
# available from their official sources (RFCs, NIST standards, ePrints).
# Paywalled conference papers must be obtained separately.

set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

dl() {
    local file="$1" url="$2"
    if [ -f "$file" ]; then
        echo "  SKIP  $file (exists)"
    else
        echo "  FETCH $file"
        curl -sSfL -o "$file" "$url" || echo "  FAIL  $file"
    fi
}

echo "=== NIST Standards ==="
dl "FIPS-180-4.pdf"   "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf"
dl "FIPS-197.pdf"     "https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf"
dl "FIPS-203.pdf"     "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf"
dl "FIPS-204.pdf"     "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf"
dl "FIPS-205.pdf"     "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf"
dl "SP-800-38D.pdf"   "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf"
dl "SP-800-90A.pdf"   "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf"

echo ""
echo "=== IETF RFCs ==="
dl "RFC-1951.pdf"  "https://www.rfc-editor.org/rfc/pdfrfc/rfc1951.txt.pdf"
dl "RFC-2104.pdf"  "https://www.rfc-editor.org/rfc/pdfrfc/rfc2104.txt.pdf"
dl "RFC-4033.pdf"  "https://www.rfc-editor.org/rfc/pdfrfc/rfc4033.txt.pdf"
dl "RFC-4034.pdf"  "https://www.rfc-editor.org/rfc/pdfrfc/rfc4034.txt.pdf"
dl "RFC-4035.pdf"  "https://www.rfc-editor.org/rfc/pdfrfc/rfc4035.txt.pdf"
dl "RFC-5869.pdf"  "https://www.rfc-editor.org/rfc/pdfrfc/rfc5869.txt.pdf"
dl "RFC-6177.pdf"  "https://www.rfc-editor.org/rfc/pdfrfc/rfc6177.txt.pdf"
dl "RFC-7748.pdf"  "https://www.rfc-editor.org/rfc/pdfrfc/rfc7748.txt.pdf"
dl "RFC-8032.pdf"  "https://www.rfc-editor.org/rfc/pdfrfc/rfc8032.txt.pdf"
dl "RFC-8439.pdf"  "https://www.rfc-editor.org/rfc/pdfrfc/rfc8439.txt.pdf"
dl "RFC-8446.pdf"  "https://www.rfc-editor.org/rfc/pdfrfc/rfc8446.txt.pdf"
dl "RFC-8452.pdf"  "https://www.rfc-editor.org/rfc/pdfrfc/rfc8452.txt.pdf"
dl "RFC-8949.pdf"  "https://www.rfc-editor.org/rfc/pdfrfc/rfc8949.txt.pdf"
dl "RFC-9106.pdf"  "https://www.rfc-editor.org/rfc/pdfrfc/rfc9106.txt.pdf"
dl "RFC-9381.pdf"  "https://www.rfc-editor.org/rfc/pdfrfc/rfc9381.txt.pdf"

echo ""
echo "=== IACR ePrint / Open Access Papers ==="
dl "Bernstein-2005-CacheTimingAES.pdf"  "https://cr.yp.to/antiforgery/cachetiming-20050414.pdf"
dl "Bernstein-2006-Curve25519.pdf"      "https://cr.yp.to/ecdh/curve25519-20060209.pdf"
dl "Bernstein-2008-ChaCha.pdf"          "https://cr.yp.to/chacha/chacha-20080128.pdf"
dl "Perrin-2018-Noise.pdf"              "https://noiseprotocol.org/noise.pdf"

echo ""
echo "=== Summary ==="
total=$(find . -maxdepth 1 -name '*.pdf' | wc -l)
echo "PDFs present: $total / 83"
echo ""
echo "Remaining papers must be obtained from their respective publishers"
echo "(Springer, IEEE, ACM, USENIX) or from the authors' personal pages."
