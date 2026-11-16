#!/bin/bash
# SPDX-License-Identifier: MIT
# Scan OCI image layouts for known vulnerabilities with Anchore's grype,
# fetched once into DIR and verified before it runs:
#
#   tools/scan-images.sh DIR OCI_DIR...
#
# - grype is pinned (GRYPE_VERSION and the digests below). Its release
#   tarball must match GitHub's recorded digest and the release's checksums
#   file, and that file must carry a Sigstore signature whose certificate
#   names Anchore's release workflow and chains to Sigstore's Fulcio CA
#   (needs openssl and python3). The transparency-log entry isn't checked.
# - Its vulnerability database goes in DIR/db; grype checks its checksum.
# - WRAP is a command prefix to scan as another user (e.g. setpriv ... to
#   run as nobody); DIR must be writable by that user.
# - Per image: the distro, the matches by severity, which have a fix, and
#   every Critical and High one. The full reports are DIR/out/NAME.json.
#
# Nothing here is installed outside DIR.
set -eu
DIR=$1
shift
WRAP=${WRAP:-}
V=${GRYPE_VERSION:-0.121.0}
TAR=grype_${V}_linux_amd64.tar.gz SUMS=grype_${V}_checksums.txt
mkdir -p "$DIR/bin" "$DIR/out" "$DIR/home"
if [ ! -x "$DIR/bin/grype" ] || [ "$("$DIR/bin/grype" version | awk '/^Version:/ {print $2}')" != "$V" ]; then
    case $V in
    0.121.0) want="64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519  $TAR
938761709760ee0e94ebca564a757b6658ab4efddc0d19ecc6ede12f22d2fdd0  $SUMS
76e0fda1979bdc991dcab685fd10ed59c704edcab083667684412527e35af0e9  $SUMS.sigstore.json" ;;
    *) echo "no pinned digests for grype $V: add them from GitHub's release page" >&2; exit 2 ;;
    esac
    D=$(mktemp -d "$DIR/dl.XXXXXX")
    cd "$D"
    for f in $TAR $SUMS $SUMS.sigstore.json; do
        curl -fsSL --proto '=https' -o "$f" "https://github.com/anchore/grype/releases/download/v$V/$f"
    done
    curl -fsSL --proto '=https' -o trusted_root.json \
        https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json
    echo "$want" | sha256sum -c --quiet -
    grep " $TAR\$" $SUMS | sha256sum -c --quiet -
    python3 -I - $SUMS.sigstore.json $SUMS trusted_root.json << 'EOF'
import base64, hashlib, json, sys
b = json.load(open(sys.argv[1]))
vm = b["verificationMaterial"]
cert = vm.get("certificate", {}).get("rawBytes") or vm["x509CertificateChain"]["certificates"][0]["rawBytes"]
open("leaf.der", "wb").write(base64.b64decode(cert))
ms = b["messageSignature"]
open("sig.bin", "wb").write(base64.b64decode(ms["signature"]))
if base64.b64decode(ms["messageDigest"]["digest"]).hex() != hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest():
    sys.exit("the signature bundle is for another checksums file")
with open("fulcio.pem", "w") as f:
    for ca in json.load(open(sys.argv[3]))["certificateAuthorities"]:
        for c in ca["certChain"]["certificates"]:
            f.write("-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(base64.b64decode(c["rawBytes"])).decode() +
                    "-----END CERTIFICATE-----\n")
EOF
    openssl x509 -inform der -in leaf.der -out leaf.pem
    openssl x509 -in leaf.pem -noout -pubkey > leaf.pub
    openssl dgst -sha256 -verify leaf.pub -signature sig.bin $SUMS > /dev/null
    openssl x509 -in leaf.pem -noout -ext subjectAltName |
        grep -qx '    URI:https://github.com/anchore/grype/.github/workflows/release.yaml@refs/heads/main' ||
        { echo "the signing certificate isn't Anchore's release workflow" >&2; exit 1; }
    t=$(date -d "$(openssl x509 -in leaf.pem -noout -startdate | cut -d= -f2) + 1 min" +%s)
    openssl verify -attime "$t" -partial_chain -CAfile fulcio.pem -purpose any leaf.pem > /dev/null
    tar -xzf $TAR -C "$DIR/bin" grype
    cd - > /dev/null
    rm -rf "$D"
    echo "grype $V: digests, checksums, signature and certificate verified"
fi
[ -z "$WRAP" ] || chmod -R a+rwX "$DIR"
G=(env GRYPE_DB_CACHE_DIR="$DIR/db" GRYPE_CHECK_FOR_APP_UPDATE=false HOME="$DIR/home" XDG_CACHE_HOME="$DIR/cache")
$WRAP "${G[@]}" "$DIR/bin/grype" db update 2>&1 | tail -1
$WRAP "${G[@]}" "$DIR/bin/grype" db status | grep -E '^(Built|Status):'
for oci in "$@"; do
    name=$(basename "$oci")
    echo "== $name ($oci)"
    $WRAP "${G[@]}" GRYPE_DB_AUTO_UPDATE=false "$DIR/bin/grype" -q "oci-dir:$oci" -o json --file "$DIR/out/$name.json"
    python3 -I - "$DIR/out/$name.json" << 'EOF'
import collections, json, sys
r = json.load(open(sys.argv[1]))
order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
m = r["matches"]
d = r.get("distro", {})
print(f'distro: {d.get("name")} {d.get("version")}')
sev = collections.Counter(x["vulnerability"]["severity"] for x in m)
print("matches: " + (", ".join(f"{sev[s]} {s}" for s in order if sev[s]) or "none"))
fixed = [x for x in m if x["vulnerability"]["fix"]["state"] == "fixed"]
print(f"with a fix released: {len(fixed)}")
for x in sorted(m, key=lambda x: order.index(x["vulnerability"]["severity"])):
    v, a = x["vulnerability"], x["artifact"]
    if v["severity"] in ("Critical", "High") or v["fix"]["state"] == "fixed":
        loc = a["locations"][0]["path"] if a.get("locations") else ""
        print(f'  {v["severity"]:8} {v["id"]:20} {a["name"]} {a["version"]} ({a["type"]}): '
              f'{v["fix"]["state"]} {",".join(v["fix"]["versions"])} {loc}')
EOF
done
