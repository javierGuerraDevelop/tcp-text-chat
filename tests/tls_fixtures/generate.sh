#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

readonly openssl=/usr/bin/openssl
umask 077
tmp_dir="$(mktemp -d .tls-fixtures.XXXXXX)"
trap 'rm -rf -- "$tmp_dir"' EXIT

for name in \
    trusted_ca \
    untrusted_ca \
    trusted_server \
    wrong_host_server \
    untrusted_server \
    expired_server; do
    "$openssl" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$tmp_dir/$name.key"
done

cat > "$tmp_dir/ca.ext" <<'EOF'
[ca]
basicConstraints=critical,CA:true
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
EOF

make_ca() {
    local name=$1
    local common_name=$2
    local serial=$3

    "$openssl" req -new -sha256 -key "$tmp_dir/$name.key" \
        -subj "/CN=$common_name" -out "$tmp_dir/$name.csr"
    "$openssl" x509 -req -sha256 -in "$tmp_dir/$name.csr" \
        -signkey "$tmp_dir/$name.key" -set_serial "$serial" \
        -not_before 20200101000000Z -not_after 20400101000000Z \
        -extfile "$tmp_dir/ca.ext" -extensions ca \
        -out "$tmp_dir/$name.crt"
}

make_leaf() {
    local name=$1
    local ca_name=$2
    local common_name=$3
    local san=$4
    local not_before=$5
    local not_after=$6
    local serial=$7

    cat > "$tmp_dir/$name.ext" <<EOF
[leaf]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=$san
EOF

    "$openssl" req -new -sha256 -key "$tmp_dir/$name.key" \
        -subj "/CN=$common_name" -out "$tmp_dir/$name.csr"
    "$openssl" x509 -req -sha256 -in "$tmp_dir/$name.csr" \
        -CA "$tmp_dir/$ca_name.crt" -CAkey "$tmp_dir/$ca_name.key" \
        -set_serial "$serial" -not_before "$not_before" \
        -not_after "$not_after" -extfile "$tmp_dir/$name.ext" \
        -extensions leaf -out "$tmp_dir/$name.crt"
}

make_ca trusted_ca \
    "tcp-text-chat NON-PRODUCTION test trusted CA" 0x1000
make_ca untrusted_ca \
    "tcp-text-chat NON-PRODUCTION test untrusted CA" 0x2000

make_leaf trusted_server trusted_ca localhost \
    "DNS:localhost,IP:127.0.0.1,IP:::1" \
    20200101000000Z 20400101000000Z 0x1001
make_leaf wrong_host_server trusted_ca chat.invalid \
    "DNS:chat.invalid" \
    20200101000000Z 20400101000000Z 0x1002
make_leaf untrusted_server untrusted_ca localhost \
    "DNS:localhost,IP:127.0.0.1,IP:::1" \
    20200101000000Z 20400101000000Z 0x2001
make_leaf expired_server trusted_ca localhost \
    "DNS:localhost,IP:127.0.0.1,IP:::1" \
    20200101000000Z 20210101000000Z 0x1003

for artifact in \
    trusted_ca.crt \
    untrusted_ca.crt \
    trusted_server.crt \
    trusted_server.key \
    wrong_host_server.crt \
    wrong_host_server.key \
    untrusted_server.crt \
    untrusted_server.key \
    expired_server.crt \
    expired_server.key; do
    if [[ $artifact == *.crt ]]; then
        chmod 0644 "$tmp_dir/$artifact"
    fi
    mv "$tmp_dir/$artifact" "$artifact"
done
