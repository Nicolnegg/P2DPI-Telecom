#!/bin/bash
set -e

# === Clean previous state (optional, useful for rebuilds) ===
rm -rf certs/* private/* newcerts/* csr/* crl/* index.txt* serial*

# === Re-create the folder structure for the CA ===
mkdir -p certs private newcerts csr crl
touch index.txt
echo 1000 > serial

# === Generate the Root CA (private key + certificate) ===
echo "[+] Generating CA private key..."
openssl genrsa -out private/ca.key.pem 4096

echo "[+] Generating CA certificate with CN=P2DPI protocol..."
openssl req -x509 -new -nodes -key private/ca.key.pem -sha256 -days 3650 \
  -out certs/ca.cert.pem \
  -subj "/C=FR/ST=Paris/L=Paris/O=P2DPI/OU=RootCA/CN=P2DPI protocol"

# === Helper function to generate OpenSSL config with SAN (SubjectAltName) ===
create_openssl_conf() {
  local CN="$1"
  local SAN="$2"
  local OUTFILE="$3"

  cat > "$OUTFILE" <<EOF
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[dn]
C  = FR
ST = Paris
L  = Paris
O  = P2DPI
OU = Nodes
CN = $CN

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SAN
EOF
}

# === Function to generate a certificate for any role (Sender, Receiver, etc.) ===
generate_cert() {
  local NAME=$1
  local CN=$2
  local SAN=$3
  local CONFIG="/tmp/${NAME}.cnf"

  echo "[+] Generating $NAME key and CSR..."
  openssl genrsa -out private/${NAME}.key 2048
  create_openssl_conf "$CN" "$SAN" "$CONFIG"
  openssl req -new -key private/${NAME}.key -out csr/${NAME}.csr -config "$CONFIG"

  echo "[+] Signing $NAME certificate..."
  openssl x509 -req -in csr/${NAME}.csr -CA certs/ca.cert.pem -CAkey private/ca.key.pem \
    -CAcreateserial -out certs/${NAME}.crt -days 365 -sha256 \
    -extfile "$CONFIG" -extensions req_ext
}

# === Generate certificates for each node ===
generate_cert "receiver" "receiver.p2dpi.local" "receiver.p2dpi.local"
generate_cert "sender" "sender.p2dpi.local" "sender.p2dpi.local"
generate_cert "client" "client.p2dpi.local" "client.p2dpi.local"
generate_cert "server" "server.p2dpi.local" "server.p2dpi.local"

echo "[✓] All certificates (CA, Sender, Receiver, Client, Server) generated successfully."

# Optional: Keep the container running for inspection
tail -f /dev/null
