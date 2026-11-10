#!/bin/sh
# Test-only OpenVPN servers with a throwaway CA. Client profiles, including client keys, go to /out.
# Profiles name their server as @tcp@, @udp@, @userpass@, @badserver@, @pkcs1@, @cbc@ or @redirect@, for the caller to replace with host and port.
# The TCP server on 1194 starts last, so its "Initialization Sequence Completed" on stdout means every server is up.
set -eu

mkdir -p /lab /out
cd /lab

new_ca() {
    openssl ecparam -name prime256v1 -genkey -noout -out "$1.key"
    openssl req -x509 -new -key "$1.key" -sha256 -days 7 -subj "/CN=$1" -out "$1.crt"
}

# name, eku, key type (ec, rsa or ed25519)
new_cert() {
    case "$3" in
        rsa) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" ;;
        ed25519) openssl genpkey -algorithm ed25519 -out "$1.key" ;;
        *) openssl ecparam -name prime256v1 -genkey -noout -out "$1.key" ;;
    esac
    openssl req -new -key "$1.key" -subj "/CN=lab-$1" -out "$1.csr"
    printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=%s\n' "$2" > "$1.ext"
    openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 7 -sha256 -extfile "$1.ext" -out "$1.crt"
    openssl pkcs8 -topk8 -nocrypt -in "$1.key" -outform DER -out "$1.pk8"
}

new_ca ca
new_ca other-ca
new_cert server serverAuth ec
new_cert client clientAuth ec
new_cert client-rsa clientAuth rsa
new_cert client-ed25519 clientAuth ed25519
openvpn --genkey secret tc.key

# Only RSA PKCS#1 v1.5 signatures from clients, which TLS 1.2 allows and 1.3 doesn't.
cat > pkcs1.cnf <<'EOF'
openssl_conf = init
[init]
ssl_conf = ssl_section
[ssl_section]
system_default = system_default_section
[system_default_section]
MaxProtocol = TLSv1.2
ClientSignatureAlgorithms = RSA+SHA256
EOF

# User "crv" gets a second sign-in step (OpenVPN's dynamic challenge), answered with code 654321.
cat > check.sh <<'EOF'
#!/bin/sh
user=$(sed -n 1p "$1")
pass=$(sed -n 2p "$1")
if [ "$user" = crv ]; then
    case "$pass" in
        CRV1::labstate::654321) exit 0 ;;
        labpass)
            printf 'CRV1:R,E:labstate:%s:Enter the code from your app' "$(printf crv | base64)" > "${auth_failed_reason_file:-/dev/null}"
            exit 1
            ;;
        *) exit 1 ;;
    esac
fi
case "$pass" in
    SCRV1:*)
        secret=$(echo "$pass" | cut -d: -f2 | base64 -d)
        code=$(echo "$pass" | cut -d: -f3 | base64 -d)
        [ "$user" = lab ] && [ "$secret" = labpass ] && [ "$code" = 123456 ]
        ;;
    *)
        [ "$user" = lab ] && [ "$pass" = labpass ]
        ;;
esac
EOF
chmod +x check.sh

# proto, device, subnet, server cert name, port
server_config() {
    cat <<EOF
port $5
proto $1
dev $2
topology subnet
server $3 255.255.255.0
ca /lab/ca.crt
cert /lab/$4.crt
key /lab/$4.key
dh none
tls-crypt /lab/tc.key
tls-version-min 1.2
data-ciphers AES-256-GCM:CHACHA20-POLY1305
keepalive 10 60
push "dhcp-option DNS ${3%.0}.1"
push "dhcp-option DOMAIN lab.internal"
verb 3
EOF
}

# proto, remote, ca file, extra lines
client_profile() {
    cat <<EOF
client
dev tun
proto $1
remote $2
nobind
remote-cert-tls server
verb 3
$4
<ca>
$(cat "/lab/$3")
</ca>
<tls-crypt>
$(cat /lab/tc.key)
</tls-crypt>
EOF
}

inline_key() {
    printf '<cert>\n%s\n</cert>\n<key>\n%s\n</key>\n' "$(cat "/lab/$1.crt")" "$(cat "/lab/$1.key")"
}

server_config tcp-server tun0 10.8.0.0 server 1194 > server-tcp.conf
server_config udp tun1 10.9.0.0 server 1194 > server-udp.conf
{
    server_config tcp-server tun2 10.10.0.0 server 1195
    printf 'script-security 2\nauth-user-pass-verify /lab/check.sh via-file\ntmp-dir /tmp\n'
} > server-userpass.conf
server_config tcp-server tun3 10.11.0.0 client 1196 > server-badserver.conf
server_config tcp-server tun4 10.12.0.0 server 1197 > server-pkcs1.conf
# Only AES-256-CBC on the data channel, which Core leaves out unless non-preferred ciphers are allowed.
{
    server_config tcp-server tun5 10.13.0.0 server 1198
    echo "data-ciphers AES-256-CBC"
} > server-cbc.conf
# Everything a real adapter needs to know: all traffic through the VPN, a network kept outside it, metrics, no IPv6.
{
    server_config tcp-server tun6 10.14.0.0 server 1199
    cat <<'EOF'
push "redirect-gateway def1"
push "route 192.0.2.0 255.255.255.0 net_gateway"
push "route 198.51.100.0 255.255.255.0 vpn_gateway 7"
push "route-metric 50"
push "block-ipv6"
EOF
} > server-redirect.conf

{ client_profile tcp-client @tcp@ ca.crt ""; inline_key client; } > /out/client-tcp.ovpn
{ client_profile udp @udp@ ca.crt ""; inline_key client; } > /out/client-udp.ovpn
client_profile tcp-client @tcp@ ca.crt "" > /out/client-tcp-epki.ovpn
client_profile tcp-client @tcp@ ca.crt "tls-version-max 1.2" > /out/client-tcp-epki-tls12.ovpn
{ client_profile tcp-client @tcp@ other-ca.crt ""; inline_key client; } > /out/client-wrongca.ovpn
{ client_profile tcp-client @userpass@ ca.crt "auth-user-pass"; inline_key client; } > /out/client-userpass.ovpn
{ client_profile tcp-client @userpass@ ca.crt "auth-user-pass
static-challenge \"Enter your code\" 1"; inline_key client; } > /out/client-challenge.ovpn
{ client_profile tcp-client @badserver@ ca.crt ""; inline_key client; } > /out/client-badserver.ovpn
{ client_profile tcp-client @userpass@ ca.crt "auth-user-pass"; inline_key client; } > /out/client-dynamic.ovpn
client_profile tcp-client @pkcs1@ ca.crt "" > /out/client-pkcs1-epki.ovpn
{ client_profile tcp-client @cbc@ ca.crt ""; inline_key client; } > /out/client-cbc.ovpn
{ client_profile tcp-client @redirect@ ca.crt ""; inline_key client; } > /out/client-redirect.ovpn
cp client.crt client.pk8 client-rsa.crt client-rsa.pk8 client-ed25519.crt client-ed25519.pk8 /out/

openvpn --config server-udp.conf --log /lab/udp.log &
openvpn --config server-userpass.conf --log /lab/userpass.log &
openvpn --config server-badserver.conf --log /lab/badserver.log &
OPENSSL_CONF=/lab/pkcs1.cnf openvpn --config server-pkcs1.conf --log /lab/pkcs1.log &
openvpn --config server-cbc.conf --log /lab/cbc.log &
openvpn --config server-redirect.conf --log /lab/redirect.log &

waited=0
for log in udp userpass badserver pkcs1 cbc redirect; do
    until grep -q "Initialization Sequence Completed" "/lab/$log.log" 2>/dev/null; do
        waited=$((waited + 1))
        if [ "$waited" -gt 120 ]; then
            echo "The $log server didn't come up:" >&2
            cat "/lab/$log.log" >&2
            exit 1
        fi
        sleep 0.5
    done
done
exec openvpn --config server-tcp.conf
