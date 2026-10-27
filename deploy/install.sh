#!/bin/sh
# Install sc-server on a systemd-based Linux host.
#   sudo ./install.sh ./sc-server-linux-amd64 [first-key-name]
set -eu

BIN=${1:?usage: install.sh <sc-server binary> [first-key-name]}
KEY_NAME=${2:-}
HERE=$(cd "$(dirname "$0")" && pwd)
CONF_DIR=/etc/server-control
CONF=$CONF_DIR/config.yaml

if [ "$(id -u)" -ne 0 ]; then
	echo "run as root (sudo)" >&2
	exit 1
fi

install -m 0755 "$BIN" /usr/local/bin/sc-server
install -d -m 0700 "$CONF_DIR"
if [ ! -f "$CONF" ]; then
	install -m 0600 "$HERE/config.example.yaml" "$CONF"
	echo "Created $CONF"
fi
if [ ! -f "$CONF_DIR/tls/cert.pem" ]; then
	/usr/local/bin/sc-server cert gen -config "$CONF"
fi

install -d -m 0700 /var/log/server-control
if [ -d /etc/logrotate.d ]; then
	install -m 0644 "$HERE/sc-server.logrotate" /etc/logrotate.d/sc-server
fi

install -m 0644 "$HERE/sc-server.service" /etc/systemd/system/sc-server.service
systemctl daemon-reload

if [ -n "$KEY_NAME" ]; then
	/usr/local/bin/sc-server key add -config "$CONF" -name "$KEY_NAME" -scopes all \
		-read-path / -write-path / -service '*'
fi

systemctl enable --now sc-server
systemctl reload sc-server 2>/dev/null || true

echo
echo "sc-server is running. Certificate fingerprint:"
/usr/local/bin/sc-server fingerprint -config "$CONF"
echo
echo "Create (more) keys with, for example:"
echo "  sudo sc-server key add -name monitoring -scopes info,exec,services -allow '^uptime\$' -service nginx"
echo "then: sudo systemctl reload sc-server"
