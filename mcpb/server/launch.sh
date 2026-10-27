#!/bin/sh
# Starts the sc-mcp binary for this OS and CPU (macOS and Linux; Windows runs the .exe directly).
dir=$(cd "$(dirname "$0")" && pwd)
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case $(uname -m) in
	x86_64 | amd64) arch=amd64 ;;
	arm64 | aarch64) arch=arm64 ;;
	*) echo "server-control: unsupported CPU $(uname -m)" >&2; exit 1 ;;
esac
bin="$dir/sc-mcp-$os-$arch"
if [ ! -f "$bin" ]; then
	echo "server-control: no binary for $os/$arch in this bundle" >&2
	exit 1
fi
# Bundles packed on Windows carry no Unix permissions, so restore the executable bit.
[ -x "$bin" ] || chmod +x "$bin"
exec "$bin" "$@"
