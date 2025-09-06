#!/bin/bash
set -e
if [ ! -f build/packet_sniffer ]; then
  echo "Binary not found. Run scripts/build.sh first."
  exit 1
fi
sudo setcap cap_net_raw,cap_net_admin=eip build/packet_sniffer
echo "Capabilities set. Now you can run ./build/packet_sniffer without sudo."
