#!/bin/bash
set -euxo pipefail

for ns in ns1 ns2 ns3 ns4 ns5 ns6; do
	ip netns del $ns
done
