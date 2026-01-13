#!/bin/bash
set -euo pipefail

ROOT_DIR=$(dirname $(dirname $(realpath $0)))

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
	echo "Please run as root"
	exit 1
fi

# Tear up experiment topology
# ns1 <-> [ns2 <-> ns3 <-> ns4] <-> ns5
# ns2, ns3, ns4 are SRv6 tunnels

# Create network namespaces
for ns in ns1 ns2 ns3 ns4 ns5; do
	ip netns add $ns
done

# Set up veth pairs
ip link add veth1@ns1 type veth peer name veth1@ns2
ip link add veth2@ns2 type veth peer name veth1@ns3
ip link add veth2@ns3 type veth peer name veth1@ns4
ip link add veth2@ns4 type veth peer name veth1@ns5
ip link set veth1@ns1 netns ns1
ip link set veth1@ns2 netns ns2
ip link set veth2@ns2 netns ns2
ip link set veth1@ns3 netns ns3
ip link set veth2@ns3 netns ns3
ip link set veth1@ns4 netns ns4
ip link set veth2@ns4 netns ns4
ip link set veth1@ns5 netns ns5

# Configure interfaces and IP addresses
ip -n ns1 addr add 10.0.1.1/24 dev veth1@ns1
ip -n ns2 addr add 10.0.1.2/24 dev veth1@ns2
ip -n ns2 addr add fd00:1::1/64 dev veth2@ns2
ip -n ns3 addr add fd00:1::2/64 dev veth1@ns3
ip -n ns3 addr add fd00:2::1/64 dev veth2@ns3
ip -n ns4 addr add fd00:2::2/64 dev veth1@ns4
ip -n ns4 addr add 10.0.2.1/24 dev veth2@ns4
ip -n ns5 addr add 10.0.2.2/24 dev veth1@ns5

# Bring up interfaces
for ns in ns1 ns2 ns3 ns4 ns5; do
	for iface in $(ip -n $ns -j link show | jq -r '.[].ifname'); do
		ip -n $ns link set dev $iface up
	done
done

# --- SRv6 routing setup ---
# Goal:
# - ns1 -> ns5: ns2(encap) -> ns3(transit) -> ns4(decap)
# - ns5 -> ns1: ns4(encap) -> ns3(transit) -> ns2(decap)

# Enable forwarding + SRv6 support (seg6_enabled must be enabled per NIC).
for ns in ns2 ns3 ns4; do
	ip netns exec $ns sysctl -qw net.ipv6.conf.all.forwarding=1
	ip netns exec $ns sysctl -qw net.ipv6.conf.all.seg6_enabled=1
	ip netns exec $ns sysctl -qw net.ipv6.conf.default.seg6_enabled=1
	for iface in $(ip -n $ns -j link show | jq -r '.[].ifname'); do
		ip netns exec $ns sysctl -qw net.ipv6.conf.$iface.seg6_enabled=1
	done
done

# End.DX4 decap requires IPv4 forwarding.
ip netns exec ns2 sysctl -qw net.ipv4.ip_forward=1
ip netns exec ns4 sysctl -qw net.ipv4.ip_forward=1

# Edge IPv4 routes (send traffic to the SRv6 edge nodes).
ip -n ns1 route add 10.0.2.0/24 via 10.0.1.2
ip -n ns5 route add 10.0.1.0/24 via 10.0.2.1

# SIDs (keep them in a dedicated prefix; they don't need to be assigned as addresses).
SID_NS2_DX4=fd00:3::2
SID_NS3_END=fd00:3::3
SID_NS4_DX4=fd00:3::4

# Ensure SIDs are reachable through the IPv6 underlay.
ip -n ns2 -6 route add $SID_NS3_END/128 via fd00:1::2 dev veth2@ns2
ip -n ns2 -6 route add $SID_NS4_DX4/128 via fd00:1::2 dev veth2@ns2

ip -n ns3 -6 route add $SID_NS2_DX4/128 via fd00:1::1 dev veth1@ns3
ip -n ns3 -6 route add $SID_NS4_DX4/128 via fd00:2::2 dev veth2@ns3

ip -n ns4 -6 route add $SID_NS2_DX4/128 via fd00:2::1 dev veth1@ns4
ip -n ns4 -6 route add $SID_NS3_END/128 via fd00:2::1 dev veth1@ns4

# Configure SRv6 endpoint behaviors.
# - ns3: transit (End)
# - ns4: decap towards ns5 (End.DX4)
# - ns2: decap towards ns1 (End.DX4)
# ip -n ns3 -6 route add local $SID_NS3_END/128 dev lo encap seg6local action End
ip -n ns3 -6 route add $SID_NS3_END/128 encap bpf xmit obj bin/parse.bpf.o section lwt_xmit dev veth1@ns3
ip -n ns4 -6 route add $SID_NS4_DX4/128 encap seg6local action End.DX4 nh4 10.0.2.2 dev veth1@ns4
ip -n ns2 -6 route add $SID_NS2_DX4/128 encap seg6local action End.DX4 nh4 10.0.1.1 dev veth1@ns2

# Configure SRv6 encapsulation on edge nodes (IPv4-in-IPv6+SRH).
ip -n ns2 route add 10.0.2.0/24 encap seg6 mode encap segs $SID_NS3_END,$SID_NS4_DX4 dev veth2@ns2
ip -n ns4 route add 10.0.1.0/24 encap seg6 mode encap segs $SID_NS3_END,$SID_NS2_DX4 dev veth1@ns4
