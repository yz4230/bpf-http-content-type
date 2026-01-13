#!/bin/bash
set -euo pipefail

SID_NS2_DX4=fd00:3::2
SID_NS3_END=fd00:3::3
SID_NS4_DX4=fd00:3::4

ip -n ns3 -6 route rep $SID_NS3_END/128 encap bpf xmit obj bin/parse.bpf.o section lwt_xmit dev veth1@ns3
