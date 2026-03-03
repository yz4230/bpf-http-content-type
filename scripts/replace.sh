#!/bin/bash
set -euo pipefail

# usage: sudo ./scripts/replace.sh [add|rep|del]
OPERATION=${1:-rep}

SID_NS2_DX4=fd00:3::2
SID_NS3_END=fd00:3::3
SID_NS4_DX4=fd00:3::4

CMD="ip -n ns3 -6 route $OPERATION $SID_NS3_END/128"
if [[ "$OPERATION" == "add" || "$OPERATION" == "rep" ]]; then
	CMD+=" encap bpf xmit obj bin/parse.bpf.o section lwt_xmit dev veth1@ns3"
fi

eval "$CMD"
