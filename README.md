
# bpf-http-content-type

Proof-of-concept: extract the HTTP `Content-Type` header from raw packet bytes in an **eBPF LWT (SRv6) program**, then optionally influence SRH forwarding based on the value.

This repo also includes a small kernel module that registers a few string helper **kfuncs** (e.g. `bpf_strcmp`) used by the BPF program.

## What it does

- Sets up an SRv6 lab topology using Linux network namespaces.
- Attaches an eBPF program to a **SRv6 End SID** via `ip -6 route ... encap bpf xmit`.
- On matching packets, the BPF program:
	- Locates IPv6 / SRH / TCP headers (bounded walk).
	- Scans the first ~128 bytes of TCP payload for a line that begins with `Content-Type:` (case-insensitive).
	- Prints the extracted value via `bpf_printk`.
	- Always advances the SRH like an `End` behavior (advance one segment).
	- If the value equals `video/mp4`, advances one extra segment (advance two total).

Implementation lives in `src/parse.bpf.c`.

## Repo layout

- `src/parse.bpf.c`: LWT_XMIT BPF program (header discovery + HTTP header scan + SRH rewrite).
- `src/vmlinux.h`: generated from `/sys/kernel/btf/vmlinux` (do not edit).
- `module/string.c`: kernel module registering string kfuncs (loaded as `string.ko`).
- `scripts/tearup.sh`: creates namespaces + veths + SRv6 routes and attaches the BPF program.
- `scripts/replace.sh`: remove/add/replace the BPF attachment on the ns3 End SID.
- `scripts/teardown.sh`: deletes namespaces.
- `scripts/http_response.txt`: sample HTTP payload used by the Scapy generator.
- `scripts/gen-packet.py`: builds an example IPv6+SRH+nested-IPv6+TCP+HTTP packet and writes `packet.bin.local`.
