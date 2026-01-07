# Copilot instructions (bpf-http-content-type)

## Project intent (POC)
This repo is a small proof-of-concept for **extracting the HTTP `Content-Type` header from raw packet bytes**.
The current implementation is a *user-space* parser that mimics the kind of parsing you’d do in an eBPF program.

## Key files / data flow
- `scripts/http_response.txt`: sample HTTP response payload (headers + body).
- `scripts/gen-packet.py`: uses Scapy to build an **IPv6 packet with extension headers** (Segment Routing Header + nested IPv6) + TCP + HTTP payload, and writes `packet.bin.local`.
- `src/parse.c`: reads `packet.bin.local`, locates IPv6 + TCP headers (including skipping IPv6 extension headers), then scans the TCP payload header lines for `Content-Type:`.
- `src/vmlinux.h`: generated from the running kernel BTF; **don’t edit by hand**.

## Developer workflows (use `mise`)
This repo is task-driven via `mise.toml`:

- Generate kernel headers (Linux only; requires `bpftool`):
  - `mise run gen-vmlinux`
- Fetch/update the sample HTTP response (requires `xh`):
  - `mise run gen-http-response`
- Generate a sample packet file (Python 3.13 + `uv`; dependency: `scapy`):
  - `mise run gen-packet`
- Build and run the debug parser (requires `clang`):
  - `mise run run-debug`

If you need Python deps locally, prefer `uv` (see `pyproject.toml` / `uv.lock`).

## Parsing conventions (important)
- Packet parsing assumes **IPv6**, not IPv4.
- TCP header discovery is done by walking IPv6 `nexthdr` and extension headers in `search_tcp_hdr()`.
  - Keep parsing bounded (the code uses `max_depth`) to mirror eBPF-style constraints.
- HTTP header scan is **line-based** and intentionally limited (`max_headers = 16`).
  - The match is case-insensitive for the prefix `Content-Type:`.

## Style / edits
- C formatting: `.clang-format` is Google-ish, 4-space indent, no column limit. Keep diffs minimal.
- Generated artifacts:
  - Treat `src/vmlinux.h` as generated.
  - `packet.bin.local` and `parse` are local artifacts; don’t “pretty print” or convert them.

## When adding new code
- Prefer to keep user-space parsing logic close to `src/parse.c` so it can later be ported to eBPF.
- If adding new parsing helpers, keep them small and avoid unbounded loops or allocations.
