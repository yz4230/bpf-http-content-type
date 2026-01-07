#include "vmlinux.h"

// clang-format off
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// clang-format on

#define MAX_HDR_DEPTH 8
#define MAX_HTTP_HEADERS 8
#define MAX_PAYLOAD_SCAN 128
#define MAX_CT_LINE 48

#define TOLOWER(c) ((c) >= 'A' && (c) <= 'Z' ? (c) + 32 : (c))

#define IPPROTO_ROUTING 43

static int search_headers(void *data, void *data_end,
                          struct ipv6hdr **ip6h, struct ipv6_sr_hdr **srh, struct tcphdr **tcph) {
    u8 *buf = (u8 *)data;
    u8 nexthdr = IPPROTO_IPV6;  // assume starting with IPv6

    for (u32 depth = 0; depth < MAX_HDR_DEPTH; depth++) {
        switch (nexthdr) {
            case IPPROTO_IPV6: {
                *ip6h = (struct ipv6hdr *)(buf);
                if ((void *)(*ip6h + 1) > data_end) return -1;
                nexthdr = (*ip6h)->nexthdr;
                buf += sizeof(struct ipv6hdr);
                break;
            }
            case IPPROTO_ROUTING: {
                struct ipv6_rt_hdr *rth = (struct ipv6_rt_hdr *)(buf);
                if ((void *)(rth + 1) > data_end) return -1;

                if (rth->type == 4)
                    *srh = (struct ipv6_sr_hdr *)(buf);

                nexthdr = rth->nexthdr;
                u32 hdr_bytes = (u32)(rth->hdrlen + 1) * 8;
                if ((void *)(buf + hdr_bytes) > data_end) return -1;
                buf += hdr_bytes;
                break;
            }
            case IPPROTO_TCP: {
                if (!*ip6h) return -1;
                *tcph = (struct tcphdr *)(buf);
                if ((void *)(*tcph + 1) > data_end) return -1;
                return 0;
            }
            default:
                return -1;
        }
    }

    return -1;
}

SEC("lwt_xmit")
int bpf_prog(struct __sk_buff *skb) {
    void *data = (void *)(u64)skb->data;
    void *data_end = (void *)(u64)skb->data_end;

    bpf_printk("SBK len: %d\n", skb->len);

    struct ipv6hdr *ip6h = NULL;
    struct ipv6_sr_hdr *srh = NULL;
    struct tcphdr *tcph = NULL;
    if (search_headers(data, data_end, &ip6h, &srh, &tcph) < 0) {
        bpf_printk("Failed to find TCP header\n");
        return BPF_OK;
    }

    if (!(ip6h && (void *)(ip6h + 1) <= data_end &&
          tcph && (void *)(tcph + 1) <= data_end)) {
        bpf_printk("Invalid headers\n");
        return BPF_OK;
    }

    bpf_printk(
        "Found IPv6 header\n"
        "    src: %pI6\n"
        "    dst: %pI6\n",
        (u64)&ip6h->saddr, (u64)&ip6h->daddr);
    bpf_printk(
        "Found TCP header\n"
        "    src port: %d\n"
        "    dst port: %d\n",
        bpf_ntohs(tcph->source), bpf_ntohs(tcph->dest));

    u64 payload_off = ((u64 *)tcph - (u64 *)data) + (u64)(tcph->doff * 4);
    if (bpf_skb_pull_data(skb, 0) < 0) {
        bpf_printk("Failed to pull payload bytes\n");
        return BPF_OK;
    }

    u8 buf[MAX_PAYLOAD_SCAN];
    u32 want = skb->len - payload_off;
    if (want > sizeof(buf) - 1) want = sizeof(buf) - 1;
    if (want < 1) want = 1;
    if (bpf_skb_load_bytes(skb, payload_off, buf, want) < 0) {
        bpf_printk("Failed to load payload bytes\n");
        return BPF_OK;
    }

    // scan headers for Content-Type (single-pass, verifier-friendly)
    // "content-type:" pre-lowercased
    const char ct_lower[] = "content-type:";
    const int ct_match_len = sizeof(ct_lower) - 1;

    u32 pos = 0;            // current position in buffer
    int at_line_start = 1;  // are we at the start of a line?
    int match_idx = 0;      // how many chars of ct_lower matched so far
    int found = 0;

    for (int iter = 0; iter < MAX_PAYLOAD_SCAN; iter++) {
        if (pos >= want) break;
        if (found) break;

        u8 c = buf[pos];

        // Check for end of HTTP headers (empty line)
        if (at_line_start && (c == '\r' || c == '\n')) break;

        if (at_line_start) {
            // Start matching Content-Type:
            u8 lc = TOLOWER(c);
            match_idx = (lc == ct_lower[0]) ? 1 : 0;
            at_line_start = 0;
        } else if (match_idx > 0 && match_idx < ct_match_len) {
            u8 lc = TOLOWER(c);
            if (lc == ct_lower[match_idx]) {
                match_idx++;
                if (match_idx == ct_match_len) {
                    found = 1;
                }
            } else {
                match_idx = 0;
            }
        }

        // Advance to next char, detect newlines
        if (c == '\n') {
            at_line_start = 1;
            match_idx = 0;
        }
        pos++;
    }

    // print content type line if found
    if (found) {
        // extract value until end of line
        u8 ct[MAX_CT_LINE];
        u32 ct_off = 0;
        for (u32 i = 0; i < MAX_CT_LINE - 1; i++) {
            u32 idx = pos + i;
            if (idx >= want) break;
            u8 c = buf[idx];
            if (c == '\r' || c == '\n') break;
            ct[ct_off++] = c;
        }
        ct[ct_off] = '\0';
        bpf_printk("Content-Type:%s\n", ct);
    }

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
