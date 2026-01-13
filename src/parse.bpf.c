#include "vmlinux.h"

// clang-format off
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// clang-format on

#define MAX_HDR_DEPTH 4
#define MAX_HTTP_HEADERS 8
#define MAX_PAYLOAD_SCAN 128
#define MAX_CT_LINE 48

#define TOLOWER(c) ((c) >= 'A' && (c) <= 'Z' ? (c) + 32 : (c))

#define IPPROTO_ROUTING 43

// "content-type:" pre-lowercased
static const char ct_lower[] = "content-type:";

struct ct_scan_ctx {
    const u8 *buf;
    u32 want;
    int at_line_start;
    int match_idx;
    int found;
    int stop;
    u32 pos_after_match;
};

static long ct_scan_cb(u32 idx, void *ctx_ptr) {
    struct ct_scan_ctx *ctx = (struct ct_scan_ctx *)ctx_ptr;
    const int ct_match_len = sizeof(ct_lower) - 1;

    if (ctx->stop || ctx->found) return 1;
    // bpf_loop's index isn't range-tracked by the verifier, so we must
    // explicitly bound it before doing a variable-offset stack read.
    u32 pos = idx & (MAX_PAYLOAD_SCAN - 1);
    if (pos >= ctx->want) return 1;

    u8 c = ctx->buf[pos];

    // End of HTTP headers (empty line)
    if (ctx->at_line_start && (c == '\r' || c == '\n')) {
        ctx->stop = 1;
        return 1;
    }

    if (ctx->at_line_start) {
        u8 lc = TOLOWER(c);
        ctx->match_idx = (lc == ct_lower[0]) ? 1 : 0;
        ctx->at_line_start = 0;
    } else if (ctx->match_idx > 0 && ctx->match_idx < ct_match_len) {
        u8 lc = TOLOWER(c);
        if (lc == ct_lower[ctx->match_idx]) {
            ctx->match_idx++;
            if (ctx->match_idx == ct_match_len) {
                ctx->found = 1;
                ctx->pos_after_match = pos + 1;
                return 1;
            }
        } else {
            ctx->match_idx = 0;
        }
    }

    if (c == '\n') {
        ctx->at_line_start = 1;
        ctx->match_idx = 0;
    }

    return 0;
}

static int search_headers(void *data, void *data_end,
                          struct ipv6hdr **ip6h, struct ipv6_sr_hdr **srh, struct tcphdr **tcph) {
    u8 *buf = (u8 *)data;
    u8 nexthdr = IPPROTO_IPV6;  // assume starting with IPv6
    struct ipv6hdr *last_ip6h = NULL;

    for (u32 depth = 0; depth < MAX_HDR_DEPTH; depth++) {
        switch (nexthdr) {
            case IPPROTO_IPIP: {  // IPv4-in-IPv6
                struct iphdr *iph = (struct iphdr *)(buf);
                if ((void *)(iph + 1) > data_end) return -1;
                nexthdr = iph->protocol;
                u32 ihl_bytes = (u32)(iph->ihl) * 4;
                if ((void *)(buf + ihl_bytes) > data_end) return -1;
                buf += ihl_bytes;
                break;
            }
            case IPPROTO_IPV6: {
                last_ip6h = (struct ipv6hdr *)(buf);
                if (!*ip6h) *ip6h = last_ip6h;
                if ((void *)(last_ip6h + 1) > data_end) return -1;
                nexthdr = last_ip6h->nexthdr;
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

    bpf_printk("SKB len: %d\n", skb->len);

    struct ipv6hdr *ip6h = NULL;
    struct ipv6_sr_hdr *srh = NULL;
    struct tcphdr *tcph = NULL;
    if (search_headers(data, data_end, &ip6h, &srh, &tcph) < 0) {
        bpf_printk("Failed to find TCP header\n");
        return BPF_OK;
    }

    if (!ip6h || !tcph) {
        bpf_printk("Invalid headers\n");
        return BPF_OK;
    }

    if (!((void *)(ip6h + 1) <= data_end)) {
        bpf_printk("IPv6 header out of bounds\n");
        return BPF_OK;
    }

    if (!((void *)(tcph + 1) <= data_end)) {
        bpf_printk("TCP header out of bounds\n");
        return BPF_OK;
    }

    if (srh && (void *)(srh + 1) <= data_end) {
        bpf_printk(
            "Found SRH header\n"
            "    segments_left: %d\n",
            srh->segments_left);

        srh->segments_left--;
        bpf_printk("    decremented segments_left: %d\n", srh->segments_left);
        struct in6_addr *new_dst = srh->segments + srh->segments_left;
        if (data <= (void *)new_dst && (void *)(new_dst + 1) <= data_end) {
            bpf_printk("    new dst: %pI6\n", (u64)new_dst);
            ip6h->daddr = *new_dst;
        }
    }

    ip6h->hop_limit = 42;

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

    // if ack, skip payload processing
    if (tcph->ack) {
        bpf_printk("TCP ACK packet, skipping payload processing\n");
        return BPF_LWT_REROUTE;
    }

    u64 payload_off = (u64)((void *)tcph - data) + (u64)(tcph->doff * 4);
    if (bpf_skb_pull_data(skb, 0) < 0) {
        bpf_printk("Failed to pull payload bytes\n");
        return BPF_LWT_REROUTE;
    }

    u8 buf[MAX_PAYLOAD_SCAN];
    u32 want = skb->len - payload_off;
    if (want > sizeof(buf) - 1) want = sizeof(buf) - 1;
    if (want < 1) want = 1;
    bpf_printk("Loading %d bytes of payload at offset %llu\n", want, payload_off);
    if (bpf_skb_load_bytes(skb, payload_off, buf, want) < 0) {
        bpf_printk("Failed to load payload bytes\n");
        return BPF_LWT_REROUTE;
    }

    // scan headers for Content-Type (single-pass, verifier-friendly)
    struct ct_scan_ctx scan_ctx = {
        .buf = buf,
        .want = want,
        .at_line_start = 1,
        .match_idx = 0,
        .found = 0,
        .stop = 0,
        .pos_after_match = 0,
    };
    bpf_loop(MAX_PAYLOAD_SCAN, ct_scan_cb, &scan_ctx, 0);

    // print content type line if found
    if (scan_ctx.found) {
        u32 pos = scan_ctx.pos_after_match;
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

    return BPF_LWT_REROUTE;
}

char _license[] SEC("license") = "GPL";
