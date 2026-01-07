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

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
