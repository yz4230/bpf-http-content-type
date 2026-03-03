#include "vmlinux.h"

// clang-format off
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern int bpf_strcmp(const char *s1, const char *s2) __ksym;
extern int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz) __ksym;
extern int bpf_strcasestr(const char *s1, u32 len1, const char *s2, u32 len2) __ksym;

#define MAX_HDR_DEPTH 8
#define MAX_HTTP_HEADERS 8
#define MAX_PAYLOAD_SCAN 128
#define MAX_CT_LINE 48

#define TOLOWER(c) ((c) >= 'A' && (c) <= 'Z' ? (c) + 32 : (c))

#define IPPROTO_ROUTING 43

// "content-type:" pre-lowercased
static const char ct_lower[] = "content-type: ";

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
                          u16 *ip6h_off, u16 *srh_off, u16 *tcph_off) {
    u8 *buf = (u8 *)data;
    u8 nexthdr = IPPROTO_IPV6;  // assume starting with IPv6
    u16 offset = 0;

    bpf_repeat(MAX_HDR_DEPTH) {
        offset &= 0xff;
        barrier_var(offset);

        switch (nexthdr) {
            case IPPROTO_IPIP: {  // IPv4-in-IPv6
                struct iphdr *iph = (struct iphdr *)(buf + offset);
                if ((void *)(iph + 1) > data_end) return -1;
                nexthdr = iph->protocol;
                u32 ihl_bytes = (u32)(iph->ihl) * 4;
                offset += ihl_bytes;
                break;
            }
            case IPPROTO_IPV6: {
                if (*ip6h_off == 0) *ip6h_off = offset;
                struct ipv6hdr *ip6h = (struct ipv6hdr *)(buf + offset);
                if ((void *)(ip6h + 1) > data_end) return -1;
                nexthdr = ip6h->nexthdr;
                offset += sizeof(struct ipv6hdr);
                break;
            }
            case IPPROTO_ROUTING: {
                struct ipv6_rt_hdr *rth = (struct ipv6_rt_hdr *)(buf + offset);
                if ((void *)(rth + 1) > data_end) return -1;
                if (rth->type == 4) *srh_off = offset;
                nexthdr = rth->nexthdr;
                u32 hdr_bytes = (u32)(rth->hdrlen + 1) * 8;
                if ((void *)(buf + offset + hdr_bytes) > data_end) return -1;
                offset += hdr_bytes;
                break;
            }
            case IPPROTO_TCP: {
                *tcph_off = offset;
                if ((void *)(buf + offset + sizeof(struct tcphdr)) > data_end) return -1;
                return 0;
            }
            default:  // unsupported protocol
                return -1;
        }
    }

    return 0;
}

SEC("lwt_xmit")
int bpf_prog(struct __sk_buff *skb) {
    void *data, *data_end;
    u8 segleft_adv = 1;

    bpf_printk("xmit triggered, skb len: %d\n", skb->len);

    data = (void *)(u64)skb->data;
    data_end = (void *)(u64)skb->data_end;

    u16 ip6h_off = 0, srh_off = 0, tcph_off = 0;
    if (search_headers(data, data_end, &ip6h_off, &srh_off, &tcph_off) < 0) {
        bpf_printk("Failed to find TCP header\n");
        return BPF_OK;
    }

    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + ip6h_off);
    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)(data + srh_off);
    if ((void *)(ip6h + 1) > data_end || (void *)(srh + 1) > data_end) {
        bpf_printk("IPv6 or SRH header out of bounds\n");
        return BPF_OK;
    }

    struct tcphdr *tcph = (struct tcphdr *)(data + tcph_off);
    if ((void *)(tcph + 1) > data_end) {
        bpf_printk("TCP header out of bounds\n");
        goto reroute;
    }

    bpf_printk(
        "Found IPv6 header\n"
        "    src: %pI6\n"
        "    dst: %pI6\n",
        "Found SRH header\n"
        "    segments_left: %d\n",
        "Found TCP header\n"
        "    src port: %d\n"
        "    dst port: %d\n",
        (u64)&ip6h->saddr, (u64)&ip6h->daddr,
        srh->segments_left,
        bpf_ntohs(tcph->source), bpf_ntohs(tcph->dest));

    ip6h->hop_limit = 42;  // for easy identification of processed packets

    u64 payload_off = (u64)((void *)tcph - data) + (u64)(tcph->doff * 4);
    if (payload_off >= skb->len) {
        bpf_printk("No TCP payload. Skipping\n");
        goto reroute;
    }

    if (bpf_skb_pull_data(skb, 0) < 0) {
        bpf_printk("Failed to pull payload bytes\n");
        goto reroute;
    }

    u8 buf[MAX_PAYLOAD_SCAN];
    u32 want = skb->len - payload_off;
    if (want > sizeof(buf) - 1) want = sizeof(buf) - 1;
    if (want < 1) want = 1;
    bpf_printk("Loading %d bytes of payload at offset %llu\n", want, payload_off);
    if (bpf_skb_load_bytes(skb, payload_off, buf, want) < 0) {
        bpf_printk("Failed to load payload bytes\n");
        goto reroute;
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
    u8 ct[MAX_CT_LINE];
    u32 ct_off = 0;
    if (scan_ctx.found) {
        u32 pos = scan_ctx.pos_after_match;
        // extract value until end of line
        for (u32 i = 0; i < MAX_CT_LINE - 1; i++) {
            u32 idx = pos + i;
            if (idx >= want) break;
            u8 c = buf[idx];
            if (c == '\r' || c == '\n') break;
            ct[ct_off++] = c;
        }
        ct_off &= (MAX_CT_LINE - 1);
        ct[ct_off] = '\0';
        bpf_printk("Content-Type:%s\n", ct);
    }

    const char mp4[] = "video/mp4";
    if (bpf_strcmp((const char *)ct, mp4) == 0) {
        segleft_adv++;  // advance one extra segment for MP4
        bpf_printk("MP4 Content-Type detected, performing SRH reroute\n");
    } else {
        bpf_printk("Non-MP4 or no Content-Type detected, skipping SRH reroute\n");
    }

reroute:
    data = (void *)(u64)skb->data;
    data_end = (void *)(u64)skb->data_end;
    ip6h = (struct ipv6hdr *)(data + ip6h_off);
    srh = (struct ipv6_sr_hdr *)(data + srh_off);

    if (!(data <= (void *)ip6h && (void *)(ip6h + 1) <= data_end)) {
        bpf_printk("IPv6 header out of bounds after skb pull\n");
        return BPF_OK;
    }
    if (!(data <= (void *)srh && (void *)(srh + 1) <= data_end)) {
        bpf_printk("SRH header out of bounds after skb pull\n");
        return BPF_OK;
    }

    srh->segments_left = srh->segments_left > segleft_adv ? srh->segments_left - segleft_adv : 0;
    struct in6_addr *new_dst = srh->segments + srh->segments_left;
    if (data <= (void *)new_dst && (void *)(new_dst + 1) <= data_end) {
        ip6h->daddr = *new_dst;
        bpf_printk("Updated dst: %pI6\n", (u64)&ip6h->daddr);
    }

    return BPF_LWT_REROUTE;
}

char _license[] SEC("license") = "GPL";
