#include "vmlinux.h"

// clang-format off
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern int bpf_strcmp(const char* s1, const char* s2) __ksym;
extern int bpf_strncasecmp(const char* s1, const char* s2, size_t n) __ksym;
extern int bpf_strnstr(const char* s1, const char* s2, size_t n) __ksym;

#define MAX_HDR_DEPTH 8
#define MAX_HTTP_HEADERS 16
#define CT_VAL_SIZE 64

#define IPPROTO_ROUTING 43

static int find_content_type(void* data, void* data_end, char* ct_val) {
    // first line: "HTTP/1.1 200 OK\r\n"
    // subsequent lines: "Header-Name: value\r\n"
    // end of headers: "\r\n"
    const char LINE_BREAK[] = "\r\n";
    const char CT_HEADER[] = "content-type: ";
    const char CT_OFFSET = sizeof(CT_HEADER) - 1;

    u32 start = 0, end = 0, len;
    u16 tot_len = data_end - data;
    char buf[CT_VAL_SIZE], *c;
    u8 buf_idx = 0;

    bpf_repeat(MAX_HTTP_HEADERS) {
        if (start >= tot_len) break;
        end = bpf_strnstr((char*)data + start, LINE_BREAK, tot_len - start);
        if (end <= 0) break;  // end == 0 is for end of headers ("\r\n\r\n")
        end = (end + start) & 0x7fff;

        len = end - start;
        if (len == 0) break;  // empty line indicates end of headers

        bpf_for(buf_idx, 0, len & (CT_VAL_SIZE - 1)) {
            c = (char*)(data + ((start + buf_idx) & 0x7fff));
            if ((void*)(c + 1) > data_end) break;
            buf[buf_idx] = *c;
        }
        buf[(buf_idx + 1) & (CT_VAL_SIZE - 1)] = '\0';

        if (bpf_strncasecmp(buf, CT_HEADER, CT_OFFSET) == 0) {
            __builtin_memcpy(ct_val, buf + CT_OFFSET, CT_VAL_SIZE);
            return 0;
        }

        start = (end + sizeof(LINE_BREAK) - 1) & 0x7fff;
    }

    return -1;
}

static int search_headers(void* data, void* data_end,
                          u16* ip6h_off, u16* srh_off, u16* tcph_off) {
    u8* buf = (u8*)data;
    u8 nexthdr = IPPROTO_IPV6;  // assume starting with IPv6
    u16 offset = 0;

    bpf_repeat(MAX_HDR_DEPTH) {
        offset &= 0xff;

        switch (nexthdr) {
            case IPPROTO_IPIP: {  // IPv4-in-IPv6
                struct iphdr* iph = (struct iphdr*)(buf + offset);
                if ((void*)(iph + 1) > data_end) return -1;
                nexthdr = iph->protocol;
                u32 ihl_bytes = (u32)(iph->ihl) * 4;
                offset += ihl_bytes;
                break;
            }
            case IPPROTO_IPV6: {
                if (*ip6h_off == 0) *ip6h_off = offset;
                struct ipv6hdr* ip6h = (struct ipv6hdr*)(buf + offset);
                if ((void*)(ip6h + 1) > data_end) return -1;
                nexthdr = ip6h->nexthdr;
                offset += sizeof(struct ipv6hdr);
                break;
            }
            case IPPROTO_ROUTING: {
                struct ipv6_rt_hdr* rth = (struct ipv6_rt_hdr*)(buf + offset);
                if ((void*)(rth + 1) > data_end) return -1;
                if (rth->type == 4) *srh_off = offset;
                nexthdr = rth->nexthdr;
                u32 hdr_bytes = (u32)(rth->hdrlen + 1) * 8;
                if ((void*)(buf + offset + hdr_bytes) > data_end) return -1;
                offset += hdr_bytes;
                break;
            }
            case IPPROTO_TCP: {
                *tcph_off = offset;
                if ((void*)(buf + offset + sizeof(struct tcphdr)) > data_end) return -1;
                return 0;
            }
            default:  // unsupported protocol
                return -1;
        }
    }

    return 0;
}

SEC("lwt_xmit")
int bpf_prog(struct __sk_buff* skb) {
    void *data, *data_end;
    u8 segleft_adv = 1;

    bpf_printk("xmit triggered, skb len: %d\n", skb->len);

    data = (void*)(u64)skb->data;
    data_end = (void*)(u64)skb->data_end;

    u16 ip6h_off = 0, srh_off = 0, tcph_off = 0;
    if (search_headers(data, data_end, &ip6h_off, &srh_off, &tcph_off) < 0) {
        bpf_printk("Failed to find TCP header");
        return BPF_OK;
    }

    struct ipv6hdr* ip6h = (struct ipv6hdr*)(data + ip6h_off);
    struct ipv6_sr_hdr* srh = (struct ipv6_sr_hdr*)(data + srh_off);
    if ((void*)(ip6h + 1) > data_end || (void*)(srh + 1) > data_end) {
        bpf_printk("IPv6 or SRH header out of bounds");
        return BPF_OK;
    }

    struct tcphdr* tcph = (struct tcphdr*)(data + tcph_off);
    if ((void*)(tcph + 1) > data_end) {
        bpf_printk("TCP header out of bounds");
        goto reroute;
    }

    bpf_printk(
        "Found IPv6 header\n"
        "    src: %pI6\n"
        "    dst: %pI6\n"
        "Found SRH header\n"
        "    segments_left: %d\n"
        "Found TCP header\n"
        "    src port: %d\n"
        "    dst port: %d",
        (u64)&ip6h->saddr, (u64)&ip6h->daddr,
        srh->segments_left,
        bpf_ntohs(tcph->source), bpf_ntohs(tcph->dest));

    ip6h->hop_limit = 42;  // for easy identification of processed packets

    u16 payload_off;
    payload_off = (u16)((void*)tcph - data) + (u16)(tcph->doff * 4);
    payload_off &= 0x7fff;
    if (payload_off >= skb->len) {
        bpf_printk("No TCP payload. Skipping");
        goto reroute;
    }

    if (bpf_skb_pull_data(skb, skb->len) < 0) {
        bpf_printk("Failed to pull payload bytes");
        goto reroute;
    }

    data = (void*)(u64)skb->data;
    data_end = (void*)(u64)skb->data_end;
    char content_type[CT_VAL_SIZE] = {0};

    if (find_content_type(data + payload_off, data_end, content_type) < 0) {
        bpf_printk("content type header not found");
    } else {
        bpf_printk("Extracted content type: %s", content_type);
    }

reroute:
    data = (void*)(u64)skb->data;
    data_end = (void*)(u64)skb->data_end;
    ip6h = (struct ipv6hdr*)(data + ip6h_off);
    srh = (struct ipv6_sr_hdr*)(data + srh_off);

    if ((void*)(ip6h + 1) > data_end) {
        bpf_printk("IPv6 header out of bounds after skb pull");
        return BPF_OK;
    }
    if ((void*)(srh + 1) > data_end) {
        bpf_printk("SRH header out of bounds after skb pull");
        return BPF_OK;
    }

    srh->segments_left = srh->segments_left > segleft_adv ? srh->segments_left - segleft_adv : 0;
    struct in6_addr* new_dst = srh->segments + srh->segments_left;
    if (data <= (void*)new_dst && (void*)(new_dst + 1) <= data_end) {
        ip6h->daddr = *new_dst;
        bpf_printk("Updated dst: %pI6\n", (u64)&ip6h->daddr);
    }

    return BPF_LWT_REROUTE;
}

char _license[] SEC("license") = "GPL";
