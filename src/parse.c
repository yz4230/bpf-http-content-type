#include <arpa/inet.h>
#include <linux/ipv6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#define MAX_HDR_DEPTH 8

int search_tcp_hdr(const char *data, size_t len, struct ipv6hdr **ip6h,
                   struct tcphdr **tcph) {
    char *buf = (char *)data;
    struct ipv6hdr *hdr;
    short nexthdr = IPPROTO_IPV6;  // assume starting with IPv6

    for (int depth = 0; depth < MAX_HDR_DEPTH; depth++) {
        switch (nexthdr) {
            case IPPROTO_IPV6: {
                hdr = (struct ipv6hdr *)(buf);
                // if ((void *)(hdr + 1) > data_end) return -1;
                nexthdr = hdr->nexthdr;
                buf += sizeof(struct ipv6hdr);
                break;
            }
            case IPPROTO_ROUTING: {
                struct ipv6_opt_hdr *opth = (struct ipv6_opt_hdr *)(buf);
                // if ((void *)(opth + 1) > data_end) return -1;
                nexthdr = opth->nexthdr;
                buf += (opth->hdrlen + 1) * 8;
                break;
            }
            case IPPROTO_TCP: {
                *ip6h = hdr;
                *tcph = (struct tcphdr *)(buf);
                return 0;
            }
            default:
                break;
        }
    }

    return -1;
}

#define pktbin "packet.bin.local"

int main(const int argc, const char **argv) {
    FILE *f = fopen(pktbin, "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    char buf[1024];
    size_t size = fread(buf, 1, sizeof(buf), f);
    if (size == 0 && ferror(f)) {
        perror("fread");
        fclose(f);
        return 1;
    }
    fclose(f);

    printf("Read %zu bytes from %s\n", size, pktbin);

    struct ipv6hdr *ip6h = NULL;
    struct tcphdr *tcph = NULL;
    if (search_tcp_hdr(buf, size, &ip6h, &tcph) < 0) {
        printf("TCP header not found\n");
        return 1;
    }

    if (!ip6h) {
        printf("IPv6 header not found\n");
        return 1;
    }

    if (!tcph) {
        printf("TCP header not found\n");
        return 1;
    }

    char src_ip[INET6_ADDRSTRLEN];
    char dest_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6h->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET6, &ip6h->daddr, dest_ip, sizeof(dest_ip));
    printf("IPv6 Header:\n");
    printf("    Source IP: %s\n", src_ip);
    printf("    Destination IP: %s\n", dest_ip);
    printf("TCP header:\n");
    printf("    Source Port: %u\n", ntohs(tcph->source));
    printf("    Destination Port: %u\n", ntohs(tcph->dest));

    char *data = (char *)tcph + (tcph->doff * 4);
    size_t data_len = size - (data - buf);  // total size - headers size
    // scan headers for Content-Type
    static const char *content_type_str = "Content-Type:";
    int content_type_str_len = strlen(content_type_str);

    static const int max_headers = 16;
    for (int i = 0; i < max_headers; i++) {
        char *line_end = memchr(data, '\n', data_len);
        if (!line_end) break;

        size_t line_len = line_end - data + 1;  // include '\n'
        if (line_len >= content_type_str_len &&
            strncasecmp(data, content_type_str, content_type_str_len) == 0) {
            // Found Content-Type header
            printf("Found Content-Type header: ");
            fwrite(data, 1, line_len, stdout);
            break;
        }

        data += line_len;
        data_len -= line_len;
    }

    return 0;
}
