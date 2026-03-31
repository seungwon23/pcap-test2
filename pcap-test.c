#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#define ETHERTYPE_IP 0x0800

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

// Ethernet Header
struct ethernet_hdr {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};

// IPv4 Header
struct ipv4_hdr {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t ip_off;
    uint8_t ttl;
    uint8_t protocol; 
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
};

// TCP Header
struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

void print_mac(const uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i < 5) printf(":");
    }
    printf("\n");
}

void print_ip(const uint8_t* ip) {
    for (int i = 0; i < 4; i++) {
        printf("%d", ip[i]);
        if (i < 3) printf(".");
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct ethernet_hdr* eth = (struct ethernet_hdr*)packet;
        if (ntohs(eth->type) != ETHERTYPE_IP) continue;

        struct ipv4_hdr* ip = (struct ipv4_hdr*)(packet + sizeof(struct ethernet_hdr));
        int ip_hdr_len = (ip->ver_ihl & 0x0F) * 4;
        if (ip->protocol != 0x06) continue;

        struct tcp_hdr* tcp = (struct tcp_hdr*)(packet + sizeof(struct ethernet_hdr) + ip_hdr_len);
        int tcp_hdr_len = ((tcp->offset_reserved & 0xF0) >> 4) * 4;

        const u_char* payload = packet + sizeof(struct ethernet_hdr) + ip_hdr_len + tcp_hdr_len;
        int payload_len = ntohs(ip->total_len) - ip_hdr_len - tcp_hdr_len;
        if (payload_len < 0)
            payload_len = 0;

	int max_len;
        if(payload_len > 20)
            max_len = 20;
        else
            max_len = payload_len;

        printf("\n=== TCP Packet Captured ===\n");

        printf("Dst MAC: ");
        print_mac(eth->dst_mac);
        printf("Src MAC: ");
        print_mac(eth->src_mac);

        printf("Src IP: ");
        print_ip(ip->src_ip);
        printf("Dst IP: ");
        print_ip(ip->dst_ip);

        printf("Src Port: %u\n", ntohs(tcp->src_port));
        printf("Dst Port: %u\n", ntohs(tcp->dst_port));

        printf("Payload (%d bytes): ", payload_len);
        for (int i = 0; i < max_len; i++) {
            printf("%02x ", payload[i]);
        }
        printf("\n");
    }

    pcap_close(pcap);
    return 0;
}
