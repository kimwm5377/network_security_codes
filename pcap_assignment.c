#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "myheader.h"

#define DEVICE "ens33"      // VMware Ubuntu network interface name
#define ETHERNET_LEN 14      // Ethernet header size is normally 14 bytes

void print_mac(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_payload_as_text(const u_char *payload, int payload_len) {
    int i;

    for (i = 0; i < payload_len; i++) {
        // Print readable characters as-is. Keep common line breaks/tabs.
        if (isprint(payload[i]) || payload[i] == '\n' || payload[i] == '\r' || payload[i] == '\t') {
            putchar(payload[i]);
        } else {
            putchar('.');
        }
    }

    if (payload_len > 0 && payload[payload_len - 1] != '\n') {
        putchar('\n');
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;  // Unused parameter

    // 1. Ethernet header starts at the beginning of the packet.
    if (header->caplen < ETHERNET_LEN) {
        return;
    }

    struct ethheader *eth = (struct ethheader *)packet;

    // Only IPv4 packets use Ethernet type 0x0800.
    if (ntohs(eth->ether_type) != 0x0800) {
        return;
    }

    printf("\n================ TCP Packet ================\n");

    printf("[Ethernet Header]\n");
    printf("  Src MAC : ");
    print_mac(eth->ether_shost);
    printf("\n");
    printf("  Dst MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n");

    // 2. IP header starts right after Ethernet header.
    if (header->caplen < ETHERNET_LEN + sizeof(struct ipheader)) {
        printf("  Packet is too short for IP header.\n");
        return;
    }

    struct ipheader *ip = (struct ipheader *)(packet + ETHERNET_LEN);

    // IP header length is stored in 4-byte words, so multiply by 4.
    int ip_header_len = ip->iph_ihl * 4;

    if (ip_header_len < 20) {
        printf("  Invalid IP header length: %d\n", ip_header_len);
        return;
    }

    if (header->caplen < ETHERNET_LEN + ip_header_len) {
        printf("  Captured packet is shorter than IP header length.\n");
        return;
    }

    // This assignment ignores UDP and analyzes TCP only.
    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    printf("[IP Header]\n");
    printf("  Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("  Dst IP  : %s\n", inet_ntoa(ip->iph_destip));
    printf("  IP Header Length : %d bytes\n", ip_header_len);

    // 3. TCP header starts after Ethernet header + actual IP header length.
    if (header->caplen < ETHERNET_LEN + ip_header_len + sizeof(struct tcpheader)) {
        printf("  Packet is too short for TCP header.\n");
        return;
    }

    struct tcpheader *tcp = (struct tcpheader *)(packet + ETHERNET_LEN + ip_header_len);

    // TCP header length is also stored in 4-byte words.
    int tcp_header_len = TH_OFF(tcp) * 4;

    if (tcp_header_len < 20) {
        printf("  Invalid TCP header length: %d\n", tcp_header_len);
        return;
    }

    if (header->caplen < ETHERNET_LEN + ip_header_len + tcp_header_len) {
        printf("  Captured packet is shorter than TCP header length.\n");
        return;
    }

    printf("[TCP Header]\n");
    printf("  Src Port : %u\n", ntohs(tcp->tcp_sport));
    printf("  Dst Port : %u\n", ntohs(tcp->tcp_dport));
    printf("  TCP Header Length : %d bytes\n", tcp_header_len);

    // 4. TCP payload starts after Ethernet + IP header + TCP header.
    int ip_total_len = ntohs(ip->iph_len);
    int payload_len = ip_total_len - ip_header_len - tcp_header_len;

    if (payload_len <= 0) {
        printf("[HTTP Message]\n");
        printf("  No application data in this TCP packet.\n");
        return;
    }

    const u_char *payload = packet + ETHERNET_LEN + ip_header_len + tcp_header_len;

    // Prevent reading beyond the captured packet length.
    int captured_payload_len = header->caplen - (ETHERNET_LEN + ip_header_len + tcp_header_len);
    if (payload_len > captured_payload_len) {
        payload_len = captured_payload_len;
    }

    printf("[HTTP Message / TCP Payload]\n");

    // HTTP normally uses port 80. HTTPS uses port 443, so the content is encrypted.
    if (ntohs(tcp->tcp_sport) == 80 || ntohs(tcp->tcp_dport) == 80) {
        print_payload_as_text(payload, payload_len);
    } else {
        printf("  This TCP payload is not port 80 HTTP data. Payload length: %d bytes\n", payload_len);
    }
}

int main(void) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;

    // TCP only. UDP packets are ignored by this filter.
    char filter_exp[] = "tcp";

    if (pcap_lookupnet(DEVICE, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = PCAP_NETMASK_UNKNOWN;
    }

    handle = pcap_open_live(DEVICE, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", DEVICE, errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, mask) == -1) {
        fprintf(stderr, "Could not compile filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not set filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }

    printf("Listening on %s... Press Ctrl+C to stop.\n", DEVICE);
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}

