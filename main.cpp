#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_line() {
    printf("-----------------------\n");
}

void print_mac(const u_char* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const u_char* ip) {
    printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(const u_char* port) {
    printf("%u\n", (port[0] << 8) | port[1]);
}

int check_ip(const u_char* type) {
    if (((type[0] << 8) | type[1]) != 0x0800) {
        printf("type: 0x%X%X\n", type[0], type[1]);
        print_line();
        return 1;
    }
    else return 0;
}

int check_tcp(const u_char* protocol) {
    if (protocol[0] != 0x06) {
        printf("protocol: 0x%X\n", protocol[0]);
        print_line();
        return 1;
    }
    else return 0;
}

void check_tcp_data(bpf_u_int32 total_length, int offset, const u_char* payload) {
    if (int(total_length) - offset) {
        printf("data: ");
        for (int i = 0; i < int(total_length) - offset && i < 10; i++) {
            printf("%02X ", payload[i]);
        }
        printf("\n");
    }
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    print_line();
    printf("%u bytes captured\n", header->caplen);
    printf("Dmac: ");
    print_mac(&packet[0]);
    printf("Smac: ");
    print_mac(&packet[6]);
    if (check_ip(&packet[12])) continue;
    printf("Sip: ");
    print_ip(&packet[26]);
    printf("Dip: ");
    print_ip(&packet[30]);
    if (check_tcp(&packet[23])) continue;
    printf("Sport: ");
    print_port(&packet[34]);
    printf("Dport: ");
    print_port(&packet[36]);
    check_tcp_data(header->caplen, 54, &packet[54]);
    print_line();
  }

  pcap_close(handle);
  return 0;
}
