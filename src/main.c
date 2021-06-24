#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "errmsg.h"


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

int main(int argc, char *argv[])
{
    // if (argc != 4) {
    //     fprintf(stderr, ERROR_DISPLAY_USAGE, argv[0]);
    //     exit(EXIT_FAILURE);
    // }

    char *victim_ip, *spoofed_ip_source, *interface;
    unsigned char *atk_mac = NULL;
    unsigned char *victim_mac_address = NULL;
    int sock;


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
        return (fprintf(stderr, ERROR_SOCKET_CREATION), EXIT_FAILURE);
    }

    if (!(atk_mac = get_my_mac_address(sock, interface))) {
        return (fprintf(stderr, ERROR_GET_MAC), EXIT_FAILURE);
    }

    printf("Attacker MAC : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
           atk_mac[0], atk_mac[1], atk_mac[2],
           atk_mac[3], atk_mac[4], atk_mac[5]);


    if (atk_mac != NULL) free(atk_mac);
    close(sock);


    return 0;
}
