#ifndef _SNIFF_H_
#define _SNIFF_H_

void sniff_and_relay(FILE* logfile, int sockid, unsigned char* buffer, int size,
                     char* victim_ip_1, unsigned char* victim_mac_1,
                     char* victim_ip_2, unsigned char* victim_mac_2,
                     unsigned char* hacker_mac, char* interface);

void print_ip_header(FILE* logfile, unsigned char*, int);
void print_tcp_packet(FILE* logfile, unsigned char *, int);
void print_icmp_packet(FILE* logfile, unsigned char* Buffer, int Size);
void print_data(FILE* logfile, unsigned char*, int);

void relay_icmp_packet(int sockid, unsigned char* buffer, int size,
                       char* victim_ip_1, unsigned char* victim_mac_1,
                       char* victim_ip_2, unsigned char* victim_mac_2,
                       unsigned char* hacker_mac, char* interface);
void relay_tcp_packet(int sockid, unsigned char* buffer, int size,
                      char* victim_ip_1, unsigned char* victim_mac_1,
                      char* victim_ip_2, unsigned char* victim_mac_2,
                      unsigned char* hacker_mac, char* interface);

#endif // _SNIFF_H_
