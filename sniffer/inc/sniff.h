#ifndef _SNIFF_H_
#define _SNIFF_H_

void process_packet(FILE* logfile, unsigned char*, int);
void print_ip_header(FILE* logfile, unsigned char*, int);
void print_tcp_packet(FILE* logfile, unsigned char *, int);
void print_icmp_packet(FILE* logfile, unsigned char* Buffer, int Size);
void print_data(FILE* logfile, unsigned char*, int);

void relay_icmp_packet(int sockid, unsigned char* buffer, int size);
void relay_tcp_packet(int sockid, unsigned char* buffer, int size);

#endif // _SNIFF_H_
