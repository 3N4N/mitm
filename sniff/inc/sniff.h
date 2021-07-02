void process_packet(FILE* logfile, unsigned char*, int);
void print_ip_header(FILE* logfile, unsigned char*, int);
void print_tcp_packet(FILE* logfile, unsigned char *, int );
void print_udp_packet(FILE* logfile, unsigned char *, int );
void print_icmp_packet(FILE* logfile, unsigned char*, int );
void print_data(FILE* logfile, unsigned char*, int);
