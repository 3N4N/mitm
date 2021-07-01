#ifndef _PACKETS_H_
# define _PACKETS_H_

# include <stdint.h>
# define ETH_HEADER_LENGTH 14
# define ARP_HEADER_LENGTH 28
# define HARDWARE_LENGTH 6
# define IP_LENGTH 4

// Inspired by the <net/ethernet.h> header
typedef struct
{
    uint8_t target_mac[HARDWARE_LENGTH];
    uint8_t sender_mac[HARDWARE_LENGTH];
    uint16_t eth_type;
} eth_packet;

typedef struct
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;
    uint8_t sender_mac[HARDWARE_LENGTH];
    uint8_t sender_ip[IP_LENGTH];
    uint8_t target_mac[HARDWARE_LENGTH];
    uint8_t target_ip[IP_LENGTH];
} arp_packet;

arp_packet *create_arp_packet(const uint16_t opcode,
                                const uint8_t *my_mac_address,
                                const char *spoofed_ip_source,
                                const uint8_t *destination_mac_address,
                                const char *destination_ip);
eth_packet *create_eth_packet(const uint8_t *src_mac,
                                          const uint8_t *dest_mac,
                                          const arp_packet *arp_packet);

#endif /* _PACKETS_H_ */
