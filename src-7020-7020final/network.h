




#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>

void network_init(const char *ip_addr_str, const uint8_t mac_addr[6]);
int network_send_udp(uint32_t dest_ip, uint16_t dest_port, const uint8_t *data, uint16_t len);



void udp_send_data(const uint8_t *data, uint16_t len);

void network_poll(void);

#endif 
