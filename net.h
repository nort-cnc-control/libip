#pragma once

#include <stdint.h>
#include <unistd.h>

void udp_packet_handler(uint32_t remote_ip, uint16_t dport, uint16_t sport, const uint8_t *payload, size_t len);
void send_ethernet_frame(const uint8_t *payload, size_t payload_len);

void libip_handle_ethernet(const uint8_t *payload, size_t len);
void libip_init(uint32_t ip, const uint8_t mac[6]);

void libip_send_udp_packet(const uint8_t *payload, size_t payload_len, uint32_t remote_ip, uint16_t local_port, uint16_t remote_port);
void libip_send_icmp_echo_reply(const uint8_t *payload, size_t len, const uint32_t remote_ip, uint16_t id, uint16_t seq);
void libip_send_arp_response(const uint32_t remote_ip, const uint8_t remote_mac[6]);
