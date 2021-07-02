/*
MIT License

Copyright (c) 2021 Vladislav Tsendrovskii

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

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
