#pragma once

#include <unistd.h>
#include <stdint.h>

struct __attribute__((packed)) arp_header_s
{
    uint16_t htype_h : 8;
    uint16_t htype_l : 8;

    uint16_t ptype_h : 8;
    uint16_t ptype_l : 8;

    uint8_t  hardware_len;
    uint8_t  protocol_len;

    uint16_t oper_h : 8;
    uint16_t oper_l : 8;
};

#define ARP_HEADER_LEN sizeof(struct arp_header_s)

#define ARP_HTYPE_ETHERNET 0x0001

#define ARP_OPERATION_REQUEST 1
#define ARP_OPERATION_RESPONSE 2


uint16_t arp_get_hardware(const uint8_t *data, size_t len);
uint16_t arp_get_protocol(const uint8_t *data, size_t len);

const uint8_t *arp_get_sender_hardware(const uint8_t *data, size_t len, size_t *hlen);
const uint8_t *arp_get_sender_protocol(const uint8_t *data, size_t len, size_t *plen);

const uint8_t *arp_get_target_hardware(const uint8_t *data, size_t len, size_t *hlen);
const uint8_t *arp_get_target_protocol(const uint8_t *data, size_t len, size_t *plen);

uint16_t arp_get_operation(const uint8_t *data, size_t len);

size_t arp_fill_header(uint8_t *buf, uint16_t htype, uint8_t hlen, uint16_t ptype, uint8_t plen, uint16_t oper);

void arp_set_sender_hardware(uint8_t *buf, const uint8_t *hw, size_t hlen, size_t plen);
void arp_set_sender_protocol(uint8_t *buf, const uint8_t *p, size_t hlen, size_t plen);
void arp_set_target_hardware(uint8_t *buf, const uint8_t *hw, size_t hlen, size_t plen);
void arp_set_target_protocol(uint8_t *buf, const uint8_t *p, size_t hlen, size_t plen);

