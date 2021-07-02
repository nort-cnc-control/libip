#pragma once

#include <unistd.h>
#include <stdint.h>

struct __attribute__((packed)) ip_header_s
{
    uint8_t IHL       : 4;
    uint8_t version   : 4;
    uint8_t ToS;

    uint16_t length_h : 8;
    uint16_t length_l : 8;

    uint16_t id_h     : 8;
    uint16_t id_l     : 8;


    uint16_t offset_h : 5;

    uint8_t flags_mf  : 1;
    uint8_t flags_df  : 1;
    uint8_t flags_res : 1;

    uint16_t offset_l : 8;

    uint8_t TTL;
    uint8_t protocol;

    uint16_t hchecksum_h : 8;
    uint16_t hchecksum_l : 8;

    uint8_t source[4];
    uint8_t destination[4];
};

#define IP_HEADER_LEN sizeof(struct ip_header_s)

#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_UDP 17

uint16_t ip_get_length(const uint8_t *data, size_t len);
uint32_t ip_get_source(const uint8_t *data, size_t len);
uint32_t ip_get_destination(const uint8_t *data, size_t len);
uint8_t ip_get_protocol(const uint8_t *data, size_t len);
const uint8_t *ip_get_payload(const uint8_t *data, size_t len, size_t *plen);

size_t ip_fill_header(uint8_t *buf, uint32_t source, uint32_t destination, uint8_t protocol, uint8_t TTL, size_t len);

