#pragma once

#include <unistd.h>
#include <stdint.h>

struct __attribute__((packed)) udp_header_s
{
    uint16_t source_h : 8;
    uint16_t source_l : 8;

    uint16_t destination_h : 8;
    uint16_t destination_l : 8;

    uint16_t length_h : 8;
    uint16_t length_l : 8;

    uint16_t checksum_h : 8;
    uint16_t checksum_l : 8;
};

#define UDP_HEADER_LEN sizeof(struct udp_header_s)

uint16_t udp_get_length(const uint8_t *data, size_t len);
uint16_t udp_get_source(const uint8_t *data, size_t len);
uint16_t udp_get_destination(const uint8_t *data, size_t len);
const uint8_t *udp_get_payload(const uint8_t *data, size_t len, size_t *plen);

size_t udp_fill_payload(uint8_t *buf, const uint8_t *data, size_t len);
size_t udp_fill_header(uint8_t *buf, uint16_t source, uint16_t destination, size_t len);

