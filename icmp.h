#pragma once

#include <unistd.h>
#include <stdint.h>

struct __attribute__((packed)) icmp_header_s
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum_h : 8;
    uint16_t checksum_l : 8;
};

struct __attribute__((packed)) icmp_echo_s
{
    uint16_t identifier_h : 8;
    uint16_t identifier_l : 8;
    uint16_t sequence_number_h : 8;
    uint16_t sequence_number_l : 8;
};

#define ICMP_HEADER_LEN sizeof(struct icmp_header_s)
#define ICMP_ECHO_LEN sizeof(struct icmp_echo_s)


#define ICMP_TYPE_ECHO 8
#define ICMP_CODE_ECHO 0

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_CODE_ECHO_REPLY 0

uint8_t icmp_get_type(const uint8_t *data, size_t len);
uint8_t icmp_get_code(const uint8_t *data, size_t len);

uint16_t icmp_echo_get_identifier(const uint8_t *data, size_t len);
uint16_t icmp_echo_get_sequence_number(const uint8_t *data, size_t len);
const uint8_t *icmp_echo_get_payload(const uint8_t *data, size_t len, size_t *payload_len);

size_t icmp_fill_echo_payload(uint8_t *buf, const uint8_t *payload, size_t len);
size_t icmp_fill_echo_header(uint8_t *buf, uint16_t identifier, uint16_t sequence_number, size_t payload_len);
size_t icmp_fill_header(uint8_t *buf, uint8_t type, uint8_t code, size_t len);

