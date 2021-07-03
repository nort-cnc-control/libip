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

#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

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

bool ip_validate(const uint8_t *data, size_t len);

uint16_t ip_get_offset(const uint8_t *data, size_t len);
uint16_t ip_get_length(const uint8_t *data, size_t len);
uint32_t ip_get_source(const uint8_t *data, size_t len);
uint32_t ip_get_destination(const uint8_t *data, size_t len);
uint8_t ip_get_protocol(const uint8_t *data, size_t len);
const uint8_t *ip_get_payload(const uint8_t *data, size_t len, size_t *plen);

size_t ip_fill_header(uint8_t *buf, uint32_t source, uint32_t destination, uint8_t protocol, uint8_t TTL, size_t len);

