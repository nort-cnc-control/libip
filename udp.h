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

