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

#define ETHERNET_MTU  1524

#define ETHERTYPE_IP  0x0800
#define ETHERTYPE_ARP 0x0806

#define ETHERNET_ADDR_LEN 6
#define ETHERNET_HEADER_LEN 14

bool ethernet_validate(const uint8_t *data, size_t len);
uint16_t ethernet_get_ethertype(const uint8_t *data, size_t len);
const uint8_t *ethernet_get_target(const uint8_t *data, size_t len);
const uint8_t *ethernet_get_source(const uint8_t *data, size_t len);
const uint8_t *ethernet_get_payload(const uint8_t *data, size_t len, size_t *payload_len);

size_t ethernet_fill_header(uint8_t *buf, const uint8_t *src, const uint8_t *dst, uint16_t ethertype, size_t len);
