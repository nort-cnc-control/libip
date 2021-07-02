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

#include "ip.h"


uint16_t ip_get_length(const uint8_t *data, size_t len)
{
    const struct ip_header_s *hdr = (const struct ip_header_s *)data;
    return hdr->length_h << 8 | hdr->length_l;
}

uint32_t ip_get_source(const uint8_t *data, size_t len)
{
    const struct ip_header_s *hdr = (const struct ip_header_s *)data;
    return ((uint32_t)hdr->source[0]) << 24 | ((uint32_t)hdr->source[1]) << 16 | ((uint32_t)hdr->source[2]) << 8 | ((uint32_t)hdr->source[3]);
}

uint32_t ip_get_destination(const uint8_t *data, size_t len)
{
    const struct ip_header_s *hdr = (const struct ip_header_s *)data;
    return ((uint32_t)hdr->destination[0]) << 24 | ((uint32_t)hdr->destination[1]) << 16 | ((uint32_t)hdr->destination[2]) << 8 | ((uint32_t)hdr->destination[3]);
}

uint8_t ip_get_protocol(const uint8_t *data, size_t len)
{
    const struct ip_header_s *hdr = (const struct ip_header_s *)data;
    return hdr->protocol;
}

const uint8_t *ip_get_payload(const uint8_t *data, size_t len, size_t *plen)
{
    const struct ip_header_s *hdr = (const struct ip_header_s *)data;
    *plen = (hdr->length_h << 8) | (hdr->length_l) - IP_HEADER_LEN;
    return data + IP_HEADER_LEN;
}

static uint16_t checksum(const uint8_t *buf, size_t len)
{
    uint32_t sum = 0xFFFF;
    
    while (len > 1)
    {
        uint16_t word = (uint16_t)(*buf) << 8 | *(buf+1);
        sum += word;
        buf += 2;
        len -= 2;
    }
    if (len == 1)
    {
        sum += *buf;
    }

    sum =  (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

size_t ip_fill_header(uint8_t *buf, uint32_t source, uint32_t destination, uint8_t protocol, uint8_t TTL, size_t len)
{
    struct ip_header_s *hdr = (struct ip_header_s *)buf;

    hdr->source[0] = source >> 24;
    hdr->source[1] = source >> 16;
    hdr->source[2] = source >> 8;
    hdr->source[3] = source;

    hdr->destination[0] = destination >> 24;
    hdr->destination[1] = destination >> 16;
    hdr->destination[2] = destination >> 8;
    hdr->destination[3] = destination;

    hdr->TTL = TTL;
    hdr->protocol = protocol;

    hdr->flags_res = 0;
    hdr->flags_df = 1;
    hdr->flags_mf = 0;
    hdr->id_h = 0;
    hdr->id_l = 0;
    hdr->ToS = 0;
    hdr->IHL = 5;
    hdr->version = 4;

    hdr->length_h = (len + IP_HEADER_LEN) >> 8;
    hdr->length_l = (len + IP_HEADER_LEN) & 0XFF;

    hdr->hchecksum_h = 0;
    hdr->hchecksum_l = 0;
    uint16_t chs = checksum(buf, IP_HEADER_LEN);
    hdr->hchecksum_h = chs >> 8;
    hdr->hchecksum_l = chs;

	hdr->offset_h = 0;
	hdr->offset_l = 0;
    return len + IP_HEADER_LEN;
}

