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

#include <string.h>
#include "udp.h"

bool udp_validate(const uint8_t *data, size_t len)
{
    if (len < UDP_HEADER_LEN)
        return false;
    uint16_t total_len = udp_get_length(data, len);
    if (total_len < UDP_HEADER_LEN)
        return false;
    if (len < total_len)
        return false;
    return true;
}

uint16_t udp_get_length(const uint8_t *data, size_t len)
{
    const struct udp_header_s *hdr = (const struct udp_header_s *)data;
    return hdr->length_h << 8 | hdr->length_l;
}

uint16_t udp_get_source(const uint8_t *data, size_t len)
{
    const struct udp_header_s *hdr = (const struct udp_header_s *)data;
    return (hdr->source_h << 8) | (hdr->source_l);
}

uint16_t udp_get_destination(const uint8_t *data, size_t len)
{
    const struct udp_header_s *hdr = (const struct udp_header_s *)data;
    return (hdr->destination_h << 8) | (hdr->destination_l);
}

const uint8_t *udp_get_payload(const uint8_t *data, size_t len, size_t *plen)
{
    const struct udp_header_s *hdr = (const struct udp_header_s *)data;
    *plen = (hdr->length_h << 8) | (hdr->length_l) - UDP_HEADER_LEN;
    return data + UDP_HEADER_LEN;
}

size_t udp_fill_payload(uint8_t *buf, const uint8_t *data, size_t len)
{
    memcpy(buf + UDP_HEADER_LEN, data, len);
    return len;
}

size_t udp_fill_header(uint8_t *buf, uint16_t source, uint16_t destination, size_t len)
{
    struct udp_header_s *hdr = (struct udp_header_s *)buf;

    hdr->source_h = source >> 8;
    hdr->source_l = source & 0XFF;

    hdr->destination_h = destination >> 8;
    hdr->destination_l = destination & 0XFF;

    hdr->length_h = (len + UDP_HEADER_LEN) >> 8;
    hdr->length_l = (len + UDP_HEADER_LEN) & 0XFF;

    return len + UDP_HEADER_LEN;
}

