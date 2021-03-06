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

#include "arp.h"
#include <string.h>

bool arp_validate(const uint8_t *data, size_t len)
{
    if (len < ARP_HEADER_LEN)
        return false;
    const struct arp_header_s *hdr = (const struct arp_header_s *)data;
    if (len < ARP_HEADER_LEN + 2*hdr->hardware_len + 2*hdr->protocol_len)
        return false;
    return true;
}

uint16_t arp_get_hardware(const uint8_t *data, size_t len)
{
    const struct arp_header_s *hdr = (const struct arp_header_s *)data;
    return hdr->htype_h << 8 | hdr->htype_l;
}

uint16_t arp_get_protocol(const uint8_t *data, size_t len)
{
    const struct arp_header_s *hdr = (const struct arp_header_s *)data;
    return hdr->ptype_h << 8 | hdr->ptype_l;
}

const uint8_t *arp_get_sender_hardware(const uint8_t *data, size_t len, size_t *hlen)
{
    const struct arp_header_s *hdr = (const struct arp_header_s *)data;
    *hlen = hdr->hardware_len;
    const uint8_t *shw = data + ARP_HEADER_LEN;
    return shw;
}

const uint8_t *arp_get_sender_protocol(const uint8_t *data, size_t len, size_t *plen)
{
    const struct arp_header_s *hdr = (const struct arp_header_s *)data;
    size_t hlen = hdr->hardware_len;
    *plen = hdr->protocol_len;
    const uint8_t *sp = data + ARP_HEADER_LEN + hlen;
    return sp;
}

const uint8_t *arp_get_target_hardware(const uint8_t *data, size_t len, size_t *hlen)
{
    const struct arp_header_s *hdr = (const struct arp_header_s *)data;
    *hlen = hdr->hardware_len;
    size_t plen = hdr->protocol_len;
    const uint8_t *shw = data + ARP_HEADER_LEN + *hlen + plen;
    return shw;
}

const uint8_t *arp_get_target_protocol(const uint8_t *data, size_t len, size_t *plen)
{
    const struct arp_header_s *hdr = (const struct arp_header_s *)data;
    size_t hlen = hdr->hardware_len;
    *plen = hdr->protocol_len;
    const uint8_t *sp = data + ARP_HEADER_LEN + hlen + *plen + hlen;
    return sp;
}

uint16_t arp_get_operation(const uint8_t *data, size_t len)
{
    const struct arp_header_s *hdr = (const struct arp_header_s *)data;
    return hdr->oper_h << 8 | hdr->oper_l;
}

size_t arp_fill_header(uint8_t *buf, uint16_t htype, uint8_t hlen, uint16_t ptype, uint8_t plen, uint16_t oper)
{
    struct arp_header_s *hdr = (struct arp_header_s *)buf;
    hdr->htype_h = htype >> 8;
    hdr->htype_l = htype & 0xFF;
    hdr->ptype_h = ptype >> 8;
    hdr->ptype_l = ptype & 0xFF;
    hdr->hardware_len = hlen;
    hdr->protocol_len = plen;
    hdr->oper_h = oper >> 8;
    hdr->oper_l = oper & 0xFF;
    return ARP_HEADER_LEN + hlen*2 + plen*2;
}

void arp_set_sender_hardware(uint8_t *buf, const uint8_t *hw, size_t hlen, size_t plen)
{
    memcpy(buf + ARP_HEADER_LEN, hw, hlen);
}

void arp_set_sender_protocol(uint8_t *buf, const uint8_t *p, size_t hlen, size_t plen)
{
    memcpy(buf + ARP_HEADER_LEN + hlen, p, plen);
}

void arp_set_target_hardware(uint8_t *buf, const uint8_t *hw, size_t hlen, size_t plen)
{
    memcpy(buf + ARP_HEADER_LEN + hlen + plen, hw, hlen);
}

void arp_set_target_protocol(uint8_t *buf, const uint8_t *p, size_t hlen, size_t plen)
{
    memcpy(buf + ARP_HEADER_LEN + hlen + plen + hlen, p, plen);
}

