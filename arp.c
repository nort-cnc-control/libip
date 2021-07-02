#include "arp.h"
#include <string.h>

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

