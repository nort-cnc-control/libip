#include <string.h>
#include "udp.h"

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

