#include <string.h>
#include <ethernet.h>

uint16_t ethernet_get_ethertype(const uint8_t *data, size_t len)
{
    if (len < 14)
        return 0xFFFF;
    return ((uint16_t)data[12]) << 8 | (data[13]);
}

const uint8_t *ethernet_get_target(const uint8_t *data, size_t len)
{
    return data;
}

const uint8_t *ethernet_get_source(const uint8_t *data, size_t len)
{
    return data + 6;
}

const uint8_t *ethernet_get_payload(const uint8_t *data, size_t len, size_t *payload_len)
{
    *payload_len = len - ETHERNET_HEADER_LEN;
    return data + ETHERNET_HEADER_LEN;
}

size_t ethernet_fill_header(uint8_t *buf, const uint8_t *src, const uint8_t *dst, uint16_t ethertype, size_t len)
{
    memmove(buf, dst, 6);
    memmove(buf+6, src, 6);
    buf[12] = ethertype >> 8;
    buf[13] = ethertype & 0xFF;
    return len + ETHERNET_HEADER_LEN;
}

void ethernet_fill_payload(uint8_t *buf, const uint8_t *payload, size_t len)
{
    memmove(buf + 14, payload, len);
}

