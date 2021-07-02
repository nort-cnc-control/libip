# libip

This is small and simple event-based UPD/IP library. TCP is not supported and not planned (now, at least).
It implements ONLY network, and you don't need to write any extra code, such as program state, or smth else. Just network events.


You need to implement 2 callback function to use libip:

Handler of incoming UDP packets:
```
void udp_packet_handler(uint32_t remote_ip, uint16_t dport, uint16_t sport, const uint8_t *payload, size_t len);
```

Sender of outcoming ethernet frames:
```
void send_ethernet_frame(const uint8_t *payload, size_t payload_len);
```

Incoming Ethernet frames should be handled with

```
void libip_handle_ethernet(const uint8_t *payload, size_t len);
```

Full list of API functions see in `net.h`

# License

MIT
