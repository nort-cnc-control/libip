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

#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include <net.h>

#include <ethernet.h>
#include <icmp.h>
#include <udp.h>
#include <ip.h>
#include <arp.h>

static uint8_t local_mac[6];
static uint32_t local_ip;

static struct packet_state_s
{
	uint8_t remote_mac[6];
	uint32_t remote_ip;
} packet_state;

static uint8_t send_buffer[ETHERNET_MTU];

#define ARP_RECORDS 10
static struct apr_record
{
	int8_t ttl;
	uint8_t mac[6];
	uint32_t ip;
} arp_table[ARP_RECORDS];
static const uint8_t mac_bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

typedef const uint8_t *mac_ptr;

static void find_mac(const uint32_t ip, mac_ptr *mac)
{
	int i;
	*mac = mac_bcast;
	for (i = 0; i < ARP_RECORDS; i++)
	{
		if (ip == arp_table[i].ip)
		{
			*mac = arp_table[i].mac;
			arp_table[i].ttl = 0;
			break;
		}
	}
}

static void remember_mac(const uint32_t ip, const uint8_t mac[6])
{
	int i;
	int maxttl;
	int maxi;
	for (i = 0; i < ARP_RECORDS; i++)
		arp_table[i].ttl++;
	for (i = 0; i < ARP_RECORDS; i++)
	{
		if (arp_table[i].ip == 0)
		{
			arp_table[i].ip = ip;
			arp_table[i].mac[0] = mac[0];
			arp_table[i].mac[1] = mac[1];
			arp_table[i].mac[2] = mac[2];
			arp_table[i].mac[3] = mac[3];
			arp_table[i].mac[4] = mac[4];
			arp_table[i].mac[5] = mac[5];
			arp_table[i].ttl = 0;
			return;
		}
	}

	maxttl = 0;
	maxi = 0;
	for (i = 0; i < ARP_RECORDS; i++)
	{
		if (arp_table[i].ttl > maxttl)
		{
			maxi = i;
			maxttl = arp_table[i].ttl;
		}
	}

	arp_table[maxi].ip = ip;
	arp_table[maxi].mac[0] = mac[0];
	arp_table[maxi].mac[1] = mac[1];
	arp_table[maxi].mac[2] = mac[2];
	arp_table[maxi].mac[3] = mac[3];
	arp_table[maxi].mac[4] = mac[4];
	arp_table[maxi].mac[5] = mac[5];
	arp_table[maxi].ttl = 0;
}

/* Sending outcoming packets */

void libip_send_udp_packet(const uint8_t *payload, size_t payload_len, uint32_t remote_ip, uint16_t local_port, uint16_t remote_port)
{
	memset(send_buffer, 0, sizeof(send_buffer));
	uint8_t *buffer = send_buffer;
	mac_ptr remote_mac;
	find_mac(remote_ip, &remote_mac);

	size_t udp_payload_len = udp_fill_payload(buffer + ETHERNET_HEADER_LEN + IP_HEADER_LEN, payload, payload_len);
	size_t udp_len = udp_fill_header(buffer + ETHERNET_HEADER_LEN + IP_HEADER_LEN, local_port, remote_port, udp_payload_len);
	size_t ip_len = ip_fill_header(buffer + ETHERNET_HEADER_LEN, local_ip, remote_ip, IP_PROTOCOL_UDP, 30, udp_len);
	size_t eth_len = ethernet_fill_header(buffer, local_mac, remote_mac, ETHERTYPE_IP, ip_len);
	send_ethernet_frame(buffer, eth_len);
}

void libip_send_icmp_echo_reply(const uint8_t *payload, size_t len, const uint32_t remote_ip, uint16_t id, uint16_t seq)
{
	memset(send_buffer, 0, sizeof(send_buffer));
	uint8_t *buffer = send_buffer;
	mac_ptr remote_mac;
	find_mac(remote_ip, &remote_mac);

	size_t payload_len = icmp_fill_echo_payload(buffer + ETHERNET_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN, payload, len);
	size_t echo_len = icmp_fill_echo_header(buffer + ETHERNET_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN, id, seq, payload_len);
	size_t icmp_len = icmp_fill_header(buffer + ETHERNET_HEADER_LEN + IP_HEADER_LEN, ICMP_TYPE_ECHO_REPLY, 0, echo_len);
	size_t ip_len = ip_fill_header(buffer + ETHERNET_HEADER_LEN, local_ip, remote_ip, IP_PROTOCOL_ICMP, 30, icmp_len);
	size_t eth_len = ethernet_fill_header(buffer, local_mac, remote_mac, ETHERTYPE_IP, ip_len);
	send_ethernet_frame(send_buffer, eth_len);
}

void libip_send_arp_response(const uint32_t remote_ip, const uint8_t remote_mac[6])
{
	memset(send_buffer, 0, sizeof(send_buffer));
	uint8_t remote_ip_buf[4] = {(uint8_t)(remote_ip >> 24), (uint8_t)(remote_ip >> 16), (uint8_t)(remote_ip >> 8), (uint8_t)(remote_ip)};
	uint8_t local_ip_buf[4] = {(uint8_t)(local_ip >> 24), (uint8_t)(local_ip >> 16), (uint8_t)(local_ip >> 8), (uint8_t)(local_ip)};

	uint8_t *buffer = send_buffer;
	arp_set_sender_hardware(buffer + ETHERNET_HEADER_LEN, local_mac, 6, 4);
	arp_set_sender_protocol(buffer + ETHERNET_HEADER_LEN, local_ip_buf, 6, 4);

	arp_set_target_hardware(buffer + ETHERNET_HEADER_LEN, remote_mac, 6, 4);
	arp_set_target_protocol(buffer + ETHERNET_HEADER_LEN, remote_ip_buf, 6, 4);

	size_t arp_len = arp_fill_header(buffer + ETHERNET_HEADER_LEN, ARP_HTYPE_ETHERNET, 6, ETHERTYPE_IP, 4, ARP_OPERATION_RESPONSE);
	size_t eth_len = ethernet_fill_header(buffer, local_mac, remote_mac, ETHERTYPE_ARP, arp_len);

	send_ethernet_frame(send_buffer, eth_len);
}

/* Handle incoming packets */

static void handle_udp(const uint8_t *payload, size_t len)
{
	uint16_t sport = udp_get_source(payload, len);
	uint16_t dport = udp_get_destination(payload, len);
	size_t udp_payload_len;
	const uint8_t *udp_payload = udp_get_payload(payload, len, &udp_payload_len);

	udp_packet_handler(packet_state.remote_ip, dport, sport, udp_payload, udp_payload_len);
}

static void handle_icmp(const uint8_t *payload, size_t len)
{
	uint8_t type = icmp_get_type(payload, len);
	uint8_t code = icmp_get_code(payload, len);
	switch (type)
	{
	case ICMP_TYPE_ECHO:
	{
		uint16_t id = icmp_echo_get_identifier(payload, len);
		uint16_t sn = icmp_echo_get_sequence_number(payload, len);
		size_t icmp_payload_len;
		const uint8_t *icmp_payload = icmp_echo_get_payload(payload, len, &icmp_payload_len);

		/* Send ICMP ECHO REPLY response */
		libip_send_icmp_echo_reply(icmp_payload, icmp_payload_len, packet_state.remote_ip, id, sn);
		break;
	}
	default:
		break;
	}
}

static void handle_ip(const uint8_t *payload, size_t len)
{
	uint8_t protocol = ip_get_protocol(payload, len);
	packet_state.remote_ip = ip_get_source(payload, len);
	remember_mac(packet_state.remote_ip, packet_state.remote_mac);

	size_t ip_payload_len;
	const uint8_t *ip_payload = ip_get_payload(payload, len, &ip_payload_len);
	switch (protocol)
	{
	case IP_PROTOCOL_UDP:
	{
		handle_udp(ip_payload, ip_payload_len);
		break;
	}
	case IP_PROTOCOL_ICMP:
	{
		handle_icmp(ip_payload, ip_payload_len);
		return;
	}
	default:
		break;
	}
}

static void handle_arp(const uint8_t *payload, size_t len)
{
	uint16_t hw = arp_get_hardware(payload, len);
	uint16_t proto = arp_get_protocol(payload, len);

	if (hw != ARP_HTYPE_ETHERNET || proto != ETHERTYPE_IP)
		return;

	size_t hwlen;
	size_t plen;

	uint8_t sender_hw[6];
	memcpy(sender_hw, arp_get_sender_hardware(payload, len, &hwlen), sizeof(sender_hw));

	uint8_t sender_p[4];
	memcpy(sender_p, arp_get_sender_protocol(payload, len, &plen), sizeof(sender_p));

	const uint8_t *target_hw = arp_get_target_hardware(payload, len, &hwlen);
	const uint8_t *target_p = arp_get_target_protocol(payload, len, &plen);

	uint32_t sender_ip = (uint32_t)sender_p[0] << 24 | (uint32_t)sender_p[1] << 16 | (uint32_t)sender_p[2] << 8 | (uint32_t)sender_p[3];
	uint32_t target_ip = (uint32_t)target_p[0] << 24 | (uint32_t)target_p[1] << 16 | (uint32_t)target_p[2] << 8 | (uint32_t)target_p[3];

	uint16_t op = arp_get_operation(payload, len);

	switch (op)
	{
	case ARP_OPERATION_REQUEST:
	{
		if (target_ip == local_ip)
		{
			uint8_t *buffer = send_buffer;
			uint8_t rshw[6], rsp[4];

			/* Send ARP response */
			libip_send_arp_response(sender_ip, sender_hw);
		}
		break;
	}
	case ARP_OPERATION_RESPONSE:
	{
		break;
	}
	default:
		break;
	}
}

void libip_handle_ethernet(const uint8_t *payload, size_t len)
{
	uint16_t ethertype = ethernet_get_ethertype(payload, len);

	memcpy(packet_state.remote_mac, ethernet_get_source(payload, len), 6);

	size_t ethernet_payload_len;
	const uint8_t *ethernet_payload = ethernet_get_payload(payload, len, &ethernet_payload_len);
	switch (ethertype)
	{
	case ETHERTYPE_IP:
		handle_ip(ethernet_payload, ethernet_payload_len);
		break;
	case ETHERTYPE_ARP:
		handle_arp(ethernet_payload, ethernet_payload_len);
		break;

	default:
		break;
	}
}

void libip_init(uint32_t ip, const uint8_t mac[6])
{
	local_ip = ip;
	memcpy(local_mac, mac, 6);
}
